"""
The HTTP layer, and the one rule it exists to enforce.

EVERY POST MUST CARRY ``x-amz-content-sha256``.

CloudFront reaches the service's Function URL through an origin access control
with ``signing_behavior = "always"``. That means CloudFront signs each origin
request with SigV4 — and SigV4 covers the request BODY. The viewer has to supply
the body's SHA-256 in ``x-amz-content-sha256`` for that signature to be
computable. Without it the request is refused at the edge:

    403  x-amzn-errortype: InvalidSignatureException

and it NEVER REACHES THE SERVICE. No route runs. Nothing is logged. The caller
sees a 403 that says nothing about the cause. The web client shipped a form with
a bare ``fetch()`` once and this is exactly what it did.

So there is exactly one function in this library that builds a POST, it computes
the digest from the bytes it is about to send, and nothing else is allowed to
build one. ``tests/test_transport.py`` asserts that structurally, because no
functional test can catch it — the signing layer exists only in production, and
a stub server will happily accept a request that CloudFront would reject.

THE SECOND RULE: NEVER ``Authorization: Bearer``. The same origin access control
REPLACES the Authorization header with its own signature, so a credential sent
that way never arrives. Measured against production rather than assumed —
``GET /api/account/shares`` with a well-formed but unknown key:

    no credential                  -> 401 {"error":"signin_required"}
    x-sikkerfil-key: <key>         -> 401 {"error":"bad_key"}       <- it ARRIVED
    Authorization: Bearer <key>    -> 401 {"error":"signin_required"} <- STRIPPED

The middle line is the service reading the credential and rejecting its VALUE.
The last line is indistinguishable from sending nothing at all, because that is
what the origin received. Credentials therefore travel in ``x-sikkerfil-key``
and ``x-sikkerfil-token``, and the same run confirms the first rule:

    POST /api/shares, no digest header      -> 403 InvalidSignatureException
    POST /api/shares, wrong digest          -> 403 InvalidSignatureException
    POST /api/shares, digest from this file -> 401 {"error":"signin_required"}

— the last one being the request reaching the service and being refused for the
only thing actually missing, a credential.

Those runs predate the /api/v1 prefix and their addresses are left exactly as
requested, because a measurement rewritten to a path that was never tested is
not a measurement. The behaviour they establish is a property of the CDN in
front of the service, not of any one route, and the prefix does not change it:
this library sends /api/v1/... and still supplies the digest on every POST.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import certifi

from . import links
from .errors import (
    ApiError,
    AuthenticationError,
    BudgetError,
    ConfigurationError,
    NotFoundError,
    SignatureError,
    TransportError,
)

#: The credential headers. Named constants because they appear in the docs, the
#: web client and here, and a typo in one of three places is a silent 401.
KEY_HEADER = "x-sikkerfil-key"
TOKEN_HEADER = "x-sikkerfil-token"

#: The digest header the edge requires on every signed POST. See the module docstring.
DIGEST_HEADER = "x-amz-content-sha256"

#: WHAT THE SERVICE ACTUALLY MINTS, read out of its source and not assumed:
#: ``KEY_PATTERN`` in app/src/key-format.ts and ``WRITE_TOKEN_PATTERN`` in
#: app/src/ids.ts. Checked POSITIVELY, because the thing being kept off the wire is
#: a decryption key, and "not a key" is a far weaker statement than "is one of the
#: two shapes a credential comes in".
#:
#: THE ASSUMPTION IS WHY THIS IS WRITTEN OUT WITH ITS SOURCE. The first version of
#: this check simply required a credential to start with ``sikkerfil_sk_`` or
#: ``wt_`` — and the service had never minted a ``wt_`` anything. A write token was
#: ``randomBytes(32).toString("base64url")``, so the check refused EVERY GENUINE
#: TOKEN: revoke() and audit() would have raised for every real caller on their
#: first call. Nothing here caught it, because conftest minted ``wt-<id>`` and both
#: /utviklere and this library's README documented ``wt_…`` — a test double and two
#: documents agreeing with each other and not with the code that mints the value.
#:
#: The service now mints the prefix the documentation promised (sikkerfil#62), and
#: that is what makes the token shape worth checking: a write token and a
#: decryption key were previously the SAME SHAPE — 43 characters of base64url,
#: character for character — so no test of the value could tell them apart, and the
#: mix-up this guard exists for (revoke(id, write_token=<the key>)) was undecidable
#: here. With ``wt_`` in front of a real token, a key handed over whole is refused,
#: and so is every near miss: one character short, still carrying ``=`` padding,
#: wrapped across two lines, or spelled in standard base64 with ``+/``.
#:
#: A token issued before that deploy has no prefix and is refused by name. That is
#: deliberate rather than overlooked: this library is not published yet, so no
#: caller holds one, and accepting a bare 43-character value on this header would
#: mean accepting a decryption key on it — which is the disclosure the whole check
#: exists to prevent.
_API_KEY = re.compile(r"sikkerfil_sk_[A-Za-z0-9_-]{43}")
_WRITE_TOKEN = re.compile(r"wt_[A-Za-z0-9_-]{43}")

#: The prefixes those two shapes put in front of their 43 characters. Exported
#: because client._same_key has to take one off before it can compare a credential
#: with a key: "wt_" + the share's own key is a perfectly shaped write token, and
#: the thing behind the prefix is the file's key.
CREDENTIAL_PREFIXES = ("wt_", "sikkerfil_sk_")

#: Keyed on the header constants rather than repeating their spellings, so a third
#: credential header cannot quietly escape the check.
_CREDENTIAL_SHAPES = {KEY_HEADER: _API_KEY, TOKEN_HEADER: _WRITE_TOKEN}

#: The API version every address carries: /api/v1/...
#:
#: The service also still answers the unversioned form, as a legacy alias for
#: browser bundles cached before the prefix existed. This library does not use
#: it: an address without a version is outside the compatibility promise
#: published on /utviklere, and a client that quietly relies on an alias is a
#: client that breaks the day the alias goes.
API_VERSION = "v1"
API_PREFIX = f"/api/{API_VERSION}"

USER_AGENT = "sikkerfil-python"

#: Connect/read timeout. Generous enough for a slow mobile link, short enough
#: that a black-holed connection does not hang a caller's job forever.
DEFAULT_TIMEOUT = 60.0

#: Only these are retried, and only for idempotent work. A 500 from the service
#: is not on the list: the request may have had an effect we cannot see.
_RETRY_STATUSES = frozenset({502, 503, 504})


def sha256_hex(payload: bytes) -> str:
    """The digest the edge signs over. Hex, lowercase, of the exact bytes sent."""
    return hashlib.sha256(payload).hexdigest()


class Transport:
    """A thin HTTP client that cannot forget the digest header.

    Deliberately stdlib. The protocol is four JSON calls and two blob transfers;
    a security library that drags a transitive dependency tree into a customer's
    environment is asking them to audit our taste as well as our code.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = 2,
        user_agent: str = USER_AGENT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = max(0, retries)
        self.user_agent = user_agent
        # certifi rather than the system store, because a python.org install on
        # macOS has no system store and the first call dies with "certificate
        # verify failed" — which reads as "the service is broken".
        self._ssl = ssl.create_default_context(cafile=certifi.where())

    # --- The two verbs -------------------------------------------------------

    def get_json(self, path: str, *, headers: Mapping[str, str] | None = None) -> Any:
        body, _ = self._send("GET", self._url(path), None, dict(headers or {}))
        return _decode_json(body)

    def get_bytes(self, url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        """Fetch an absolute URL as raw bytes — a presigned S3 object.

        Takes a full URL rather than a path because that is what the service
        hands back, and rewriting it against our own base would break it.
        """
        body, _ = self._send("GET", url, None, dict(headers or {}))
        return body

    def post_json(
        self,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """THE ONLY PLACE A POST IS BUILT. See the module docstring.

        The digest is computed here, from ``body`` — the exact bytes about to go
        on the wire. Computing it anywhere else, or from anything else, is how
        the signature ends up covering a body that was never sent.
        """
        body = json.dumps(payload if payload is not None else {}, separators=(",", ":")).encode()
        sent = {
            "content-type": "application/json",
            DIGEST_HEADER: sha256_hex(body),
            **dict(headers or {}),
        }
        raw, _ = self._send("POST", self._url(path), body, sent)
        return _decode_json(raw) if raw else None

    def put_bytes(self, url: str, body: bytes, *, content_type: str) -> None:
        """Upload to a presigned URL.

        NOT through ``post_json``, and not signed by us: the URL already carries
        a signature S3 will check, and that signature PINS THE CONTENT LENGTH.
        Sending a different number of bytes than the share was created for is
        refused by S3 — which is the whole point, since an unpinned presigned PUT
        is an invitation to store a 5 TB object on somebody else's bill.
        """
        self._send(
            "PUT",
            url,
            body,
            {"content-type": content_type, "content-length": str(len(body))},
        )

    def delete(self, path: str, *, headers: Mapping[str, str] | None = None) -> None:
        self._send("DELETE", self._url(path), None, dict(headers or {}))

    # --- The wire ------------------------------------------------------------

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def _send(
        self,
        method: str,
        url: str,
        body: bytes | None,
        headers: dict[str, str],
    ) -> tuple[bytes, dict[str, str]]:
        headers.setdefault("user-agent", self.user_agent)
        headers.setdefault("accept", "application/json")

        # CHECKED HERE, BEFORE http.client ENCODES THEM. A header value that is not
        # latin-1 raises UnicodeEncodeError from inside the standard library, and
        # that exception carries the WHOLE VALUE on `.object` — so a credential with
        # one smart quote in it, which is what a paste out of a document or a chat
        # window produces, came back out inside a stdlib error. It was not even a
        # SikkerfilError, so a caller catching ours never saw it coming.
        #
        # Every credential this library sends is ASCII by construction —
        # sikkerfil_sk_… or base64url — so a value that is not is a caller mistake,
        # and it is refused by NAME rather than by value.
        for name, value in headers.items():
            # THE NAME IS SENT TOO, and every safeguard below was applied only to the
            # value. A key is a valid HTTP field name — get_json(path, headers={key:
            # "x"}) put all forty-three characters on the wire as a header NAME, and
            # the refusals further down interpolate the name into their message, so a
            # bad value echoed the key locally as well. Transport is public; a caller
            # building headers from a dict they assembled can invert a pair.
            #
            # THE MEDIA-TYPE PREDICATE, NOT THE DEGENERATE ONE, and the numbers chose
            # it. A header name is a registered token whose length nobody picked, so a
            # length test has nothing to say about it: holds_a_key refuses
            # x-amz-server-side-encryption-customer-key-md5, and renders_key_bytes
            # refuses x-amz-server-side-encryption-customer-key — the second on 3.13
            # only, which is the interpreter-dependence fixed in the same round. What
            # is asked is what a media type is asked: is this EXACTLY a key, or does
            # it hold a rendering whose alphabet means something.
            #
            # The gap, named rather than found later: a key with DECORATION on it as a
            # header name — "x-key-<a key>" — is not caught, because catching it means
            # refusing the AWS names above. A bare key is the mistake that happens.
            if _a_key_is_the_header_name(name):
                raise ConfigurationError(
                    "a header name given carries what looks like a decryption key. A "
                    "header name is sent to the service exactly as a value is, so a "
                    "key used as one is handed to the party that must never hold it. "
                    "The key belongs after '#k=' in a link. The name is not repeated "
                    "here, and nothing was sent."
                )
            # ASCII IS NOT ENOUGH, which is where the first version of this stopped.
            # CR and LF are ASCII, so a credential wrapped across two lines in a
            # config file sailed through — and then http.client's own validation
            # raised ValueError("Invalid header value b'<the whole credential>'"),
            # which is neither one of our errors nor redacted. A control character
            # in a header is also how header injection is spelled, so there are two
            # reasons to refuse it and no reason to allow it.
            # A DECRYPTION KEY IS NEVER A CREDENTIAL. This is the worst mix-up the
            # library can be handed: revoke(id, write_token=<the key>) put the key in
            # x-sikkerfil-token and SENT IT TO THE SERVICE, next to the share id it
            # opens. Every other leak on this branch was into a log the operator
            # already had; this one hands the one secret the service is designed
            # never to hold straight to it, and no amount of redaction downstream
            # helps because the disclosure is the request itself.
            # LOWERCASED, BECAUSE HTTP HEADER NAMES ARE CASE-INSENSITIVE. This
            # library spells them through the constants, so nothing here missed the
            # check — but a caller using Transport directly with the conventional
            # "X-Sikkerfil-Token" got a dict miss and an unchecked credential, and
            # the service reads that header just the same. A guard keyed on one
            # spelling of a case-insensitive name is a guard with a spelling bypass.
            shape = _CREDENTIAL_SHAPES.get(name.lower())
            if shape is not None and not shape.fullmatch(value):
                expected = (
                    "an API key is sikkerfil_sk_ and then 43 characters of base64url"
                    if name.lower() == KEY_HEADER
                    else "a write token is wt_ and then 43 characters, exactly as "
                    "the service returned it as writeToken when the share was created"
                )
                raise ConfigurationError(
                    f"the value given for {name} is not shaped like a credential: "
                    f"{expected}. A DECRYPTION KEY is what this most often is by "
                    "mistake, and it must never be sent to the service — it opens "
                    "the file, and belongs only after '#k=' in a link. A write token "
                    "is what revoking and auditing need; an API key is what sending "
                    "needs. The value is not repeated here, and nothing was sent."
                )
            if not value.isascii() or any(c < " " or c == "\x7f" for c in value):
                raise ConfigurationError(
                    f"the {name} header contains a character that cannot be sent: "
                    "it must be printable ASCII. The value is not repeated here, "
                    "because the headers this library sets carry credentials. A "
                    "smart quote from a copied document, or a credential wrapped "
                    "across two lines, is the usual cause."
                )

        attempt = 0
        while True:
            request = urllib.request.Request(url, data=body, method=method)
            for name, value in headers.items():
                request.add_header(name, value)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout, context=self._ssl) as r:
                    return r.read(), {k.lower(): v for k, v in r.headers.items()}
            except urllib.error.HTTPError as exc:
                received = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
                detail = exc.read() if hasattr(exc, "read") else b""
                if exc.code in _RETRY_STATUSES and attempt < self.retries and _idempotent(method):
                    attempt += 1
                    time.sleep(_backoff(attempt))
                    continue
                raise _refusal(exc.code, detail, received, url) from exc
            except urllib.error.URLError as exc:
                if attempt < self.retries:
                    attempt += 1
                    time.sleep(_backoff(attempt))
                    continue
                raise TransportError(
                    f"could not reach {urlsplit(url).netloc}: {exc.reason}"
                ) from exc
            except TimeoutError as exc:
                if attempt < self.retries:
                    attempt += 1
                    time.sleep(_backoff(attempt))
                    continue
                raise TransportError(
                    f"{method} {urlsplit(url).netloc} timed out after {self.timeout:g}s"
                ) from exc


def _idempotent(method: str) -> bool:
    # A POST is never retried automatically. Creating a share twice costs the
    # caller a second share and a second upload URL; deciding to accept that is
    # the caller's call, not ours.
    return method in {"GET", "PUT", "DELETE"}


def _backoff(attempt: int) -> float:
    return min(8.0, 0.5 * float(2 ** (attempt - 1)))


def _decode_json(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(body)
    except ValueError as exc:
        raise TransportError(
            "the service returned a body that is not JSON. This usually means a "
            "proxy or captive portal answered instead of sikkerfil."
        ) from exc


def _refusal(
    status: int,
    body: bytes,
    headers: Mapping[str, str],
    url: str,
) -> ApiError:
    """Turn a refusal into the most specific exception the evidence supports."""
    code: str | None = None
    message: str | None = None
    try:
        parsed = json.loads(body) if body else None
        if isinstance(parsed, dict):
            code = parsed.get("error")
            message = parsed.get("message")
    except ValueError:
        pass

    request_id = headers.get("x-amz-cf-id")

    # THE EDGE REFUSED IT, so no route ran and the body is CloudFront's, not
    # ours. Worth its own exception and its own sentence: every other 403 is
    # about the caller's credential, and this one is about our own signing.
    if headers.get("x-amzn-errortype", "").startswith("InvalidSignature"):
        return SignatureError(
            "CloudFront refused this request before it reached sikkerfil: the body "
            f"digest ({DIGEST_HEADER}) was missing or did not match the bytes sent. "
            "This is a bug in sikkerfil-python, not in your code — please report it "
            "at https://github.com/motorvei/sikkerfil-py/issues"
            + (f" (request {request_id})" if request_id else ""),
            status=status,
            code=code,
            request_id=request_id,
        )

    if status in (401, 403):
        return AuthenticationError(
            message or _auth_hint(code, url),
            status=status,
            code=code,
            request_id=request_id,
        )
    if status == 404:
        return NotFoundError(
            message
            or "no such share — it may have expired, been revoked, or the "
            "credential you sent does not authorise this one (the service answers "
            "404 rather than 403 so it cannot be used to confirm a share exists)",
            status=status,
            code=code,
            request_id=request_id,
        )
    if status == 503 and code == "daily_budget_spent":
        return BudgetError(
            "sikkerfil's daily egress budget is spent; this clears on its own",
            status=status,
            code=code,
            request_id=request_id,
            retry_after=_retry_after(headers),
        )
    return ApiError(
        message or f"sikkerfil refused the request ({status})",
        status=status,
        code=code,
        request_id=request_id,
    )


def _auth_hint(code: str | None, url: str) -> str:
    if code == "session_required":
        return (
            "this endpoint needs a signed-in browser session, not an API key. "
            "Minting, listing and revoking API keys is deliberately session-only: "
            "a leaked key must not be able to issue itself a sibling. Manage keys "
            "at https://sikkerfil.no/konto"
        )
    if "/audit" in url or url.rstrip("/").count(f"{API_PREFIX}/shares/") == 1:
        return (
            "not authorised. Revoking a share and reading its audit trail take the "
            "WRITE TOKEN issued when the share was created (or a browser session) — "
            "an API key is not accepted for these"
        )
    return (
        "not authorised — check the API key. Keys are minted at "
        "https://sikkerfil.no/konto and require a Business account"
    )


def _retry_after(headers: Mapping[str, str]) -> int:
    try:
        return int(headers.get("retry-after", "3600"))
    except ValueError:
        return 3600


def _a_key_is_the_header_name(name: str) -> bool:
    """Whether an HTTP field name is a key, or holds a rendering with an alphabet.

    Deliberately the same question ``_a_key_hides_in`` asks of a media type's tokens,
    for the same reason: both are names whose length somebody else chose, so "forty
    characters" and "forty-three characters" say nothing about them. See the comment
    at the call site for the two real header names that proved it.
    """
    return (
        links.spells_a_key_exactly(name)
        or links.renders_key_bytes_strictly(name)
        or links.renders_key_bytes_strictly_inside(name)
    )
