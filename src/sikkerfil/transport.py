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
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import certifi

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
        # Every credential this library sends is ASCII by construction — wt_…,
        # sikkerfil_sk_…, base64url — so a value that is not is a caller mistake,
        # and it is refused by NAME rather than by value.
        for name, value in headers.items():
            if not value.isascii():
                raise ConfigurationError(
                    f"the {name} header is not ASCII, so it cannot be sent. Its "
                    "value is not repeated here, because the headers this library "
                    "sets carry credentials. A smart quote from a copied document "
                    "is the usual cause."
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
