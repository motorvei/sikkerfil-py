"""
The client: send a file, receive a file, and the housekeeping around both.

WHAT THIS LIBRARY IS FOR. sikkerfil stores a file it cannot read. The encryption
happens in the caller's process, the key goes in a URL fragment the server never
receives, and the ciphertext sits in Stockholm. Everything here is arranged so
that using the library the obvious way preserves that, and so that the two ways
to break it — sending the key, or skipping the encryption — are not reachable
from the public surface.

THE ASYMMETRY IS DELIBERATE. Sending needs an account; receiving does not. A
recipient holds a link, not an account, and requiring them to sign up to receive
a file would break the thing the product is for. So :meth:`Sikkerfil.send` needs
an API key and :func:`receive` needs nothing at all.

WHAT AN API KEY CAN AND CANNOT DO, because it surprises people:

    POST /api/v1/shares          key, or a browser session      -> send
    GET  /api/v1/account/shares  key, or a browser session      -> list shares
    DELETE /api/v1/shares/<id>   the WRITE TOKEN, or a session  -> revoke
    GET  /api/v1/shares/<id>/audit   the WRITE TOKEN, or a session
    GET/POST/DELETE /api/v1/keys     a session ONLY — a key is refused

The last line is the security posture rather than an oversight: a leaked key can
do what the account can do with files, and cannot extend its own life, mint a
sibling, or hide itself from the list that would reveal it. Revoking it ends it.
That is also why this library has no key-management methods — they would be
methods that cannot work. Keys are minted at https://sikkerfil.no/konto.
"""

from __future__ import annotations

import mimetypes
import os
from pathlib import Path
from typing import IO, Any, Union

from . import crypto, links
from .errors import (
    ApiError,
    ConfigurationError,
    DownloadsExhaustedError,
    PasswordRequiredError,
    ShareGoneError,
)
from .links import (
    DEFAULT_MARKET,
    MARKETS,
    SHARE_ID,
    ParsedLink,
    base_url_for,
    build_link,
    describe,
    origin_of,
    parse_link,
    redacted,
)
from .models import AuditEvent, ReceivedFile, SentShare, Share
from .transport import API_PREFIX, DEFAULT_TIMEOUT, KEY_HEADER, TOKEN_HEADER, Transport

#: Accepted sources for a send: a path, raw bytes, or an open binary file.
Source = Union[str, "os.PathLike[str]", bytes, bytearray, IO[bytes]]

ENV_API_KEY = "SIKKERFIL_API_KEY"
ENV_BASE_URL = "SIKKERFIL_BASE_URL"
ENV_MARKET = "SIKKERFIL_MARKET"


class Sikkerfil:
    """A client for one market and one credential.

    ::

        from sikkerfil import Sikkerfil

        sf = Sikkerfil()                      # reads SIKKERFIL_API_KEY
        sent = sf.send("kvartalsrapport.pdf")
        print(sent.url)                       # give this to the recipient
        print(sent.write_token)               # keep this to revoke or audit
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        market: str | None = None,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = 2,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get(ENV_API_KEY)
        if self.api_key is not None:
            self.api_key = self.api_key.strip()
            if not self.api_key:
                raise ConfigurationError(f"{ENV_API_KEY} is set but empty")

        resolved = base_url or os.environ.get(ENV_BASE_URL)
        if resolved is None:
            resolved = base_url_for(market or os.environ.get(ENV_MARKET) or DEFAULT_MARKET)
        elif market is not None:
            raise ConfigurationError("give either market or base_url, not both")

        # CHECKED AS AN ORIGIN, because a base_url reaches urllib and urllib says what
        # it was given: Sikkerfil(base_url=<a key>).health() raised
        # ValueError("unknown url type: '<the whole key>/api/v1/health'"), with the key
        # in the message and in args, and not as one of our errors either. A
        # constructor parameter is as much a caller value as any other; it just took
        # longer to notice because the sweep only ever built one safe client.
        #
        # origin_of ANSWERS, but its answer is not kept: it drops a path, and somebody
        # behind a reverse proxy may legitimately pass https://host/sikkerfil. So it is
        # asked whether this is a usable http(s) origin carrying no key material, and
        # the caller's own string is what gets used.
        if not origin_of(resolved):
            raise ConfigurationError(
                "base_url must be an http(s) address — a market's front door, or your "
                "own host. It is not repeated here, in case it carries a key: a "
                "decryption key is not a base URL, and it is never sent to a server."
            )
        self.base_url = resolved.rstrip("/")

        self._http = Transport(self.base_url, timeout=timeout, retries=retries)

    # --- Sending -------------------------------------------------------------

    def send(
        self,
        source: Source,
        *,
        filename: str | None = None,
        content_type: str | None = None,
        expires_in: int | None = None,
        max_downloads: int | None = None,
        password: str | None = None,
        name: str | None = None,
    ) -> SentShare:
        """Encrypt, upload, and return the link plus the write token.

        THE ORDER IS LOAD-BEARING. The file is encrypted BEFORE a share exists,
        so a failure at any later point has still never put plaintext on a wire.
        The size the share is created with is the size of the CIPHERTEXT, because
        that is what S3 will receive and the presigned upload URL pins the
        content length into its signature — a share created for the plaintext
        size produces an upload S3 refuses.

        :param source: a path, raw ``bytes``, or an open binary file.
        :param filename: the name to seal alongside the file. Defaults to the
            source's own name; pass ``""`` to send no name at all.
        :param content_type: a hint for the recipient. Never inspected by the
            service, and never trusted by it.
        :param expires_in: seconds until the share expires. Clamped by the
            service to the plan's maximum lifetime.
        :param max_downloads: clamped by the service to the plan's cap. The cap
            is never absent — an uncapped share is unbounded egress from one
            upload.
        :param password: an extra secret the recipient must supply. Hashed with
            scrypt by the service, which never sees the plaintext twice.
        :param name: claim a named link (``sikkerfil.no/kvartalsrapport``).
            Refused with a 409 if somebody already holds it.
        """
        # THE CREDENTIAL IS CHECKED FIRST, before the file is read and before a
        # byte is encrypted. Checking it where it is used instead means a caller
        # who forgot their key encrypts four gigabytes and is then told the
        # request was never going to be made.
        key_headers = self._key_headers()

        plaintext, derived_name = _read_source(source)
        if filename is None:
            filename = derived_name

        sealed = crypto.seal(plaintext)
        # The filename is sealed under the SAME key as the file. It has to be:
        # the recipient has exactly one key, and a separately-keyed name would
        # be a second secret to carry in the link.
        encrypted_name = crypto.seal_name(filename, sealed.key) if filename else None

        body: dict[str, Any] = {"sizeBytes": len(sealed.blob)}
        body["contentType"] = content_type or _guess_type(filename)
        if encrypted_name is not None:
            body["encryptedName"] = encrypted_name
        if expires_in is not None:
            body["expiresInSeconds"] = int(expires_in)
        if max_downloads is not None:
            body["maxDownloads"] = int(max_downloads)
        if password:
            body["password"] = password
        if name:
            body["name"] = name
        # Only for a real market. The service checks this against an allowlist
        # and refuses an unknown one; it is what lets it send the sender an
        # expiry reminder linking back to the domain they actually use.
        if self.base_url in MARKETS.values():
            body["origin"] = self.base_url

        created = self._http.post_json(f"{API_PREFIX}/shares", body, headers=key_headers)

        self._http.put_bytes(
            created["uploadUrl"],
            sealed.blob,
            # Not the caller's content type. An object served back with a type
            # the uploader chose is how a file share becomes an HTML host — and
            # the bytes are ciphertext anyway, so this is also the truth.
            content_type="application/octet-stream",
        )

        write_token = created["writeToken"]
        self._http.post_json(
            f"{API_PREFIX}/shares/{created['id']}/complete",
            {},
            headers={TOKEN_HEADER: write_token},
        )

        reference = created.get("name") or created["id"]
        return SentShare(
            id=created["id"],
            url=build_link(self.base_url, reference, sealed.key_text),
            write_token=write_token,
            key=sealed.key_text,
            expires_at=int(created["expiresAt"]),
            size_bytes=len(sealed.blob),
            name=created.get("name"),
        )

    # --- Receiving -----------------------------------------------------------

    def inspect(self, link: str) -> Share:
        """What the service will say about a share, without downloading it.

        Needs no credential: the link is the credential. Use it to see the size
        before pulling 4 GB, or to check whether a password is required.
        """
        return self._resolve(parse_link(link))[0]

    def receive(
        self,
        link: str,
        *,
        password: str | None = None,
        key: str | bytes | None = None,
    ) -> ReceivedFile:
        """Download and decrypt.

        TWO WAYS IN, because there are two situations.

        A RECIPIENT holds a link and nothing else, so the whole link works::

            sf.receive("https://sikkerfil.no/s/ABCD1234#k=...")

        A SENDER who kept the share usually has the id and the key as separate
        columns — :class:`SentShare` hands them over separately, so storing them
        that way is the obvious thing to do. Pass them separately::

            sf.receive(sent.id, key=sent.key)

        THE DOMAIN IN A LINK IS NOT ROUTING. One distribution serves
        sikkerfil.no, sakerfil.se and sikkerfil.dk from one table, and Host is
        not in its cache key, so any market answers for any share. Which front
        door this client uses is set by ``market``/``base_url``; the link only
        ever has to supply the id (or name) and, if you have not kept it, the
        key. There is nothing in a full URL that this client does not already
        know.

        The key is used in this process and is never part of any request.
        """
        parsed = parse_link(link)

        # CANONICALISE BEFORE COMPARING. A key arrives as base64url text or as the
        # raw bytes crypto hands back, and a fragment may keep its padding or not.
        # Comparing the spellings instead of the keys reports one key as two.
        given = crypto.key_text(key) if key else None
        in_link = crypto.key_text(parsed.key) if parsed.key else None

        # BOTH, AND DISAGREEING, is not something to resolve by precedence. One
        # of them opens the file and the other does not, and picking silently
        # means the caller debugs a decryption failure rather than a typo.
        if given and in_link and given != in_link:
            raise ConfigurationError(
                "two different keys: one in the link's '#k=' fragment and one in "
                "key=. Pass the link on its own, or the id with key=, but not a "
                "link whose fragment contradicts the argument."
            )

        secret = given or in_link or ""
        if not secret:
            raise ConfigurationError(
                f"no decryption key for {parsed.reference or redacted(link)!r}. "
                "The key is "
                "the part after '#k=' in the share link, and without it the bytes "
                "cannot be opened by anyone — including us.\n"
                "  - Recipient: ask the sender for the whole link, fragment and "
                "all. Quote it in a shell, or the '#' starts a comment and the "
                "key is dropped before the program starts.\n"
                "  - Sender: if you kept the id and key separately, pass them "
                "that way — receive(share_id, key=...)."
            )

        share, _ = self._resolve(parsed)
        return self._fetch(share, secret, password)

    # --- Housekeeping --------------------------------------------------------

    def shares(self) -> list[Share]:
        """Every share this account has sent that has not expired."""
        data = self._http.get_json(f"{API_PREFIX}/account/shares", headers=self._key_headers())
        return [Share.from_json(row) for row in data.get("shares", [])]

    def revoke(self, share: str | SentShare, *, write_token: str | None = None) -> None:
        """Delete a share now, before it expires.

        NEEDS THE WRITE TOKEN, not the API key. Pass the :class:`SentShare` and
        the token comes with it; pass an id and supply ``write_token`` yourself.
        """
        share_id, token = _identify(share, write_token)
        self._http.delete(f"{API_PREFIX}/shares/{share_id}", headers={TOKEN_HEADER: token})

    def audit(self, share: str | SentShare, *, write_token: str | None = None) -> list[AuditEvent]:
        """The trail: created, uploaded, downloaded, revoked, denied.

        This is the artifact a data protection officer asks for — evidence that
        a transfer happened, when, and roughly from where. Also needs the write
        token.
        """
        share_id, token = _identify(share, write_token)
        data = self._http.get_json(
            f"{API_PREFIX}/shares/{share_id}/audit", headers={TOKEN_HEADER: token}
        )
        return [AuditEvent.from_json(row) for row in data.get("events", [])]

    def audit_csv(self, share: str | SentShare, *, write_token: str | None = None) -> str:
        """The same trail as CSV, which is the form people actually file."""
        share_id, token = _identify(share, write_token)
        raw = self._http.get_bytes(
            f"{self.base_url}{API_PREFIX}/shares/{share_id}/audit.csv",
            headers={TOKEN_HEADER: token, "accept": "text/csv"},
        )
        return raw.decode("utf-8")

    def health(self) -> bool:
        """Whether the service is answering. No credential, no side effects."""
        try:
            return bool(self._http.get_json(f"{API_PREFIX}/health").get("ok"))
        except ApiError:
            return False

    # --- Internals -----------------------------------------------------------

    def _key_headers(self) -> dict[str, str]:
        if not self.api_key:
            raise ConfigurationError(
                "sending needs an API key. Pass Sikkerfil(api_key=...) or set "
                f"{ENV_API_KEY}. Keys are minted at https://sikkerfil.no/konto "
                "and need a Business account. (Receiving a file needs nothing — "
                "use sikkerfil.receive(link).)"
            )
        # x-sikkerfil-key, NEVER Authorization: Bearer. CloudFront replaces the
        # Authorization header with its own signature, so a credential sent that
        # way is simply dropped. See transport.py.
        return {KEY_HEADER: self.api_key}

    def _resolve(self, parsed: ParsedLink) -> tuple[Share, str]:
        """Turn a parsed link into a share and the id to address it by."""
        if parsed.share_id:
            data = self._http.get_json(f"{API_PREFIX}/shares/{parsed.share_id}")
        elif parsed.name:
            data = self._http.get_json(f"{API_PREFIX}/navn/{parsed.name}")
        else:  # pragma: no cover - parse_link guarantees one of the two
            raise ConfigurationError("the link names neither a share nor a name")
        share = Share.from_json(data)
        if not share.is_ready:
            raise ShareGoneError(
                f"share {share.id} is {share.state}: the upload never finished, "
                "or it has been revoked",
                status=404,
                code="gone",
            )
        return share, share.id

    def _fetch(self, share: Share, key_text: str, password: str | None) -> ReceivedFile:
        key = crypto.b64url_decode(key_text)
        body: dict[str, Any] = {"password": password} if password is not None else {}
        try:
            granted = self._http.post_json(f"{API_PREFIX}/shares/{share.id}/download", body)
        except ApiError as exc:
            raise _download_refusal(exc, share, password is not None) from exc

        blob = self._http.get_bytes(granted["url"])
        plaintext = crypto.open_sealed(blob, key)
        filename = crypto.open_name(share.encrypted_name, key) if share.encrypted_name else None
        return ReceivedFile(
            data=plaintext,
            filename=filename,
            content_type=share.content_type,
            share=share,
        )


# --- Module-level conveniences for the side that has no account ---------------
#
# A recipient holds a link and nothing else. Making them build a client first —
# and choose a market they have no opinion about — would be ceremony for no
# reason, so the link itself says where to go.


def receive(
    link: str,
    *,
    password: str | None = None,
    key: str | bytes | None = None,
    market: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> ReceivedFile:
    """Download and decrypt a share, with no account and no configuration.

    ::

        import sikkerfil
        file = sikkerfil.receive("https://sikkerfil.no/s/ABCD1234#k=...")
        file.save("~/Downloads")

    Or from an id and a key kept separately, which is how a sender who stored
    the share will have them::

        sikkerfil.receive("ABCD1234", key="...")

    ``market`` picks the front door when the link does not name one ("no",
    "se", "dk"). It rarely matters: one distribution serves all three from one
    table, so any of them answers for any share.
    """
    return _client_for(link, timeout, market).receive(link, password=password, key=key)


def inspect(
    link: str,
    *,
    market: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Share:
    """Metadata for a share, without downloading it. No account, no key needed.

    Takes a link or a bare id — the metadata is public to anyone holding the id,
    which is why the key is not a parameter here at all.
    """
    return _client_for(link, timeout, market).inspect(link)


def _client_for(link: str, timeout: float, market: str | None = None) -> Sikkerfil:
    """Build a client for whichever market the link points at.

    AN EXPLICIT BASE URL STILL WINS. Following the link is the right default —
    a recipient's link says which front door to use and we should not send them
    somewhere else — but somebody who has deliberately set ``SIKKERFIL_BASE_URL``
    is pointing at a staging environment on purpose, and silently ignoring that
    because the link happens to name production is how a test, or a developer,
    ends up talking to the live service without meaning to.
    """
    if os.environ.get(ENV_BASE_URL):
        return Sikkerfil(timeout=timeout)
    if market:
        return Sikkerfil(market=market, timeout=timeout)
    origin = parse_link(link).origin
    if origin:
        return Sikkerfil(base_url=origin, timeout=timeout)
    return Sikkerfil(timeout=timeout)


# --- Helpers ------------------------------------------------------------------


def _read_source(source: Source) -> tuple[bytes, str | None]:
    """Get the bytes, and a filename if the source implies one."""
    if isinstance(source, (bytes, bytearray)):
        return bytes(source), None
    if isinstance(source, (str, os.PathLike)):
        path = Path(source).expanduser()
        if not path.is_file():
            # A KEY PASTED WHERE A FILENAME GOES is a sender-side mix-up like any
            # other. Unlike a link, a path MUST usually print — "no such file"
            # without the name is useless, and it is the commonest error here — so
            # redacted_path() works per component: the directories print, and only
            # a component that could carry a key does not.
            #
            # EXACTNESS WAS THE BUG HERE TOO. This used to ask "is it a key", so
            # send(<key minus one character>) printed 42 of the 43. It asks whether
            # the value CARRIES key material now, like every other slot.
            raise ConfigurationError(f"no such file: {links.redacted_path(str(path))}")
        return path.read_bytes(), path.name
    if hasattr(source, "read"):
        data = source.read()
        if not isinstance(data, (bytes, bytearray)):
            raise ConfigurationError(
                "open the file in binary mode ('rb'): text mode hands back str, "
                "and encrypting a decoded string loses the original bytes"
            )
        name = getattr(source, "name", None)
        return bytes(data), os.path.basename(name) if isinstance(name, str) else None
    raise ConfigurationError(f"cannot send a {type(source).__name__}; pass a path, bytes or a file")


def _guess_type(filename: str | None) -> str:
    if not filename:
        return "application/octet-stream"
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


def _identify(share: str | SentShare, write_token: str | None) -> tuple[str, str]:
    if isinstance(share, SentShare):
        return share.id, write_token or share.write_token
    if not write_token:
        raise ConfigurationError(
            "this needs the write token issued when the share was created. It is "
            "returned once, as SentShare.write_token, and cannot be recovered "
            "afterwards — an API key is not accepted here."
        )
    if not SHARE_ID.match(share):
        # THIS BYPASSED THE CHOKEPOINT. Every raise in links.py goes through
        # quoted() or _describe(); this one is in client.py and echoed the value
        # directly, so revoke(<key>, write_token=...) — the same id/key column
        # mix-up already handled for receive() — printed a working key. Being in a
        # different file was the whole reason it was missed.
        raise ConfigurationError(f"{describe(share)}. A share id is {SHARE_ID.pattern}")
    return share, write_token


def _download_refusal(exc: ApiError, share: Share, password_given: bool) -> ApiError:
    """Give the service's download refusals their specific meanings."""
    if exc.status == 403:
        return PasswordRequiredError(
            # A WRONG GUESS COSTS NOTHING. The service checks the password
            # before it claims a download, so retrying with the right one
            # works — otherwise anyone holding the link could exhaust a share
            # they cannot open. Worth saying, because the natural fear on a
            # limited share is that guessing burns it.
            f"the password for share {share.id} is wrong. Retrying costs nothing: "
            "a refused guess does not consume one of the allowed downloads"
            if password_given
            else f"share {share.id} is password-protected; pass password=...",
            status=exc.status,
            code=exc.code,
            request_id=exc.request_id,
        )
    if exc.status == 410:
        return DownloadsExhaustedError(
            f"share {share.id} has no downloads left; the sender set a limit and "
            "it has been spent",
            status=exc.status,
            code=exc.code,
            request_id=exc.request_id,
        )
    return exc
