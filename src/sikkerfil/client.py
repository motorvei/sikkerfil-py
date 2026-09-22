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

    POST /api/shares          key, or a browser session      -> send
    GET  /api/account/shares  key, or a browser session      -> list your shares
    DELETE /api/shares/<id>   the WRITE TOKEN, or a session  -> revoke
    GET  /api/shares/<id>/audit   the WRITE TOKEN, or a session
    GET/POST/DELETE /api/keys     a session ONLY — a key is refused

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

from . import crypto
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
    parse_link,
)
from .models import AuditEvent, ReceivedFile, SentShare, Share
from .transport import DEFAULT_TIMEOUT, KEY_HEADER, TOKEN_HEADER, Transport

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

        created = self._http.post_json("/api/shares", body, headers=key_headers)

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
            f"/api/shares/{created['id']}/complete",
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

    def receive(self, link: str, *, password: str | None = None) -> ReceivedFile:
        """Download and decrypt.

        The key comes out of the link's ``#k=`` fragment and is used locally; it
        is never part of any request this makes.
        """
        parsed = parse_link(link)
        if not parsed.key:
            raise ConfigurationError(
                "this link has no key. The part after '#k=' is what decrypts the "
                "file, and without it the bytes cannot be opened by anyone — "
                "including us. Ask the sender for the complete link."
            )
        share, _ = self._resolve(parsed)
        return self._fetch(share, parsed.key, password)

    # --- Housekeeping --------------------------------------------------------

    def shares(self) -> list[Share]:
        """Every share this account has sent that has not expired."""
        data = self._http.get_json("/api/account/shares", headers=self._key_headers())
        return [Share.from_json(row) for row in data.get("shares", [])]

    def revoke(self, share: str | SentShare, *, write_token: str | None = None) -> None:
        """Delete a share now, before it expires.

        NEEDS THE WRITE TOKEN, not the API key. Pass the :class:`SentShare` and
        the token comes with it; pass an id and supply ``write_token`` yourself.
        """
        share_id, token = _identify(share, write_token)
        self._http.delete(f"/api/shares/{share_id}", headers={TOKEN_HEADER: token})

    def audit(self, share: str | SentShare, *, write_token: str | None = None) -> list[AuditEvent]:
        """The trail: created, uploaded, downloaded, revoked, denied.

        This is the artifact a data protection officer asks for — evidence that
        a transfer happened, when, and roughly from where. Also needs the write
        token.
        """
        share_id, token = _identify(share, write_token)
        data = self._http.get_json(
            f"/api/shares/{share_id}/audit", headers={TOKEN_HEADER: token}
        )
        return [AuditEvent.from_json(row) for row in data.get("events", [])]

    def audit_csv(self, share: str | SentShare, *, write_token: str | None = None) -> str:
        """The same trail as CSV, which is the form people actually file."""
        share_id, token = _identify(share, write_token)
        raw = self._http.get_bytes(
            f"{self.base_url}/api/shares/{share_id}/audit.csv",
            headers={TOKEN_HEADER: token, "accept": "text/csv"},
        )
        return raw.decode("utf-8")

    def health(self) -> bool:
        """Whether the service is answering. No credential, no side effects."""
        try:
            return bool(self._http.get_json("/api/health").get("ok"))
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
            data = self._http.get_json(f"/api/shares/{parsed.share_id}")
        elif parsed.name:
            data = self._http.get_json(f"/api/navn/{parsed.name}")
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
            granted = self._http.post_json(f"/api/shares/{share.id}/download", body)
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
    timeout: float = DEFAULT_TIMEOUT,
) -> ReceivedFile:
    """Download and decrypt a share, with no account and no configuration.

    ::

        import sikkerfil
        file = sikkerfil.receive("https://sikkerfil.no/s/ABCD1234#k=...")
        file.save("~/Downloads")
    """
    return _client_for(link, timeout).receive(link, password=password)


def inspect(link: str, *, timeout: float = DEFAULT_TIMEOUT) -> Share:
    """Metadata for a share, without downloading it. No account needed."""
    return _client_for(link, timeout).inspect(link)


def _client_for(link: str, timeout: float) -> Sikkerfil:
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
            raise ConfigurationError(f"no such file: {path}")
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
        raise ConfigurationError(f"{share!r} is not a share id")
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
