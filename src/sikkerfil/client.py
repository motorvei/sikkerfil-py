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
import re
from pathlib import Path
from typing import IO, Any, Union
from urllib.parse import urlsplit

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
from .transport import (
    API_PREFIX,
    CREDENTIAL_PREFIXES,
    DEFAULT_TIMEOUT,
    KEY_HEADER,
    TOKEN_HEADER,
    Transport,
)

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
        if not _usable_base_url(resolved):
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
        _nothing_here_is_a_key(name=name, content_type=content_type, password=password)

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
        # THE DOWNLOAD HAS A BODY TOO. The three send() parameters were guarded and
        # this one was not, though it is the more likely mix-up of the two: a
        # recipient holds a link and a password in the same hand, and
        # receive(link, password=<the link's own key>) posts the key that opens the
        # file to the service that stores it, in the same request that asks for it.
        _nothing_here_is_a_key(password=password)

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


def _usable_base_url(candidate: str) -> bool:
    """Whether every part of ``candidate`` is safe to put in front of a request.

    ORIGIN_OF ANSWERS FOR THE SCHEME AND HOST, and the first version of this stopped
    there — then kept the caller's whole string, so ``https://host.example/<a key>``
    was accepted and the key went into every request PATH. I had even written that the
    gap between "what was validated" and "what is used" was worth watching, and then
    shipped it anyway.

    So: the origin has to be usable, and a path, query, fragment or userinfo is
    refused — none of them belongs in a base URL, each is another place for a secret
    to ride along, and a path in particular produced links this library could not
    itself parse.
    """
    if not origin_of(candidate):
        return False
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return False
    # THE CHARACTERS, NOT THE PARSED VALUES. "https://host?" has an empty query, so a
    # truthiness test passed it — and the caller's own string is what gets kept, so
    # the next request asked for "https://host?/api/v1/health" and the API path
    # became a query string aimed at the host root.
    if "?" in candidate or "#" in candidate or "@" in parts.netloc:
        return False
    # AND NO PATH AT ALL. I accepted a path prefix last round for reverse-proxy
    # deployments, checked it for key material, and shipped a base URL that cannot
    # work: send() hands base_url to build_link, origin_of drops the path, and the
    # recipient gets https://host.example/s/<id> — the wrong route. parse_link cannot
    # read a prefixed link either, so receive() would refuse the library's own
    # output. A feature that produces broken links is worse than one that is absent,
    # and build_link and parse_link agreeing about what a link is has already been
    # the right answer twice on this branch. Supporting a prefix means teaching both
    # of them, which is a feature and not a fix.
    return not parts.path.strip("/")


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


#: A media type, by RFC 6838 and RFC 9110: a restricted name, a slash, a restricted
#: name, and then any number of ``; name=value`` parameters. Used instead of a run
#: threshold for content_type, whose contents are a registered token and not a
#: caller's invention.
#:
#: THE PARAMETERS ARE NOT DECORATION. "text/plain; charset=utf-8" is an ordinary
#: Content-Type and my first version of this refused it — a regression I introduced
#: while fixing a different over-refusal, in the same parameter, one round apart.
_MEDIA_TOKEN = r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}"
_PARAMETER_TOKEN = r"[A-Za-z0-9!#$%&'*+.^_`|~-]+"
_QUOTED_STRING = r'"(?:[^"\\]|\\.)*"'
_PARAMETER = rf";[ \t]*{_PARAMETER_TOKEN}=(?:{_PARAMETER_TOKEN}|{_QUOTED_STRING})"

#: ``\X`` inside a quoted string is ``X``, per RFC 9110. HTTP takes the backslash
#: out before anybody reads the value, so a check that leaves it in reads a string
#: the recipient never sees — the same mistake as reading a percent-encoded host.
_QUOTED_PAIR = re.compile(r"\\(.)")
_MEDIA_TYPE = re.compile(rf"{_MEDIA_TOKEN}/{_MEDIA_TOKEN}(?:[ \t]*{_PARAMETER})*[ \t]*")


def _is_a_content_type(value: str) -> bool:
    """Whether ``value`` is a media type AND not a key wearing one's shape.

    THREE QUESTIONS, because a media type has a slash in it and so does standard
    base64. The grammar alone accepts ``<20 characters of key>/<23 more>``; the
    rendering check alone does not see it either, because inserting a separator makes
    the value 44 characters and the anchor asks for 43. What reverses that value is
    deleting the slash, so the slash-joined form is asked about as well — the same
    reading the path predicate gives a chunked key.
    """
    if not _MEDIA_TYPE.fullmatch(value) or links.renders_key_bytes(value):
        return False
    # EVERY TOKEN, not the whole string and one join. "text/<a key>" and
    # "text/plain; <a key>=x" are both valid media types whose surrounding text makes
    # the WHOLE value too long to decode as anything — and my previous version looked
    # at the complete value, the slash-deleted value, and the text after each "=",
    # which is three places out of five. A key does not care which token it is in.
    return not any(links.renders_key_bytes(token) for token in _content_type_tokens(value))


def _content_type_tokens(value: str) -> list[str]:
    """Every part of a Content-Type a key could be hiding in, plus the joins.

    The type, the subtype, both of them with the slash deleted, and each parameter's
    NAME and VALUE — the value with its quoted-pairs undone, because HTTP takes those
    backslashes out and the grammar lets them in: ``k="<key with a backslash before
    every tenth character>"`` passed every check while unescaping to the key.
    """
    head, _, parameters = value.partition(";")
    kind, _, subtype = head.strip().partition("/")
    tokens = [head.strip(), head.replace("/", "").strip(), kind, subtype]
    for parameter in parameters.split(";"):
        name, _, given = parameter.partition("=")
        tokens.append(name.strip())
        given = given.strip()
        if given.startswith('"') and given.endswith('"') and len(given) >= 2:
            given = _QUOTED_PAIR.sub(r"\1", given[1:-1])
        tokens.append(given)
    return [token for token in tokens if token]


def _nothing_here_is_a_key(
    *,
    name: str | None = None,
    content_type: str | None = None,
    password: str | None = None,
) -> None:
    """The three send() parameters that reach the service AS THEY WERE GIVEN.

    A DISCLOSURE IN A BODY IS A DISCLOSURE. The credential headers were guarded and
    these were not, so ``send(data, name=<the key>)`` serialised the decryption key
    into the JSON that creates the share — beside the size and the expiry, on its way
    to the one party the design exists to keep it from. ``content_type`` and
    ``password`` do the same. Found by handing a key to every string parameter in the
    library and then looking at the request BODY, which the sweep had never read.

    ``filename`` is deliberately not in this list: it is sealed under the file's own
    key before it goes anywhere, so a key pasted there is encrypted, not sent.

    FOUR SLOTS NOW: receive()'s password is the fourth and the likelier mix-up of the
    lot, since a recipient holds a link and a password in the same hand.

    THE PATH PREDICATE WAS THE WRONG ONE, which is this round's correction. It splits
    on "/" — right for a path, wrong for a password, because standard base64 spells
    with "/" and ``("A" * 10 + "/") * 3 + "A" * 10`` is 43 characters that become a
    working key the moment somebody swaps slashes for underscores. Split on the
    slashes it reads as four short components and passes. These are opaque values,
    not paths, so they get opaque_carries_key_material, which folds that alias in.

    * ``name`` becomes a path component of a public link (``sikkerfil.no/<name>``), so
      it takes the PATH threshold — the one that leaves ``kvartalsrapport-2026-q3``
      alone.
    * ``content_type`` IS CHECKED AS A MEDIA TYPE, not with that threshold, and that
      is a correction. A run of 32 characters is not a key in a MIME type, it is a
      registered subtype: mimetypes.guess_type("x.cii") returns
      "application/vnd.anser-web-certificate-issue-initiation", which this refused
      while _guess_type generated and sent the identical value when the argument was
      left out. Refusing a value the library itself produces is not a security
      property. So the shape is checked against RFC 6838, and the rendering check is
      asked as well — because "A"*20 + "/" + "A"*22 is both a valid media type by
      that grammar and a key in standard base64.
    * ``password`` gets the same threshold, AFTER EXACTNESS WAS TRIED AND WAS WRONG.
      "Only a value that is a key to the character" reads as careful and let
      ``user:<key>`` and ``<key>-old`` through — each carrying all 256 bits to the
      service, which is the whole disclosure with a decoration on the front. The
      sweep found both within a minute of being pointed at request bodies. A run
      threshold costs a caller whose password is 32 unbroken base64url characters,
      and that is the right side to err on.
    """
    if name and links.opaque_carries_key_material(name):
        raise ConfigurationError(
            "the share name given carries what looks like a decryption key. A name "
            "goes to the service in the clear and becomes part of a public link, so "
            "a key in it is published as well as disclosed. The key belongs after "
            "'#k=' in the link the send returns. The value is not repeated here."
        )
    if content_type and not _is_a_content_type(content_type):
        raise ConfigurationError(
            "the content type given is not a media type, or it carries what looks "
            "like a decryption key. It is sent to the service as a hint for the "
            "recipient, which is the one place a key must never go. Expected "
            "type/subtype, as in application/pdf. The value is not repeated here."
        )
    if password and links.opaque_carries_key_material(password):
        raise ConfigurationError(
            "the password given carries what looks like a decryption key. A password "
            "is sent to the service, which hashes it — so a key used as one is handed "
            "to the service in the same breath as the file it opens. The key belongs "
            "after '#k=' in the link. A password of your own is fine; what is refused "
            "is 32 or more characters of base64url in a row, which no password anybody "
            "chose looks like. The value is not repeated here."
        )


def _guess_type(filename: str | None) -> str:
    if not filename:
        return "application/octet-stream"
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


def _identify(share: str | SentShare, write_token: str | None) -> tuple[str, str]:
    if isinstance(share, SentShare):
        # THE ONE PLACE A KEY PASSED AS A TOKEN CAN BE CAUGHT. Both values are 43
        # characters of base64url — the service mints a write token as 32 random
        # bytes in base64url, which is a decryption key's spelling exactly — so
        # transport's shape check cannot tell them apart, and says so. Here the
        # share's own key is in hand, so the column mix-up that motivated the check
        # (revoke(sent, write_token=sent.key)) is decidable rather than guessed at.
        if write_token and _same_key(write_token, share.key):
            raise ConfigurationError(
                "the write token given is this share's DECRYPTION KEY. The key opens "
                "the file and is never sent to the service — it belongs after '#k=' "
                "in the link. The write token is SentShare.write_token, which is a "
                "different 43 characters. Neither value is repeated here, and "
                "nothing was sent."
            )
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


def _same_key(candidate: str, key: str) -> bool:
    """Whether these two spellings are the same key.

    Through key_text so that padding, a newline or a line wrap do not make one key
    read as two — the comparison links.looks_like_a_key was written for.

    AND WITH THE CREDENTIAL PREFIX TAKEN OFF, which is what this missed: "wt_" in
    front of the share's own key decodes as nothing, so the comparison said "not the
    key" — and transport then saw wt_ and 43 characters of base64url, which is
    exactly what a real write token is, and sent the file's key to the service. The
    prefix that makes a credential recognisable also makes a key wearing it
    unrecognisable, so it comes off before the two are compared. An application that
    stores the secret and adds the documented prefix around it produces precisely
    this value.
    """
    spellings = [candidate]
    for prefix in CREDENTIAL_PREFIXES:
        if candidate.startswith(prefix):
            spellings.append(candidate[len(prefix) :])
    for spelling in spellings:
        try:
            if crypto.key_text(spelling) == crypto.key_text(key):
                return True
        except ConfigurationError:
            continue
    return False


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
