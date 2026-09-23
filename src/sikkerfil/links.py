"""
Reading and writing share links.

    https://sikkerfil.no/s/ABCD1234#k=<base64url key>
    https://sikkerfil.no/kvartalsrapport#k=<base64url key>   (a named link)

THE FRAGMENT IS THE PRODUCT. Everything after ``#`` — the key — is never sent to
a server by a browser, never appears in a Referer header and never lands in an
access log. That is the entire mechanism by which sikkerfil can hold a file it
cannot read. A library that parsed a link and then put the fragment into a
request path, a query string or a log line would quietly undo it.

So parsing happens HERE, once, and what comes out is a triple of origin, id and
key. Nothing downstream is handed the whole link, which is the cheapest way to
guarantee the key never reaches a request.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from .crypto import KEY_BYTES, b64url_decode, b64url_encode
from .errors import ConfigurationError

#: The service's own id alphabet — uppercase and digits, 4 to 32 characters.
#: Mirrors SHARE_PATH in the service's router; anything else cannot be a share,
#: so it is refused here rather than turned into a 404 round trip.
SHARE_ID = re.compile(r"^[0-9A-Z]{4,32}$")

#: A named link. Lowercase, digits and hyphens, 3 to 40 — mirrors NAME_PATH.
SHARE_NAME = re.compile(r"^[a-z0-9-]{3,40}$")

#: The three markets. One service, one distribution, three front doors; a share
#: created on any of them can be fetched from any other, so this is about which
#: domain your recipients see rather than where the bytes live. They live in
#: Stockholm either way.
MARKETS = {
    "no": "https://sikkerfil.no",
    "se": "https://sakerfil.se",
    "dk": "https://sikkerfil.dk",
}

DEFAULT_MARKET = "no"


@dataclass(frozen=True)
class ParsedLink:
    """A share link, taken apart. ``key`` is present only if the link carried one."""

    origin: str
    #: The share id, if the link addressed one directly.
    share_id: str | None
    #: The claimed name, if this was a named link. Needs one lookup to become an id.
    name: str | None
    #: The raw key text from ``#k=``, still base64url. ``None`` for a bare link.
    key: str | None

    @property
    def reference(self) -> str:
        """Whichever of id or name this link carried. Never empty."""
        return self.share_id or self.name or ""


def parse_link(link: str) -> ParsedLink:
    """Take apart a share link, a bare id, or a bare name.

    Accepts what a recipient will actually have: the whole URL pasted from an
    email, with or without the fragment, or just the id if they typed it out.
    """
    text = link.strip()
    if not text:
        raise ConfigurationError("empty share link")

    # A bare id or name, with an optional #k= glued on, and no scheme.
    if "://" not in text:
        head, _, fragment = text.partition("#")
        head = head.strip("/")
        key = _key_from_fragment(fragment)
        if SHARE_ID.match(head):
            return ParsedLink(origin="", share_id=head, name=None, key=key)
        if SHARE_NAME.match(head):
            return ParsedLink(origin="", share_id=None, name=head, key=key)
        raise ConfigurationError(
            f"{link!r} is not a share link, a share id ({SHARE_ID.pattern}) "
            f"or a named link ({SHARE_NAME.pattern})"
        )

    parts = urlsplit(text)
    if parts.scheme not in ("https", "http"):
        raise ConfigurationError(f"a share link must be https; got {parts.scheme!r}")
    origin = f"{parts.scheme}://{parts.netloc}"
    key = _key_from_fragment(parts.fragment)

    path = parts.path.strip("/")
    if path.startswith("s/"):
        candidate = path[2:]
        if not SHARE_ID.match(candidate):
            raise ConfigurationError(f"{candidate!r} is not a share id")
        return ParsedLink(origin=origin, share_id=candidate, name=None, key=key)

    if SHARE_ID.match(path):
        return ParsedLink(origin=origin, share_id=path, name=None, key=key)
    if SHARE_NAME.match(path):
        return ParsedLink(origin=origin, share_id=None, name=path, key=key)

    raise ConfigurationError(
        f"{link!r} does not look like a share link. Expected "
        "https://sikkerfil.no/s/<id>#k=<key> or https://sikkerfil.no/<name>#k=<key>"
    )


def build_link(origin: str, reference: str, key: str | bytes) -> str:
    """Assemble the link to hand to a recipient.

    The key goes after ``#k=`` and nowhere else. Built from the ORIGIN the sender
    used, so a Danish customer's recipients get a ``sikkerfil.dk`` link rather
    than being sent to a domain they have never heard of.

    ``key`` may be either spelling of the same key: the base64url text that
    :attr:`~sikkerfil.crypto.Sealed.key_text` gives you, or the raw 32 bytes from
    :attr:`~sikkerfil.crypto.Sealed.key` and :func:`~sikkerfil.crypto.new_key`.
    Both are accepted because a caller holding one and needing the other cannot
    tell from the failure: see :func:`_key_text`.
    """
    # An id lives under /s/; a claimed name lives at the root, which is why
    # names.ts keeps a reserved list — a name is in the same namespace as the
    # site's own routes.
    path = f"s/{reference}" if SHARE_ID.match(reference) else reference
    return f"{origin.rstrip('/')}/{path}#k={_key_text(key)}"


def base_url_for(market: str) -> str:
    """The front door for a market code (``no``, ``se``, ``dk``)."""
    try:
        return MARKETS[market.strip().lower()]
    except KeyError:
        raise ConfigurationError(
            f"unknown market {market!r}; expected one of {', '.join(sorted(MARKETS))}"
        ) from None


def _key_from_fragment(fragment: str) -> str | None:
    """Pull the key out of ``k=...``, tolerating a bare fragment.

    Some mail clients and chat apps mangle a link on the way through. Accepting
    a fragment that is only the key costs nothing and saves a recipient who has
    lost the ``k=`` from being told their perfectly good key is not a link.
    """
    if not fragment:
        return None
    for piece in fragment.split("&"):
        name, sep, value = piece.partition("=")
        if sep and name == "k":
            return unquote(value) or None
    return unquote(fragment) or None


def _key_text(key: str | bytes) -> str:
    """The key as it must appear after ``#k=``, from either spelling of it.

    THE FAILURE THIS EXISTS TO PREVENT IS SILENT. ``new_key()`` and ``Sealed.key``
    are bytes; the link wants base64url text. Interpolating the bytes you have
    yields ``#k=b'\\x9c\\x1f...'`` — a link of plausible length that no
    recipient can open, and nothing on the sending side ever finds out. So bytes
    are encoded rather than repr'd, and text is checked for being a key at all.

    Refusing here is cheap. The alternative is a recipient with an undecryptable
    file and a sender with no way to tell which of the two ends was wrong.
    """
    if isinstance(key, (bytes, bytearray, memoryview)):
        raw = bytes(key)
    else:
        try:
            raw = b64url_decode(key)
        # Both spellings of "not base64url" land here: binascii.Error for bad
        # characters and UnicodeEncodeError for non-ASCII are each a ValueError.
        except (TypeError, ValueError):
            raise ConfigurationError(
                f"the key in a link is base64url text; {key!r} is not. It is what "
                "Sealed.key_text gives you, or the part after #k= in another link."
            ) from None
    if len(raw) != KEY_BYTES:
        raise ConfigurationError(
            f"a sikkerfil key is {KEY_BYTES} bytes ({KEY_BYTES * 8}-bit AES); this "
            f"one is {len(raw)}. A link built from the wrong value looks right and "
            "cannot be opened by anyone, so it is refused here instead."
        )
    # Re-encoded rather than passed through, so a padded key from a config file
    # does not become a link with '=' in the fragment.
    return b64url_encode(raw)
