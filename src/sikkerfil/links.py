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

from .crypto import key_text
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
            f"{_describe(head)}. A share id is {SHARE_ID.pattern} and a named "
            f"link is {SHARE_NAME.pattern}"
        )

    # urlsplit RAISES on a malformed authority — "https://[oops/x" gives
    # ValueError("Invalid IPv6 URL"). Letting that out breaks this function's one
    # promise, which is that something it will not accept comes back as a
    # ConfigurationError; a caller catching SikkerfilError would miss it entirely.
    try:
        parts = urlsplit(text)
    except ValueError:
        raise ConfigurationError(
            "that address could not be parsed as a URL. Expected "
            "https://sikkerfil.no/s/<id>#k=<key>. It is not repeated here, in "
            "case any part of it is a key."
        ) from None

    if parts.scheme not in ("https", "http"):
        raise ConfigurationError(f"a share link must be https; got {_quoted(parts.scheme)}")
    origin = f"{parts.scheme}://{parts.netloc}"
    key = _key_from_fragment(parts.fragment)

    path = parts.path.strip("/")
    if path.startswith("s/"):
        candidate = path[2:]
        if not SHARE_ID.match(candidate):
            # A KEY PASTED WHERE THE ID GOES, on the canonical share path. This
            # echoed the candidate, so the most ordinary link shape there is was
            # the one that reproduced a key in full.
            raise ConfigurationError(f"{_describe(candidate)}. A share id is {SHARE_ID.pattern}")
        return ParsedLink(origin=origin, share_id=candidate, name=None, key=key)

    if SHARE_ID.match(path):
        return ParsedLink(origin=origin, share_id=path, name=None, key=key)
    if SHARE_NAME.match(path):
        return ParsedLink(origin=origin, share_id=None, name=path, key=key)

    raise ConfigurationError(
        f"{redacted(link)} does not look like a share link — {_describe(path)}. "
        "Expected https://sikkerfil.no/s/<id>#k=<key> or "
        "https://sikkerfil.no/<name>#k=<key>"
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
    tell from the failure: see :func:`~sikkerfil.crypto.key_text`.
    """
    # An id lives under /s/; a claimed name lives at the root, which is why
    # names.ts keeps a reserved list — a name is in the same namespace as the
    # site's own routes.
    path = f"s/{reference}" if SHARE_ID.match(reference) else reference
    return f"{origin.rstrip('/')}/{path}#k={key_text(key)}"


def base_url_for(market: str) -> str:
    """The front door for a market code (``no``, ``se``, ``dk``).

    LOOKED UP WITH .get() RATHER THAN CAUGHT, because a KeyError carries the key it
    failed on. This raised ConfigurationError ``from None`` with the value not
    echoed, and the message was clean — but the KeyError stayed on
    ``__context__`` holding the market string, which is a decryption key if that
    is what the caller passed. __suppress_context__ keeps it out of a formatted
    traceback; it does not keep it off the object, and error trackers walk chains.

    Not caught at all means nothing to leak. Found by making the leak check
    case-insensitive: the lookup lowercases, so the KeyError held a lowercased key
    and an exact-match check could not see it.
    """
    origin = MARKETS.get(market.strip().lower())
    if origin is None:
        raise ConfigurationError(
            f"unknown market {_quoted(market)}; expected one of {', '.join(sorted(MARKETS))}"
        )
    return origin


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


def origin_of(link: str) -> str:
    """``scheme://host[:port]``, or ``""`` when the address will not parse.

    THE ONE PLACE THAT DECIDES WHERE A LINK'S ORIGIN ENDS. Everything that needs
    to name a link without its secrets needs this, and every hand-rolled version
    of it has been wrong: splitting on ``/`` took a whole key to be the host when
    a link used ``?`` instead of ``#``, and taking everything before ``/s/``
    returned the entire link for a NAMED share, fragment and all.

    urlsplit knows where an authority ends. ``hostname`` rather than ``netloc``,
    because netloc carries ``user:password@``. The port stays: a port is digits,
    and a stub or a self-hosted origin needs it to be recognisable.

    AND THE HOST ITSELF IS NOT TRUSTED, which is the part I had wrong. I wrote
    down that a hostname is never a secret. Then ``https://<key>/A/B`` — a key
    pasted where the whole address goes — puts the key in the authority, and
    ``hostname`` lowercasing it does not make it safe: a 32-byte key can be spelled
    entirely in lowercase base64url, and a mangled key still gives away nearly all
    of it. So a host that could be a key is not returned at all.
    """
    try:
        parts = urlsplit(link)
        host, port = parts.hostname, parts.port
    except ValueError:  # a malformed authority, e.g. a bad IPv6 literal or port
        return ""
    if not parts.scheme or not host or _looks_like_a_key(host):
        return ""
    return f"{parts.scheme}://{host}{f':{port}' if port else ''}"


def redacted(link: str) -> str:
    """``link`` with everything that might be a secret taken out.

    THE MODULE DOCSTRING ABOVE SAYS A LOG LINE CARRYING THE FRAGMENT UNDOES THE
    PRODUCT, and an exception message is a log line: applications log what they
    did not catch, and error trackers keep it for months.

    The origin is kept — it says which market the caller aimed at, and is never a
    secret. THE PATH GOES TOO, not just the fragment: every caller of this is
    about to say it did not recognise the link, so by definition we do not know
    what its parts are, and one thing a path can be is the key.
    """
    origin = origin_of(link)
    return f"{origin}/<unrecognised>" if origin else "<unrecognised>"


def _describe(value: str) -> str:
    """Name a value we did not recognise, WITHOUT repeating it.

    We are here because it is not an id, a name or a link, so we do not know what
    it is. One of the things it can be is the decryption key: a sender who stored
    the id and the key separately and passed the key where the id belongs gets
    here, and their key works.

    So the message describes the value instead — and when it IS key-shaped, says
    so, which is the most useful thing it could say to the caller who got here
    that way.
    """
    if _looks_like_a_key(value):
        return (
            "that value is a decryption key, not a share id or a name. The key "
            "goes in key= alongside the id — receive(id, key=…) — or after #k= "
            "in a link. It is not repeated here, because it is a secret"
        )
    return f"a {len(value)}-character value that is not repeated here, in case it is a key"


def _quoted(value: str) -> str:
    """``repr(value)`` — unless it might be a key, in which case it is not echoed.

    THE RULE, APPLIED WITHOUT EXCEPTION rather than site by site. Four reviews in
    a row found a component of a link I had decided was safe to print: the
    fragment, then the path, then the id under ``/s/``, then the HOST. Each
    judgement was defensible on its own and each was wrong, and the last one
    defeated an argument I had actually written down — that a hostname is never a
    secret.

    So there are no judgements left. Anything from the caller goes through here,
    and anything key-shaped does not come out. Guessing which slots a key can
    reach has now failed four times; refusing to echo one from any slot cannot.
    """
    return "<a key, not repeated here>" if _looks_like_a_key(value) else repr(value)


def _looks_like_a_key(value: str) -> bool:
    """Whether ``value`` is a key, BY THE LIBRARY'S ONE DEFINITION OF THAT.

    Asking key_text rather than re-deriving the test is the point. The first
    version of this did its own ``.strip()`` and length check, and promptly
    disagreed with key_text: a key wrapped across two lines was accepted there
    and not recognised as a key here, so the message told a caller their key was
    "a 44-character value". Two places deciding the same question is the bug;
    keeping them in step is not a fix.
    """
    try:
        key_text(value)
    except ConfigurationError:
        return False
    return True
