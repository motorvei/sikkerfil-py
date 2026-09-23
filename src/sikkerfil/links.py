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


@dataclass(frozen=True, repr=False)
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

    def __repr__(self) -> str:
        """Without the key.

        THE OBJECT PARSING PRODUCES, and the one I missed when I masked the other
        three. ``log.debug("parsed %s", parse_link(url))`` is at least as ordinary
        a line as logging a SentShare, and the generated repr printed the key
        field in full. Masking the results of parsing and not the result of THE
        parse function was an oversight, not a distinction.
        """
        return (
            f"ParsedLink(origin={self.origin!r}, share_id={self.share_id!r}, "
            f"name={self.name!r}, key={'<hidden>' if self.key else None})"
        )


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
            f"{describe(head)}. A share id is {SHARE_ID.pattern} and a named "
            f"link is {SHARE_NAME.pattern}"
        )

    # urlsplit RAISES on a malformed authority — "https://[oops/x" gives
    # ValueError("Invalid IPv6 URL"). Letting that out breaks this function's one
    # promise, which is that something it will not accept comes back as a
    # ConfigurationError; a caller catching SikkerfilError would miss it entirely.
    # The same two-step as crypto.key_text, for the same reason: urlsplit's
    # ValueError message contains the rejected authority, and `from None` would
    # leave it on __context__ with a clean message in front of it.
    parts = None
    try:
        parts = urlsplit(text)
    except ValueError:
        parts = None
    if parts is None:
        raise ConfigurationError(
            "that address could not be parsed as a URL. Expected "
            "https://sikkerfil.no/s/<id>#k=<key>. It is not repeated here, in "
            "case any part of it is a key."
        )

    if parts.scheme not in ("https", "http"):
        raise ConfigurationError(f"a share link must be https; got {quoted(parts.scheme)}")
    # FROM THE HOSTNAME, NOT netloc. netloc carries "user:password@", and this
    # origin is not just for display — _client_for installs it as base_url, so a
    # credential here would go into every request URL and come back out of any
    # transport failure. The redaction path stopped using netloc two commits ago;
    # the OPERATIONAL path was still building from it.
    origin = origin_of(text)
    key = _key_from_fragment(parts.fragment)

    path = parts.path.strip("/")
    if path.startswith("s/"):
        candidate = path[2:]
        if not SHARE_ID.match(candidate):
            # A KEY PASTED WHERE THE ID GOES, on the canonical share path. This
            # echoed the candidate, so the most ordinary link shape there is was
            # the one that reproduced a key in full.
            raise ConfigurationError(f"{describe(candidate)}. A share id is {SHARE_ID.pattern}")
        return ParsedLink(origin=origin, share_id=candidate, name=None, key=key)

    if SHARE_ID.match(path):
        return ParsedLink(origin=origin, share_id=path, name=None, key=key)
    if SHARE_NAME.match(path):
        return ParsedLink(origin=origin, share_id=None, name=path, key=key)

    raise ConfigurationError(
        f"{redacted(link)} does not look like a share link — {describe(path)}. "
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
    # THE REFERENCE IS A PATH SEGMENT, and a path is sent. A caller who transposed
    # the id and the key got a link with the key BEFORE the '#', which every
    # recipient's browser then hands to the server and its access logs — the one
    # thing this library exists to prevent.
    #
    # CHECKED AGAINST THE PATTERNS, not against a run of key characters. A run test
    # was the first thing I wrote here and it refused "kvartalsrapport-2026-q3",
    # which is a perfectly good named link. The service's own two patterns are
    # exact and already written down, and a key matches NEITHER — 43 characters
    # exceeds the 32 of an id and the 40 of a name, and an id has no lowercase.
    # Precision beats a heuristic when precision is available.
    if not SHARE_ID.match(reference) and not SHARE_NAME.match(reference):
        raise ConfigurationError(
            f"{describe(reference)}. A link's path is sent to the server, so a key "
            "belongs only after '#k='. A share id is "
            f"{SHARE_ID.pattern} and a named link is {SHARE_NAME.pattern}."
        )
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
            f"unknown market {quoted(market)}; expected one of {', '.join(sorted(MARKETS))}"
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
    of it. So a host carrying key material is not returned at all — CARRYING, not
    being, because "<key>.example" is a hostname and still hands over a key.
    """
    try:
        parts = urlsplit(link)
        host, port = parts.hostname, parts.port
    except ValueError:  # a malformed authority, e.g. a bad IPv6 literal or port
        return ""
    if not parts.scheme or not host or carries_key_material(host):
        return ""
    # BRACKETS BACK ON FOR IPv6. urlsplit's `hostname` strips them — "[::1]" comes
    # back as "::1" — so reassembling naively gives "http://::1:5000", which is not
    # a URL. This is not cosmetic: parse_link STORES this as ParsedLink.origin and
    # the module-level receive()/inspect() install it as the client's base_url, so a
    # self-hosted or stub service on IPv6 simply stopped working. A regression I
    # introduced by pointing the operational origin at this function.
    authority = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{authority}{f':{port}' if port else ''}"


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


def path_carries_key_material(path: str) -> bool:
    """Whether any COMPONENT of ``path`` could carry key material.

    Per component and at :data:`PATH_RUN`, for the reason spelled out on
    :func:`redacted_path`: real directories are full of long alphanumeric runs, and
    the value threshold refuses half of them. I had already learned that and then
    used the value threshold here anyway, which cost this suite's own tmp_path a
    second time.
    """
    return any(_run_in(part, _PATH_CHARACTERS) for part in path.split("/"))


def redacted_path(path: str) -> str:
    """A filesystem path, with any component that could carry key material removed.

    A PATH IS THE ONE VALUE THAT MUST USUALLY PRINT. "no such file" without the
    name is useless, and it is the most common error this library raises — so this
    works per COMPONENT rather than refusing the whole string. The directories a
    caller typed are shown, and only a component that could carry a key is not.

    THE THRESHOLD IS :data:`PATH_RUN`, NOT :data:`KEY_RUN`, and that is a correction
    rather than a design. I used KEY_RUN here first, on the principle that one number
    is better than two — and then this project's own test paths came out as
    "/tmp/<17 characters>/pytest-63/<31 characters>/…", because "pytest-of-user" is
    fourteen characters of base64url alphabet and so is half of everything anyone
    names a directory. The two numbers answer genuinely different questions: for a
    value, refusing costs nothing; for a path, refusing costs the name.
    """
    return "/".join(
        f"<{len(part)} characters, not repeated>" if _run_in(part, _PATH_CHARACTERS) else part
        for part in path.split("/")
    )


def describe(value: str) -> str:
    """Name a value we did not recognise, WITHOUT repeating it.

    We are here because it is not an id, a name or a link, so we do not know what
    it is. One of the things it can be is the decryption key: a sender who stored
    the id and the key separately and passed the key where the id belongs gets
    here, and their key works.

    So the message describes the value instead — and when it IS key-shaped, says
    so, which is the most useful thing it could say to the caller who got here
    that way.
    """
    if looks_like_a_key(value):
        return (
            "that value is a decryption key, not a share id or a name. The key "
            "goes in key= alongside the id — receive(id, key=…) — or after #k= "
            "in a link. It is not repeated here, because it is a secret"
        )
    return f"a {len(value)}-character value that is not repeated here, in case it is a key"


def quoted(value: str) -> str:
    """``repr(value)`` — unless it might CARRY key material, in which case it is not.

    THE RULE, APPLIED WITHOUT EXCEPTION rather than site by site. Five reviews in a
    row found a component of a link I had decided was safe to print: the fragment,
    then the path, then the id under ``/s/``, then the HOST. Each judgement was
    defensible on its own and each was wrong.

    AND "IS IT EXACTLY A KEY" WAS THE WRONG TEST, which was the next finding after
    that. ``base_url_for(key[:-1])`` decodes to 31 bytes, so an exact test says "not
    a key" and the message then printed 42 of the 43 characters. A key-shaped
    hostname label with ``.example`` glued on passed the same way. What matters is
    not whether the value IS a key but whether it CONTAINS enough of one, which is
    the standard the tests were already holding messages to — so it is the standard
    here, from one shared constant.

    What still prints: a mistyped market code, a wrong scheme, a duration, a short
    id — everything a person actually fat-fingers. What does not: any unbroken run
    of :data:`KEY_RUN` base64url characters. A path keeps printing because ``/`` is
    not in that alphabet and breaks every run.
    """
    return "<not repeated here: it may carry a key>" if carries_key_material(value) else repr(value)


#: How long a run of key characters has to be before a VALUE is not echoed. Twelve,
#: which is conservative — and conservative HERE IS FREE, which is the whole reason
#: for the number. Nothing anybody types into these slots (a market code, a scheme,
#: a duration, an id) has an unbroken run that long, so refusing them costs a reader
#: nothing. The tests import this rather than restating it, so what the library
#: refuses and what the tests call a leak cannot drift apart.
KEY_RUN = 12

#: The same question for a PATH COMPONENT, where the answer has to be different and
#: the reason is cost rather than danger. Refusing to print a filename is not free —
#: "no such file" without the name is the commonest error this library raises — and
#: real paths are full of long alphanumeric runs: "pytest-of-user" is fourteen
#: characters, "test_the_absolute_path_esc0" is thirty-one.
#:
#: I SHIPPED KEY_RUN HERE FIRST and wrote a comment claiming two thresholds would be
#: a mistake. Then the test suite's own tmp_path came back as
#: "/tmp/<17 characters>/pytest-63/<31 characters>/…" and settled it.
#:
#: So this one is anchored in arithmetic instead of caution: a key is 43 base64url
#: characters, so disclosing 32 leaves 11 — about 66 bits — which is where guessing
#: the rest stops being hopeless. Below that a fragment is not usable on its own.
PATH_RUN = 32

#: The base64url alphabet, which is what a key is spelled in. Anything outside it —
#: a dot, a slash, a colon, a space — breaks a run, which is why hostnames and most
#: filenames keep printing in full.
_KEY_CHARACTERS = re.compile(rf"[A-Za-z0-9_-]{{{KEY_RUN},}}")
_PATH_CHARACTERS = re.compile(rf"[A-Za-z0-9_-]{{{PATH_RUN},}}")


def _run_in(value: str, pattern: re.Pattern[str]) -> bool:
    """Whether ``pattern`` matches ``value``, or ``value`` with the whitespace out.

    BOTH SPELLINGS, ALWAYS, because the decoder accepts both. key_text takes a key
    spelled with spaces between every character or wrapped across two lines, so a
    run-based check that reads only the raw text sees no run and lets it through.
    That was one bypass in the value check and then, once that was fixed, exactly
    the same bypass again in the path check — a key across two lines splits into a
    twenty and a twenty-three, and neither reaches the path threshold on its own.
    One helper now, so there is one place to get it right.
    """
    return bool(pattern.search(value) or pattern.search("".join(value.split())))


def carries_key_material(value: str) -> bool:
    """Whether ``value`` contains an unbroken run long enough to be part of a key.

    Deliberately blunter than :func:`looks_like_a_key`. That one answers "is this a
    key", which is worth saying in a message; this one answers "could printing this
    hand over part of one", which is the only question that matters before echoing.

    CHECKED WITH THE WHITESPACE OUT AS WELL, because the decoder takes it out too.
    ``key_text`` accepts a key spelled with a space between every character — that
    was a deliberate kindness for keys wrapped by an email client — and a run-based
    check reading the raw spelling sees no run at all. So ``" ".join(key)`` was
    echoed in full, and deleting the spaces gave back a working key: my own
    permissiveness defeating my own chokepoint. Anything the decoder would accept
    has to be something this recognises.
    """
    return _run_in(value, _KEY_CHARACTERS)


def looks_like_a_key(value: str) -> bool:
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
