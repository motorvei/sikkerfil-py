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

import ast
import base64
import binascii
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from .crypto import KEY_BYTES, key_text
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

    # AN ABSOLUTE LINK WHOSE ORIGIN WE CANNOT REBUILD IS REFUSED, not quietly turned
    # into a bare reference. "https:///s/ABCD1234" and "http://localhost:bad/..." both
    # gave origin="" while the share path still parsed — and an empty origin is
    # indistinguishable from "they typed just the id", so _client_for fell back to the
    # DEFAULT MARKET. A typo in a self-hosted link sent the lookup to production.
    if not origin:
        raise ConfigurationError(
            "that link has a scheme but no address we can use — check the host and "
            "port. It is not repeated here, in case any part of it is a key. A bare "
            "share id is accepted on its own if that is what you meant."
        )

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
    # AND THE PATTERNS ARE NOT SUFFICIENT, which is the correction to the paragraph
    # above. "a" * 40 is a valid named link by the service's own regex AND the first
    # 40 characters of a real key — 240 of its 256 bits, before the '#', with about
    # 65,536 completions left to try offline. Precision beats a heuristic at saying
    # what a value IS; it says nothing about what a value CARRIES, and both questions
    # have to be asked here.
    recognised = SHARE_ID.match(reference) or SHARE_NAME.match(reference)
    if not recognised or path_carries_key_material(reference):
        raise ConfigurationError(
            f"{describe(reference)}. A link's path is sent to the server, so a key "
            "belongs only after '#k='. A share id is "
            f"{SHARE_ID.pattern} and a named link is {SHARE_NAME.pattern}."
        )
    # AND THE ORIGIN, for the same reason and by the same rule. I fixed `reference`
    # last round and left this — the other half of everything before the '#'. A key
    # as the origin puts it in the link; "https://<key>.example" is worse, because it
    # looks valid and sends the key through DNS and the request authority on the first
    # click. Rebuilt through origin_of, which refuses a host carrying key material and
    # is the one place that knows where an origin ends.
    canonical = origin_of(origin)
    if not canonical:
        raise ConfigurationError(
            "that origin is not one we can build a link from. Give a market's front "
            "door — https://sikkerfil.no, sakerfil.se, sikkerfil.dk — or your own "
            "host. It is not repeated here, in case it carries a key."
        )
    path = f"s/{reference}" if SHARE_ID.match(reference) else reference
    return f"{canonical}/{path}#k={key_text(key)}"


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
    """``scheme://host[:port]`` for an http(s) link, or ``""`` when there is none to use.

    THE ONE PLACE THAT DECIDES WHERE A LINK'S ORIGIN ENDS. Everything that needs to
    name a link without its secrets needs this, and every hand-rolled version has
    been wrong: splitting on ``/`` took a whole key for the host when a link used
    ``?`` instead of ``#``, and taking everything before ``/s/`` returned the entire
    link for a NAMED share.

    ``hostname`` rather than ``netloc``, because netloc carries ``user:password@``.
    Brackets go back on an IPv6 literal, which ``hostname`` strips — leaving
    ``http://::1:5000``, which is not an address, and which broke every IPv6
    deployment until a review caught it.

    SCHEME RESTRICTED TO http(s), because a 43-character key is also a syntactically
    valid URI scheme: ``build_link(f"{key}://example.com", …)`` returned the key ahead
    of the fragment. Nothing this library builds is anything but http or https, so
    there is no cost to saying so.

    PERCENT-DECODED BEFORE THE KEY CHECK, since urllib decodes a host before it
    resolves it — so encoding every eleventh character of a key hid it from a check
    reading the raw text while DNS still saw the whole thing.

    AND THE KEY CHECK IS PER LABEL, at the path threshold, which is a CORRECTION.
    Running the 12-character value heuristic over a whole hostname rejected
    ``abcdefghijkl.example`` and ``my-company-files.example.com`` — ordinary names,
    and self-hosted origins are supported, so that broke real deployments outright
    while looking like a security improvement. A label is not a value: it is a path
    component in all but name, and gets the same threshold.
    """
    try:
        parts = urlsplit(link)
        host, port = parts.hostname, parts.port
    except ValueError:  # a malformed authority, e.g. a bad IPv6 literal or port
        return ""
    if parts.scheme not in ("http", "https") or not host:
        return ""

    decoded = unquote(host)
    # THE HOSTNAME FLOOR, for the reason written on _uniform_run_carrying_key.
    if structured_carries_key(decoded.replace(":", ".").split("."), chunk_floor=KEY_RUN):
        return ""

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


def structured_carries_key(parts: Sequence[str], *, chunk_floor: int = 4) -> bool:
    """Whether a value split into ``parts`` carries a key — as a part, or across them.

    THE SEPARATOR WAS THE BYPASS, three times in one review. Checking components
    independently is what lets ordinary hostnames and paths print, and it is also
    what let a key be smuggled through in pieces:

        "a"*21 + "." + "a"*21 + "g"      a host whose labels are both under the bar
        key[:21] + "/" + key[21:]        a path whose components are both under it

    Each piece is short enough to look innocent; the browser or the resolver puts
    them back together. So the per-part threshold stays, for the ordinary case, and
    every CONTIGUOUS RUN of parts is also joined and tested for being exactly a key.

    Exactly a key was not enough, though — see _parts_carrying_key, which does the
    work for both this and the redaction, so the two cannot answer differently.
    """
    return bool(_parts_carrying_key(parts, chunk_floor=chunk_floor))


def path_carries_key_material(path: str) -> bool:
    """Whether any COMPONENT of ``path`` could carry key material.

    Per component and at :data:`PATH_RUN`, for the reason spelled out on
    :func:`redacted_path`: real directories are full of long alphanumeric runs, and
    the value threshold refuses half of them. I had already learned that and then
    used the value threshold here anyway, which cost this suite's own tmp_path a
    second time.
    """
    return _is_a_key_spelled_with_slashes(path) or structured_carries_key(_components(path))


def renders_key_bytes(value: str) -> bool:
    """Whether ``value`` is a rendering of 32 raw bytes that anybody could reverse.

    THE PREVIOUS VERSION OF THIS ASKED ONLY ABOUT BASE64, and the review that
    followed handed me three spellings it could not see: MIME base64, which
    ``encodebytes`` wraps with a newline AFTER the padding; ``repr(raw_key)``; and
    ``raw_key.hex(":")``. Every one of them is produced by the standard library from
    the raw bytes this library itself hands callers as ``Sealed.key`` — so "a key in
    text" was never only base64, and each round of chasing another alphabet was
    treating a symptom.

    So the question is asked the other way round: not "is this spelled like a key"
    but "does this DECODE to 32 bytes under a rendering somebody could undo". That
    set is enumerable, because it is the set the standard library produces:

    * base64, either alphabet, padded or not, with any whitespace in it;
    * hex, with or without the ``:`` and ``-`` people put between the pairs;
    * a bytes literal, as ``repr()`` writes one.

    It is still a closed set and it can still be wrong, but it is closed around
    something real — what a 32-byte key looks like when it is written down — rather
    than around the spellings I happened to think of.
    """
    compact = "".join(value.split())
    if not compact:
        return False

    spelled = _aliased(compact).rstrip("=")
    if len(spelled) == KEY_TEXT_LENGTH and looks_like_a_key(spelled):
        return True

    if _is_hex_of_a_key(compact):
        return True

    # Base32, both alphabets. b32encode gives 56 characters and b32hexencode 64, and
    # neither is reachable by any of the tests above.
    if _is_base32_of_a_key(compact):
        return True

    if _is_a_bytes_literal_of_a_key(value):
        return True

    # BASE85, BOTH OF THE STANDARD LIBRARY'S. a85encode and b85encode turn 32 bytes
    # into 40 characters, and I claimed last round that the set was "the set the
    # standard library produces" while leaving two of its encoders out — the claim was
    # the part that was wrong, not the list.
    #
    # WHAT THIS TEST ACTUALLY IS, said plainly: b85's alphabet covers every letter and
    # digit, so ANY forty alphanumeric characters decode to 32 bytes — a sha1 digest
    # does. This is a length test, exactly as the base64 one is, and it is worth it
    # here because it is anchored on a whole value: 85 of 99,608 real paths on this
    # machine are 40 characters end to end (0.085%). The cost that is not measurable
    # is a caller whose PASSWORD is forty characters of that alphabet; they are
    # refused, by name, with a message that says what to change.
    # a85encode(adobe=True) wraps its output in <~ ~> and needs the same flag back;
    # the plain decoder refuses it, and the punctuation keeps the run fallback from
    # seeing anything either. Another member of "the set the standard library
    # produces" that I enumerated without consulting the library.
    #
    # INLINE, NOT A NAMED HELPER, and the sweep is why. My first version put the
    # adobe attempt behind a module-level function, which the exhaustive sweep then
    # called with a fullwidth key and caught red-handed: a85decode raises
    # ValueError("Ascii85 encoded byte sequences must end with b'~>'") for some
    # inputs and echoes the value for others, and a public-shaped function that
    # forwards a caller's value to a raising stdlib call is exactly what this branch
    # is about. Nothing here is reachable by name any more.
    for decode in (base64.a85decode, base64.b85decode):
        try:
            if len(decode(compact)) == KEY_BYTES:
                return True
        except (ValueError, TypeError):
            continue
    # a85 has TWO flags, not one: foldspaces spells four spaces as "y", so 32 spaces
    # are eight characters and no run test will ever see them. And z85 arrived in
    # 3.13, which this package supports — a decoder that exists on the interpreter
    # the caller is running is part of "what the standard library produces", whatever
    # the interpreter I happen to be testing on has.
    for attempt in (
        lambda text: base64.a85decode(text, adobe=True),
        lambda text: base64.a85decode(text, foldspaces=True),
        lambda text: base64.a85decode(text, adobe=True, foldspaces=True),
        getattr(base64, "z85decode", None),
    ):
        if attempt is None:
            continue
        try:
            if len(attempt(compact)) == KEY_BYTES:
                return True
        except (ValueError, TypeError):
            continue

    return False


def _is_hex_of_a_key(compact: str) -> bool:
    """Whether ``compact`` is 32 bytes in hex, with or without a separator.

    THE SEPARATOR IS A POSITION, NOT A CHARACTER, and that took three goes to see. I
    named ":" and "-"; then I took "whatever character is not a hex digit", which
    hex("a") walks past because its separator is inside the alphabet; and then
    deleting every "a" from hex("a") ALSO deletes the "a" inside "0a", so the digits
    come out wrong. What bytes.hex(sep, bytes_per_sep) actually produces is fixed-size
    groups of hex digits with one character between them, so that is what is checked:
    the shape, at every group size, with the separators required to agree.
    """
    candidate = compact.removeprefix("0x")
    if len(candidate) == KEY_BYTES * 2 and _is_hex(candidate):
        return True
    for per_group in range(1, KEY_BYTES):
        groups = -(-KEY_BYTES // per_group)
        if groups < 2:
            break
        if len(candidate) != KEY_BYTES * 2 + groups - 1:
            continue
        separators: set[str] = set()
        digits: list[str] = []
        at = 0
        for group in range(groups):
            size = 2 * min(per_group, KEY_BYTES - group * per_group)
            digits.append(candidate[at : at + size])
            at += size
            if group < groups - 1:
                separators.add(candidate[at])
                at += 1
        if len(separators) == 1 and all(_is_hex(piece) for piece in digits):
            return True
    return False


def _is_base32_of_a_key(compact: str) -> bool:
    """32 bytes in either base32 alphabet — 56 characters, or 64 in base32hex."""
    for decode in (base64.b32decode, base64.b32hexdecode):
        try:
            if len(decode(compact.upper())) == KEY_BYTES:
                return True
        except (ValueError, TypeError, binascii.Error):
            continue
    return False


def _is_hex(text: str) -> bool:
    """Whether every character is a hex digit, and there is an even number of them."""
    if not text or len(text) % 2:
        return False
    try:
        bytes.fromhex(text)
    except ValueError:
        return False
    return True


def renders_key_bytes_strictly(value: str) -> bool:
    """The renderings whose ALPHABET says something, not just their length.

    THE DIVISION THIS DRAWS IS THE POINT OF THIS ROUND. Some renderings of 32 bytes
    carry information in every character and some are a length test wearing a
    costume:

    * hex is 64 characters of sixteen; base32 is 56 of thirty-two, uppercase, without
      0, 1, 8 or 9. Ordinary text does not accidentally look like either.
    * base64 is 43 characters of sixty-four and base85 is 40 of eighty-five — which
      is to say ANY forty-three alphanumerics and ANY forty printable characters.
      "privatesecurefilescompanyinternalexamplecom" is forty-three characters of
      base64url, and that is a domain.

    So the second group may only ever be asked about a WHOLE value a caller handed
    over, where a refusal is explainable. The first group can be asked about joins and
    subsequences too, because a 64-character run of hex digits inside a hostname is
    not a hostname.
    """
    compact = "".join(value.split())
    return _is_hex_of_a_key(compact) or _is_base32_of_a_key(compact)


def spells_a_key_exactly(text: str) -> bool:
    """Whether ``text`` is a key in the base64 family, and nothing longer or shorter.

    The narrow question, for asking about a JOIN. renders_key_bytes answers the wide
    one, about a whole value a caller handed over.
    """
    compact = _aliased("".join(text.split())).rstrip("=")
    return len(compact) == KEY_TEXT_LENGTH and looks_like_a_key(compact)


def _is_a_bytes_literal_of_a_key(value: str) -> bool:
    """``repr(key)`` — what an f-string does to raw bytes, and what a log line keeps."""
    text = value.strip()
    if not text.startswith(("b'", 'b"')) or len(text) > 4 * KEY_BYTES * 8:
        return False
    try:
        decoded = ast.literal_eval(text)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return False
    return isinstance(decoded, bytes) and len(decoded) == KEY_BYTES


def _is_a_key_spelled_with_slashes(value: str) -> bool:
    """Whether ``value`` IS a key, with standard base64's ``/`` and ``+`` in it.

    THE SLASHES FALL WHERE THE BYTES FALL. A key re-encoded with standard base64
    rather than base64url puts "/" and "+" wherever the data puts them — 20/6/15,
    not 11/11/11/10 — so the uniformity gate that catches a hand-chunked key does
    nothing here, and neither does dropping the separators, because these separators
    ARE key characters.

    ANCHORED ON THE WHOLE VALUE, deliberately and at a cost. Reading every
    separator-delimited span that way redacts 7.7% of the real paths on this machine,
    and reading every window redacts 50%; requiring the entire value to be exactly a
    key's length costs 0.18% — paths like /usr/share/clang/scan-view-18/bin/scan-view,
    which are 43 characters with no dot in them, and which lose their name in a
    "no such file" message and nothing else.

    THE GAP THIS LEAVES, said plainly: the same spelling nested inside a longer path,
    "/tmp/<that value>", is not caught. Catching it means reading an ordinary
    separator as a key character somewhere, and every version of that I could measure
    costs more paths than it is worth.
    """
    # PADDING AND WHITESPACE FIRST. Canonical standard base64 of 32 bytes is
    # FORTY-FOUR characters — b64encode pads — and encodebytes adds a newline after
    # the padding, so rstrip("=") alone removed nothing from the MIME spelling. Both
    # come off in renders_key_bytes, which also knows the renderings that are not
    # base64 at all.
    return renders_key_bytes(value)


def joined_path_spells_a_key(path: str) -> bool:
    """Whether a path SPELLS a key once its separators are read as part of it.

    NARROWER THAN path_carries_key_material, DELIBERATELY. This is asked about the
    path that ``ReceivedFile.save`` is about to open, after the directory and the name
    have each been checked on their own — so the only thing left to catch is a
    rendering that the join put back together: "Pz8/Pz8/…/Pz8=" is b64encode of 32
    bytes and also ten directories and a filename.

    Asking the full predicate there was wrong, and its own test suite said so within a
    minute: "…/test_a_hostile_filename_canno0/authorized_keys" is 30 characters and 15,
    which is the shape of a split at width thirty, and the fragment pass finds a
    key-sized window in their 45-character join. That pass exists for a key with
    DECORATION on it, where loose matching earns its keep; a caller saving a file into
    a directory whose name is long is not that.
    """
    return renders_key_bytes(path) or bool(_uniform_run_carrying_key(_components(path)))


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
    if _is_a_key_spelled_with_slashes(path):
        return f"<{len(path)} characters, not repeated>"
    pieces = _SEPARATORS.split(path)
    parts = pieces[::2]
    separators = pieces[1::2]
    suspect = _parts_carrying_key(parts)
    if not suspect:
        return path
    out = []
    for index, part in enumerate(parts):
        out.append(f"<{len(part)} characters, not repeated>" if index in suspect else part)
        if index < len(separators):
            out.append(separators[index])
    return "".join(out)


#: What separates one component of a path from the next. BACKSLASH TOO, because a
#: Windows path is the same disclosure with a different key on the keyboard:
#: "C:\\Users\\me\\<key[:21]>\\<key[21:]>" split on "/" alone is ONE component that
#: happens to contain no long run, so both halves printed in full.
_SEPARATORS = re.compile(r"([/\\])")


def _components(path: str) -> list[str]:
    """``path`` as its components, on either separator."""
    return _SEPARATORS.split(path)[::2]


def _parts_carrying_key(parts: Sequence[str], *, chunk_floor: int = 4) -> set[int]:
    """Which components could carry key material — alone, or joined to a neighbour.

    A KEY SPLIT ACROSS COMPONENTS is carried by none of them on its own:
    ``key[:21] + "/" + key[21:]`` has two parts, both under the threshold, and the
    message printed every character. So contiguous components are joined and the
    join is searched for a key.

    SEARCHED, NOT COMPARED, which is the correction this round. Testing whether the
    join was EXACTLY a key read as precise and was defeated by four characters:
    ``<key[:21]>.<key[21:]>-old`` joins to 47 characters that are not a key and
    contain one, and a host shaped like that sends every character through DNS. So
    every key-sized window of the join is tested instead.

    AND "IS A KEY" IS A LENGTH TEST, which is worth saying plainly because I have
    been describing it as something sharper. ANY forty-three characters of base64url
    decode to exactly thirty-two bytes — 43 = 40 + 3 gives 30 + 2 — so
    looks_like_a_key asks how long a value is and what alphabet it is in, and nothing
    else. There is no entropy check to be had; the precision here is the size.

    AND ONLY WHERE THE PIECES ARE BIG ENOUGH TO BE PIECES OF A KEY, which is what
    keeps this from eating ordinary paths. ``/home/me/Documents/work/2026/rapporter``
    joins to 45 characters of perfectly good base64url alphabet, and a window scan
    with no other condition would redact it — the exact over-strictness that broke
    self-hosted hosts two rounds ago, moved to paths. A component carrying part of a
    key is at least KEY_RUN characters of the alphabet; "home" and "me" are not, so
    only runs of components that all clear that bar are joined. The gap is a key
    split into four pieces of eleven, which is a shape nothing produces by accident;
    the alternative is a library that cannot print a directory.

    ONLY THE PARTICIPANTS are marked. Redacting the whole path throws away the half
    that identifies the mistake — "/home/me/<a key>" should name the directory and
    withhold the name. My first version hid "home" and "me" too: safe and useless.
    """
    suspect = {index for index, part in enumerate(parts) if _run_in(part, _PATH_CHARACTERS)}
    # A COMPONENT THAT COULD HOLD A WHOLE KEY BY ITSELF IS NOT A FRAGMENT. It is
    # already marked by the run test above, and letting it into a join implicates its
    # neighbours: "…/pytest-180/test_a_key_shaped_filename_is_0/<key>" has a 43-
    # character window straddling the directory and the key, so the directory this
    # suite needs to print was withheld. Joins exist for the key that no single
    # component can hold.
    fragments = [
        index
        for index, part in enumerate(parts)
        if len(part) >= KEY_RUN and _run_in(part, _KEY_CHARACTERS) and not _holds_a_key(part)
    ]
    for run in _contiguous(fragments):
        joined = "".join(parts[index] for index in run)
        spans, position = [], 0
        for index in run:
            spans.append((index, position, position + len(parts[index])))
            position += len(parts[index])
        found = False
        for start in range(len(joined) - KEY_TEXT_LENGTH + 1):
            if not looks_like_a_key(joined[start : start + KEY_TEXT_LENGTH]):
                continue
            found = True
            # ONLY THE COMPONENTS THE WINDOW ACTUALLY TOUCHES. Marking the whole run
            # hid this suite's own tmp_path: "pytest-180/test_a_key_shaped_…_is_0"
            # sits next to a key-named file, so the run matched and the directory the
            # caller needs to see went with it. A window inside one component
            # implicates one component.
            window = range(start, start + KEY_TEXT_LENGTH)
            suspect |= {
                index
                for index, first, last in spans
                if first < window.stop and last > window.start
            }
        if not found and _holds_a_key(joined):
            # Some other spelling of the join is a key — percent-encoded, folded,
            # spaced. The offsets do not survive those transformations, so the whole
            # run is withheld rather than guessed at.
            suspect.update(run)

    # AND THE SEPARATOR ITSELF CAN BE PART OF THE KEY, which the pass above cannot
    # see. Standard base64 spells with "/", so ("A" * 10 + "/") * 3 + "A" * 10 is a
    # path of four ten-character components AND a 43-character key once the slashes
    # are read as underscores — and a key chunked four ways by hand is the same
    # shape. Neither piece reaches KEY_RUN, so neither is a fragment.
    #
    # THE SEPARATORS ARE DROPPED, NOT TRANSLATED, and the difference is the whole of
    # a P2 I earned. I first joined these with "_" — which works only because an
    # underscore happens to be a base64url character — and _parts_carrying_key is
    # also what origin_of asks about DNS labels. So
    # private.secure.files.company.internal.example, whose labels are 7/6/5/7/8/7,
    # joined to 45 characters with the dots read as underscores and was refused: an
    # ordinary custom origin broken, for the fourth time on this branch, by a leak
    # fix of mine. Dropping the separators is also the correct reading of the thing
    # being caught — somebody chunked a key, the separators are not part of it — and
    # those same labels then join to 40 characters, which is not a key.
    #
    # The uniformity gate stays: a key cut into pieces is cut at a fixed width, by
    # whoever cut it, while /home/me/Documents/work/2026/rapporter is not. Measured
    # over 99,595 real paths on this machine, this redacts 0.06% of them.
    suspect |= _uniform_run_carrying_key(parts, chunk_floor)
    # AND THE STRICT RENDERINGS, at every contiguous run and at any floor. A prefix
    # defeated everything above: "/tmp/" + hex("/") is two-character components, none
    # of them a fragment by any threshold, joining to a key in hex.
    suspect |= _subsequence_renders_key_strictly(parts)
    return suspect


def renders_key_bytes_strictly_inside(value: str) -> bool:
    """Whether a hex or base32 rendering is IN ``value``, decorated or not.

    A WINDOW SCAN, WHICH ONLY THE STRICT RENDERINGS EARN. "safe;" in front of sixty-
    four hex digits is not a rendering as a whole and contains one — and the same
    scan over the degenerate spellings would refuse any value with forty printable
    characters in it, which is a password.

    The lengths are derived from what the encoders produce rather than guessed: 56 for
    base32, 64 for hex and base32hex, and hex with a separator at every group size.
    """
    compact = "".join(value.split())
    for length in _STRICT_LENGTHS:
        for start in range(len(compact) - length + 1):
            if renders_key_bytes_strictly(compact[start : start + length]):
                return True
    return False


def _subsequence_renders_key_strictly(parts: Sequence[str]) -> set[int]:
    """Which contiguous components join into a hex or base32 rendering of a key.

    ASKED OF EVERY CONTIGUOUS RUN, unlike the base64 partition test, and that is
    affordable for exactly one reason: these two renderings say something with every
    character. bytes(range(32)).hex(".") is thirty-two two-character labels that join
    to sixty-four hex digits, and a hostname or a path prefix in front of it does not
    change what it is — while an ordinary domain joining to sixty-four hex digits is
    not a thing that happens. The base64 family cannot be asked this way at all:
    "privatesecurefilescompanyinternalexamplecom" is forty-three characters of
    base64url, and it is a domain.
    """
    suspect: set[int] = set()
    for start in range(len(parts)):
        for end in range(start + 2, len(parts) + 1):
            if renders_key_bytes_strictly("".join(parts[start:end])):
                suspect.update(range(start, end))
    return suspect


def _uniform_run_carrying_key(parts: Sequence[str], chunk_floor: int = 4) -> set[int]:
    """Components of an evenly-chunked run whose separators complete a key.

    ``chunk_floor`` IS HIGHER FOR A HOSTNAME, and that is the fifth hostname
    regression on this branch talking. A domain is a handful of SHORT labels, and
    four of them concatenate past forty-three characters without anybody chunking
    anything: private.secure.files.company.internal.example.com became "a key" the
    moment a three-character TLD could join a run as its remainder. On a host a piece
    of a key has to be at least KEY_RUN characters — the same threshold the rest of
    this module uses for "long enough to be part of a key" — which leaves a hostname
    chunked into pieces of eleven uncaught, and that is a deliberate construction
    rather than a name anybody registers.
    """
    suspect: set[int] = set()
    run: list[int] = []

    def close(remainder: int | None = None) -> None:
        # THE LAST PIECE OF A FIXED-WIDTH SPLIT IS SHORT, ALWAYS. textwrap.wrap of a
        # 43-character key at ten gives 10/10/10/10/3, and the three closed the run
        # before it could be counted — leaving forty characters, which is not a key,
        # and a stranded remainder. So a component too short to continue a run is
        # still tried as its end.
        widest = run if remainder is None else [*run, remainder]
        # THE PIECES MUST ADD UP TO A KEY AND NOTHING MORE. Looking for a key-sized
        # WINDOW in the join was too loose the moment a remainder could join a run:
        # "test_a_hostile_filename_canno0/authorized_keys" is 30 and 15, which is
        # exactly the shape of a split at width thirty, and its 45-character join
        # contains a 43-character window. Somebody who chunked a key produced a
        # partition OF that key, so the join is the key — nothing before it, nothing
        # after. Decoration on a chunk is the fragment pass's business, where the
        # pieces are long enough to be worth joining loosely.
        #
        # AND THE BASE64 FAMILY ONLY, not every rendering. Base85 turns 32 bytes into
        # FORTY characters of an alphabet that covers every letter and digit, so "any
        # forty alphanumerics" decode to 32 bytes — which is tolerable as a question
        # about one whole value and is not tolerable here, where every pair of
        # neighbouring components is a candidate. This suite's own tmp_path said so:
        # "test_a_tilde_in_the_directory_0" and "Downloads" are 31 and 9.
        if len(widest) >= 2 and spells_a_key_exactly("".join(parts[index] for index in widest)):
            suspect.update(widest)

    for index, part in enumerate(parts):
        # THE FLOOR IS FOR STARTING A RUN, NOT FOR ENDING ONE. A remainder can be one
        # character — wrap(key, 20) gives 20/20/3 — so it is asked about as an end
        # before the run is closed without it, and only its alphabet matters there.
        alphabet = bool(part) and bool(_EVENLY_CHUNKED.fullmatch(part))
        even = alphabet and len(part) >= chunk_floor
        if even and (not run or abs(len(part) - len(parts[run[0]])) <= _CHUNK_SLACK):
            run.append(index)
            continue
        if alphabet and run and len(part) < len(parts[run[0]]):
            close(index)
        close()
        run = [index] if even else []
    close()
    return suspect


def _contiguous(indexes: Sequence[int]) -> list[list[int]]:
    """``[1, 2, 5, 6, 7]`` as ``[[1, 2], [5, 6, 7]]`` — runs of neighbours, two or more."""
    runs: list[list[int]] = []
    for index in indexes:
        if runs and index == runs[-1][-1] + 1:
            runs[-1].append(index)
        else:
            runs.append([index])
    return [run for run in runs if len(run) > 1]


def _holds_a_key(joined: str) -> bool:
    """Whether any key-sized window of any spelling of ``joined`` is a key."""
    for spelling in _spellings(joined):
        for start in range(len(spelling) - KEY_TEXT_LENGTH + 1):
            if looks_like_a_key(spelling[start : start + KEY_TEXT_LENGTH]):
                return True
    return False


def scrubbed(text: str, given: Sequence[str] = ()) -> str:
    """A message written by somebody else, with anything key-shaped taken out.

    FOR ARGPARSE, WHICH FORMATS ITS OWN REFUSALS AND WRITES THEM ITSELF. "invalid
    choice: '<the whole key>'" reaches stderr before any of this library's code runs,
    and the SystemExit it then raises carries nothing, so the exception was spotless
    and the terminal had the key on it. I fixed that for ``--market`` by dropping
    ``choices=``, then for ``--max-downloads`` by replacing ``type=int`` — twice
    fixing the option in front of me. The subcommand slot was the third, and there is
    no way to take ``choices=`` off a subparser: ``sikkerfil <a key>`` is a plausible
    command/link mix-up and printed every character.

    So this handles the class instead: every argparse message goes through here, with
    the argv it was raised about. Three passes, in order of precision: the values
    themselves are replaced where they appear, then runs long enough to be part of a
    key, and finally the whole message is dropped if any spelling of what is left
    still holds a key.
    """
    # BY IDENTITY FIRST, because a pattern cannot see a key that has been taken apart.
    # argparse formats the offending argv element into its message, and " ".join(key)
    # is forty-two characters with a space between each one: no run for the regex to
    # find, too short for the whole-key fallback, and deleting the spaces gives back
    # 252 of the key's 256 bits. But we HAVE the argv this message is about, so the
    # value does not have to be recognised — it can be matched.
    #
    # Both spellings, because %r is how argparse formats a value and a value with a
    # newline in it appears escaped rather than literal.
    cleaned = text
    for value in given:
        if not value or not opaque_carries_key_material(value):
            continue
        placeholder = f"<{len(value)} characters, not repeated>"
        for spelling in (repr(value), value):
            cleaned = cleaned.replace(spelling, placeholder)
    cleaned = _PATH_CHARACTERS.sub(lambda m: f"<{len(m.group())} characters>", cleaned)
    # THE FALLBACK ASKS FOR A WHOLE KEY, not a run, and that is a correction: a run
    # test over the whitespace-folded spelling withheld "the following arguments are
    # required: file", because "thefollowingargumentsarerequired" is thirty-two
    # characters of the alphabet once the spaces come out. Prose reaches thirty-two;
    # it does not reach forty-three characters that decode to a 32-byte key.
    if any(
        _holds_a_key(spelling) or _holds_a_key(_aliased(spelling))
        for spelling in _spellings(cleaned)
    ):
        return "that value is not repeated here, because it could be a decryption key"
    return cleaned


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


def _safe_to_echo(value: str) -> bool:
    """Whether printing ``value`` hands over nothing.

    BOTH QUESTIONS, because carries_key_material reads runs and a rendering need not
    contain one: base_url_for(key.hex(".")) put ninety-five characters of dotted hex
    into its own refusal, every run of it two characters long. quoted() is the
    chokepoint every message in this module goes through, so it is the place where
    "could this be a key in some spelling" has to be asked in full.
    """
    return not carries_key_material(value) and not renders_key_bytes(value)


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

    AND A RUN IS NOT THE ONLY SHAPE, which was the finding after THAT.
    ``base_url_for(key.hex("."))`` put ninety-five characters of dotted hex into its
    own refusal, and every run in it is two characters long. So this asks both
    questions — runs, and whether the whole value is a rendering of 32 bytes in any
    spelling the standard library writes.

    What still prints: a mistyped market code, a wrong scheme, a duration, a short
    id — everything a person actually fat-fingers. What does not: an unbroken run of
    :data:`KEY_RUN` base64url characters, or a value that decodes to 32 bytes.
    """
    return "<not repeated here: it may carry a key>" if not _safe_to_echo(value) else repr(value)


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
#: How many characters a whole key is: base64url of 32 bytes, unpadded. Derived
#: rather than written, because 43 is the sort of number that gets typed once and
#: then disagreed with.
KEY_TEXT_LENGTH = -(-KEY_BYTES * 4 // 3)

#: The characters a hex dump is made of, so that everything else in one is its
#: separator.
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

#: How long the STRICT renderings of 32 bytes are: base32 (56), hex and base32hex
#: (64), and hex with one separator character at every group size it takes. Derived,
#: because a list of lengths I typed is the same mistake as a list of alphabets.
_STRICT_LENGTHS = sorted(
    {56, 64} | {64 + -(-KEY_BYTES // per_group) - 1 for per_group in range(1, KEY_BYTES)}
)

#: A component that is nothing but key alphabet — no dot, no space, no extension.
_EVENLY_CHUNKED = re.compile(r"[A-Za-z0-9_-]+")

#: How much two pieces of one chunked key may differ in length. Two, because a key
#: of 43 characters cut in three is 15/15/13 and cut in four is 11/11/11/10. Three
#: triples the false positives on real paths for nothing this catches.
_CHUNK_SLACK = 2

_KEY_CHARACTERS = re.compile(rf"[A-Za-z0-9_-]{{{KEY_RUN},}}")
_PATH_CHARACTERS = re.compile(rf"[A-Za-z0-9_-]{{{PATH_RUN},}}")


def _run_in(value: str, pattern: re.Pattern[str]) -> bool:
    """Whether ``pattern`` matches any spelling of ``value`` that a reader could undo.

    EVERY SPELLING, because a run check reads characters and a key can be written
    more ways than one:

    WHITESPACE OUT, because the decoder takes it out. key_text accepts a key spelled
    with spaces between every character, or wrapped across two lines — deliberately,
    for keys mangled by a mail client — so a check reading the raw text saw no run
    and echoed the whole thing. That was one bypass in the value check and then,
    once fixed, the same bypass again in the path check, where a key across two
    lines splits into a twenty and a twenty-three.

    AND COMPATIBILITY-NORMALISED, which key_text does NOT accept and which is the
    point. A fullwidth transcription is refused as a key — base64 needs ASCII — so
    the old reasoning said it was not a key and could be printed. But it NFKC-folds
    straight back to a working one, and anybody reading the log can do that fold.
    "Not a value we would accept" is not the same as "not a disclosure".
    """
    return any(pattern.search(spelling) for spelling in _spellings(value))


def _spellings(value: str) -> tuple[str, ...]:
    """``value`` in every form a reader could get back out of it.

    As written, with the whitespace out, and compatibility-normalised.

    NOT PERCENT-DECODED, and that is a deliberate omission rather than an oversight.
    Percent-decoding matters exactly where something downstream decodes before
    acting, which is the hostname — urllib decodes a host before it resolves it — and
    origin_of does that decode itself, explicitly, where it is tested. I had it here
    too, for a while, and could not make a single test fail by taking it out: a
    filesystem path is not decoded by anybody, a base URL may no longer carry a path
    at all, and a reference is `[a-z0-9-]` or `[0-9A-Z]`, so a `%` in one is refused
    before this is asked. Machinery no test can reach is machinery I have already
    shipped believing in twice.

    Not aliased here either: ``+`` and ``/`` are standard base64's pair, and folding
    them into ``-_`` merges the components of a path into one long run, so an ordinary
    ``/home/me/Documents/rapporter`` would read as key material. Values that are not
    paths get that fold in opaque_carries_key_material, where it is safe.
    """
    folded = unicodedata.normalize("NFKC", value)
    return (value, "".join(value.split()), folded, "".join(folded.split()))


def _aliased(value: str) -> str:
    """The same characters, read as base64url rather than standard base64.

    ``("A" * 10 + "/") * 3 + "A" * 10`` is 43 characters that decode to 32 bytes the
    moment somebody swaps the slashes for underscores, and the decoder here refuses
    that spelling — which is correct as INPUT and was wrong as detection. "We would
    not accept it" says nothing about whether printing it hands over a key: this is
    the same mistake as the fullwidth transcription, in the other alphabet.
    """
    return value.replace("+", "-").replace("/", "_")


def opaque_carries_key_material(value: str) -> bool:
    """Whether a value that is NOT a path could carry key material.

    A password, a content type, a share name: strings where ``/`` is an ordinary
    character rather than a separator, so the standard-base64 alias can be folded
    without merging anything that was meant to be apart.

    AT THE PATH THRESHOLD, not the value one, because these are values a caller
    chooses and refusing one costs them their password or their share name.
    ``application/octet-stream`` folds to 24 characters and prints; 32 unbroken
    characters of base64url is not a content type anybody wrote.
    """
    if renders_key_bytes(value):
        return True
    return any(
        _PATH_CHARACTERS.search(spelling) or _PATH_CHARACTERS.search(_aliased(spelling))
        for spelling in _spellings(value)
    )


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
