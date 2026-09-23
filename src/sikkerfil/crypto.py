"""
The encryption, which is the entire product.

THE SERVICE NEVER HOLDS A KEY. Everything in this module runs in the caller's
process; what leaves it is ciphertext and an IV. The key goes into the URL
fragment (``#k=...``), and a fragment is not sent to the server, does not appear
in a Referer header, and is not written to an access log. That is the whole
mechanism, and it is why ``sikkerfil.no/personvern`` can promise what it does.

THE ENVELOPE IS FIXED BY THE BROWSER, NOT BY US.

    iv (12 bytes) || ciphertext (n) || tag (16 bytes)

A file sent from this library must open in the web client, and a file sent from
the web client must open here — a Python SDK that produced files its own website
could not read would be worse than no SDK. That constraint is not a matter of
taste, so it is not left to the reader to preserve: ``tests/test_interop.py``
encrypts with the same WebCrypto calls the browser makes and decrypts the result
here, and vice versa.

WHY THE TAG IS NOT A SEPARATE FIELD. WebCrypto's ``encrypt`` appends the GCM tag
to the ciphertext and its ``decrypt`` expects it there. So does pyca's one-shot
``AESGCM``. APIs that take the tag separately — Node's ``createDecipheriv``, or
``Cipher.update``/``finalize`` — need the last 16 bytes pulled off by hand, which
is the single most common way somebody reimplements this wrong. Here the two
sides already agree and nothing has to be split.

WHY NOT ``openssl enc``. It refuses AEAD ciphers outright ("AEAD ciphers not
supported"), which is worth stating because it is the first thing anybody tries
and the error does not explain itself.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ConfigurationError, DecryptionError

#: AES-256. The browser generates the same length and there is no negotiation.
KEY_BYTES = 32

#: 96 bits, the size GCM is specified for. Anything else costs security for no
#: benefit, and WebCrypto's default is this.
IV_BYTES = 12

#: The GCM authentication tag, appended to the ciphertext by both sides.
TAG_BYTES = 16

#: The smallest envelope that can exist: an empty file is still iv and tag.
MIN_ENVELOPE_BYTES = IV_BYTES + TAG_BYTES


def b64url_encode(raw: bytes) -> str:
    """base64url, unpadded — the spelling the browser's ``toBase64Url`` produces.

    Unpadded matters: the key travels in a URL fragment, and ``=`` there is legal
    but ugly and gets helpfully escaped by things that rewrite links.
    """
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    """The inverse, tolerating padding and whitespace whether or not they are there.

    Anything that hands a key back to us — a URL bar, a config file, a shell
    variable somebody quoted, an email that wrapped the line — may or may not have
    kept the padding, and may have picked up whitespace. Refusing a correct key
    over a presentational detail is not a security property.

    WHITESPACE GOES BEFORE THE PADDING IS COUNTED, and that order is the whole
    point. base64 decoding DISCARDS whitespace but the padding calculation COUNTS
    it, so without this a key with ONE internal space was refused while the same
    key with TWO was accepted — a coin flip on how much whitespace came along.

    It cannot turn an invalid value into a valid key: 32 bytes needs 43 base64
    characters, so a key with a character genuinely missing is still short, and
    every caller that wants a key checks the length.
    """
    compact = "".join(text.split())
    padded = compact + "=" * (-len(compact) % 4)

    # THE STDLIB ERROR CARRIES THE VALUE. A UnicodeEncodeError holds the entire
    # rejected string on `.object` — so a key with one smart quote in it, pasted
    # into this by a caller following the README, produced an exception with the
    # key inside it. Neither str() nor the message shows it, which is exactly why
    # it survived several passes over these messages.
    #
    # Still a ValueError, because that is what a decoder raises and what callers
    # catch (binascii.Error and UnicodeEncodeError are both ValueErrors). Raised
    # after the handler has exited, so nothing is left on __context__ either.
    decoded: bytes | None = None
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (TypeError, ValueError):
        decoded = None
    if decoded is None:
        raise ValueError(
            f"not base64url: {len(text)} characters that will not decode. The "
            "value is not repeated here, because in this library it is usually a "
            "decryption key."
        )
    return decoded


def key_text(key: str | bytes | bytearray | memoryview) -> str:
    """One key, canonically spelled: unpadded base64url, as it appears after ``#k=``.

    THE SAME KEY HAS THREE SPELLINGS and callers hold whichever one they were
    handed. ``new_key()`` and ``Sealed.key`` are raw bytes; ``Sealed.key_text``
    and a link fragment are base64url text; a key read back out of a config file
    or a shell variable may have kept its ``=`` padding, or a newline, or a line
    wrap. They are one key, and anything comparing or publishing them must agree
    on that.

    WHAT GOES WRONG WITHOUT THIS IS NOT A CRASH. Interpolate the bytes you have
    into a link and you get ``#k=b'\\x9c\\x1f...'`` — plausible length, opens for
    nobody, and the sending side never finds out. Compare the spellings instead of
    the keys and one key reads as two, so a caller passing a correct key is told
    it contradicts itself.

    So: bytes are encoded rather than repr'd, padding is dropped, and anything
    that is not a key is refused by name.

    This signature is wider than the public API's ``str | bytes``, because this is
    where the widening happens — the callers advertise the two spellings anybody
    actually holds.
    """
    if isinstance(key, (bytes, bytearray, memoryview)):
        raw = bytes(key)
    else:
        # Whitespace and padding are b64url_decode's problem, for every caller
        # and not just this one — a key pasted into it directly had the same
        # modulo-four coin flip this function was fixed for.
        decoded: bytes | None = None
        try:
            decoded = b64url_decode(key)
        # Both spellings of "not base64url" land here: binascii.Error for bad
        # characters and UnicodeEncodeError for non-ASCII are each a ValueError.
        except (TypeError, ValueError):
            decoded = None

        # RAISED OUT HERE, NOT IN THE HANDLER, and that is the whole point of the
        # flag. `raise ... from None` suppresses how a context is DISPLAYED; it
        # does not remove the object, and a UnicodeEncodeError carries the entire
        # rejected string on `.object` — so a near-miss key stayed reachable on
        # __context__ with a clean message in front of it. Raising after the
        # handler has exited means there is no context to carry.
        if decoded is None:
            # THE VALUE IS NOT IN THIS MESSAGE either, deliberately. A key that
            # fails to decode is usually a nearly correct key — one character
            # short, or with a smart quote in it — and repeating it here puts it in
            # whatever log swallows the traceback.
            raise ConfigurationError(
                "a sikkerfil key is base64url text or 32 raw bytes; this is "
                f"{len(key)} characters that will not decode as base64url. The "
                "value is not repeated here because it is a decryption key. The "
                "text is what Sealed.key_text gives you, and what follows #k= in "
                "a share link."
            )
        raw = decoded
    if len(raw) != KEY_BYTES:
        raise ConfigurationError(
            f"a sikkerfil key is {KEY_BYTES} bytes ({KEY_BYTES * 8}-bit AES); this "
            f"one is {len(raw)}. Something this size opens nothing, so it is "
            "refused before it becomes a link or a download."
        )
    # Re-encoded rather than passed through: '=' in a fragment is legal and gets
    # helpfully escaped by things that rewrite links, and the browser writes
    # unpadded, so unpadded is the one spelling everything else can be compared to.
    return b64url_encode(raw)


def new_key() -> bytes:
    """A fresh 256-bit key from the OS CSPRNG. One per file, never reused."""
    return os.urandom(KEY_BYTES)


@dataclass(frozen=True, repr=False)
class Sealed:
    """One encrypted file: the bytes to upload, and the key that opens them."""

    #: ``iv || ciphertext || tag`` — exactly what gets PUT to the upload URL.
    blob: bytes
    #: The raw key. Never sent anywhere; ``key_text`` is what goes in the link.
    key: bytes

    @property
    def key_text(self) -> str:
        """The key as it appears after ``#k=`` in a share link."""
        return b64url_encode(self.key)

    def __repr__(self) -> str:
        """Without the key. A dataclass repr would have printed it in full.

        ``repr=False`` above is a safety belt rather than the mechanism — a
        dataclass leaves a ``__repr__`` defined in the body alone — so deleting
        this method falls back to object's repr instead of a generated one.

        This is the last way the key reached a log without anyone deciding it
        should: not a message we write, but the DEFAULT repr of an object a
        caller holds. One ``print(sealed)`` while debugging an upload was enough.
        """
        return f"Sealed(blob=<{len(self.blob)} bytes>, key=<hidden>)"


def seal(plaintext: bytes, key: bytes | None = None) -> Sealed:
    """Encrypt ``plaintext`` under a fresh key (or one supplied).

    A key is accepted so the filename can be sealed under the SAME key as the
    file it names — see :func:`seal_name`. Callers encrypting a file should let
    this generate one; reusing a key across two files is the caller taking on a
    property this module otherwise guarantees.
    """
    if key is None:
        key = new_key()
    _check_key(key)
    iv = os.urandom(IV_BYTES)
    # AESGCM.encrypt returns ciphertext || tag, which is the tail of the
    # envelope as the browser writes it. No splitting, no reassembly.
    return Sealed(blob=iv + AESGCM(key).encrypt(iv, plaintext, None), key=key)


def open_sealed(blob: bytes, key: bytes) -> bytes:
    """Decrypt an envelope produced by this library or by the web client.

    Raises :class:`~sikkerfil.errors.DecryptionError` when the tag does not
    verify, which means one of: the wrong key, a truncated download, or bytes
    that were altered in transit. GCM cannot tell those apart and neither can we
    — what matters is that it is a refusal rather than plausible-looking garbage.
    """
    _check_key(key)
    if len(blob) < MIN_ENVELOPE_BYTES:
        raise DecryptionError(
            f"the downloaded object is {len(blob)} bytes; an envelope is at least "
            f"{MIN_ENVELOPE_BYTES} (a {IV_BYTES}-byte IV and a {TAG_BYTES}-byte tag). "
            "This is a truncated or empty download, not a decryption problem."
        )
    try:
        return AESGCM(key).decrypt(blob[:IV_BYTES], blob[IV_BYTES:], None)
    except InvalidTag as exc:
        raise DecryptionError(
            "the file did not decrypt: the authentication tag does not verify. "
            "Either the key after #k= is not the one this file was sealed with, "
            "or the bytes were altered or truncated in transit."
        ) from exc


def seal_name(name: str, key: bytes) -> str:
    """Seal a filename under the file's own key, as base64url.

    A FILENAME LEAKS MOST OF THE DOCUMENT. "oppsigelse-ansatt-4412.pdf" tells
    the service, and anyone who ever reaches its table, what the file is and who
    it is about. There is no reason for the server to hold one, so it does not —
    it stores this opaque string and hands it back to whoever has the key.
    """
    return b64url_encode(seal(name.encode("utf-8"), key).blob)


def open_name(sealed_text: str, key: bytes) -> str | None:
    """Recover a sealed filename, or ``None`` if it will not open.

    DELIBERATELY NOT AN ERROR. The web client makes the same choice: a filename
    that will not decrypt must not fail the download, because the file itself may
    be perfectly good and a caller with the bytes and no name is far better off
    than a caller with an exception. The name is a convenience; the file is the
    product.
    """
    try:
        return open_sealed(b64url_decode(sealed_text), key).decode("utf-8")
    except (DecryptionError, ValueError, UnicodeDecodeError):
        return None


def _check_key(key: bytes) -> None:
    if len(key) != KEY_BYTES:
        raise DecryptionError(
            f"a sikkerfil key is {KEY_BYTES} bytes ({KEY_BYTES * 8}-bit AES); "
            f"this one is {len(key)}. If it came from a link, it is the part "
            "after #k= decoded as base64url."
        )
