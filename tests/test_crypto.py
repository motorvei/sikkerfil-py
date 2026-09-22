"""
The envelope, its edges, and the promises made about it.

``test_interop.py`` proves the format agrees with the browser. This proves the
properties: that keys are unique, that a tamper is caught, that a truncation is
told apart from a wrong key, and that a name that will not open does not take
the file down with it.
"""

from __future__ import annotations

import pytest

from sikkerfil import crypto
from sikkerfil.errors import DecryptionError


def test_a_key_is_256_bits_and_never_repeats() -> None:
    keys = {crypto.new_key() for _ in range(500)}
    assert len(keys) == 500, "two keys collided; the CSPRNG is not being used"
    assert all(len(k) == 32 for k in keys)


def test_the_envelope_is_iv_then_ciphertext_then_tag() -> None:
    sealed = crypto.seal(b"x" * 100)
    assert len(sealed.blob) == crypto.IV_BYTES + 100 + crypto.TAG_BYTES
    # The plaintext is not sitting in the envelope in the clear.
    assert b"x" * 100 not in sealed.blob


def test_the_iv_is_fresh_for_every_file() -> None:
    """GCM's one absolute requirement: never reuse an IV with the same key.

    Two files here get different keys anyway, but a fixed IV would still be a
    bug worth failing on — it is the single mistake that turns AES-GCM from
    secure into trivially broken.
    """
    key = crypto.new_key()
    ivs = {crypto.seal(b"same plaintext", key).blob[: crypto.IV_BYTES] for _ in range(200)}
    assert len(ivs) == 200


def test_the_same_plaintext_under_the_same_key_is_never_the_same_bytes() -> None:
    key = crypto.new_key()
    assert crypto.seal(b"hello", key).blob != crypto.seal(b"hello", key).blob


def test_a_round_trip_survives_anything() -> None:
    for payload in [b"", b"\x00", b"\xff" * 1000, "æøå — Grüße".encode(), bytes(range(256))]:
        sealed = crypto.seal(payload)
        assert crypto.open_sealed(sealed.blob, sealed.key) == payload


def test_an_empty_file_is_still_a_valid_envelope() -> None:
    sealed = crypto.seal(b"")
    assert len(sealed.blob) == crypto.MIN_ENVELOPE_BYTES
    assert crypto.open_sealed(sealed.blob, sealed.key) == b""


def test_a_flipped_bit_anywhere_is_refused() -> None:
    """THE REASON FOR AN AEAD. A cipher without authentication would hand back
    altered plaintext and look like it worked."""
    sealed = crypto.seal(b"transfer 100 NOK to account 1234")
    for position in (0, crypto.IV_BYTES, len(sealed.blob) - 1, len(sealed.blob) // 2):
        tampered = bytearray(sealed.blob)
        tampered[position] ^= 0x01
        with pytest.raises(DecryptionError, match="authentication tag"):
            crypto.open_sealed(bytes(tampered), sealed.key)


def test_the_wrong_key_is_refused() -> None:
    sealed = crypto.seal(b"secret")
    with pytest.raises(DecryptionError, match="authentication tag"):
        crypto.open_sealed(sealed.blob, crypto.new_key())


def test_a_truncated_download_is_told_apart_from_a_wrong_key() -> None:
    """Different causes, different fixes.

    "Your key is wrong" sends somebody hunting for a typo in a link that is
    perfectly correct, when what actually happened is that the transfer was cut
    off. Both are an InvalidTag to GCM, so the length is checked first.
    """
    with pytest.raises(DecryptionError, match="truncated"):
        crypto.open_sealed(b"short", crypto.new_key())
    with pytest.raises(DecryptionError, match="truncated"):
        crypto.open_sealed(b"", crypto.new_key())


def test_a_key_of_the_wrong_length_says_so() -> None:
    with pytest.raises(DecryptionError, match="32 bytes"):
        crypto.open_sealed(crypto.seal(b"x").blob, b"tooshort")


def test_base64url_is_unpadded_and_url_safe() -> None:
    for length in range(1, 40):
        text = crypto.b64url_encode(b"\xfb" * length)
        assert "=" not in text and "+" not in text and "/" not in text
        assert crypto.b64url_decode(text) == b"\xfb" * length


def test_base64url_decodes_a_padded_key_too() -> None:
    # A key that came back through a config file or a URL bar may have kept its
    # padding. Refusing a correct key over that is not a security property.
    raw = crypto.new_key()
    assert crypto.b64url_decode(crypto.b64url_encode(raw) + "==") == raw


def test_a_name_is_sealed_under_the_files_own_key() -> None:
    sealed = crypto.seal(b"contents")
    text = crypto.seal_name("oppsigelse-ansatt-4412.pdf", sealed.key)
    assert "oppsigelse" not in text
    assert crypto.open_name(text, sealed.key) == "oppsigelse-ansatt-4412.pdf"


def test_a_name_that_will_not_open_is_none_rather_than_an_error() -> None:
    """The file is the product; the name is a label.

    Failing a 4 GB download because its label would not decrypt would be
    choosing the wrong one of the two to protect.
    """
    text = crypto.seal_name("rapport.pdf", crypto.new_key())
    assert crypto.open_name(text, crypto.new_key()) is None
    assert crypto.open_name("not base64url at all !!!", crypto.new_key()) is None
    assert crypto.open_name("", crypto.new_key()) is None


def test_a_name_with_non_ascii_survives() -> None:
    key = crypto.new_key()
    for name in ["årsrapport.pdf", "Bokslut 2024 — färdig.xlsx", "aftale_ø.docx"]:
        assert crypto.open_name(crypto.seal_name(name, key), key) == name
