"""
Link parsing — and the one rule it exists to keep.

THE KEY MUST NEVER END UP IN A REQUEST. It lives after ``#``, which a browser
never sends and a log never records. A parser that let the fragment through into
a path or a query string would undo the entire product, quietly, and it would
look like it was working.
"""

from __future__ import annotations

import pytest

from sikkerfil import build_link, crypto, parse_link
from sikkerfil.errors import ConfigurationError

KEY = "KDYNXg9NDnXp7tQnjkL4LI_ppByM-QcOIHsUKfuN3u4"


def test_a_share_link_comes_apart_into_origin_id_and_key() -> None:
    parsed = parse_link(f"https://sikkerfil.no/s/ABCD1234#k={KEY}")
    assert parsed.origin == "https://sikkerfil.no"
    assert parsed.share_id == "ABCD1234"
    assert parsed.name is None
    assert parsed.key == KEY


def test_a_named_link_is_a_name_until_it_is_resolved() -> None:
    parsed = parse_link(f"https://sikkerfil.no/kvartalsrapport#k={KEY}")
    assert parsed.name == "kvartalsrapport"
    assert parsed.share_id is None
    assert parsed.reference == "kvartalsrapport"


def test_every_market_parses() -> None:
    for host in ("sikkerfil.no", "sakerfil.se", "sikkerfil.dk"):
        parsed = parse_link(f"https://{host}/s/ABCD1234#k={KEY}")
        assert parsed.origin == f"https://{host}"


def test_a_bare_id_and_a_bare_name_are_accepted() -> None:
    # What somebody types when they read the id off a screen.
    assert parse_link("ABCD1234").share_id == "ABCD1234"
    assert parse_link("kvartalsrapport").name == "kvartalsrapport"
    assert parse_link(f"ABCD1234#k={KEY}").key == KEY


def test_a_mangled_fragment_still_yields_the_key() -> None:
    # Mail clients and chat apps rewrite links. Telling a recipient their
    # perfectly good key is not a link would be our failure, not theirs.
    assert parse_link(f"https://sikkerfil.no/s/ABCD1234#{KEY}").key == KEY
    assert parse_link(f"https://sikkerfil.no/s/ABCD1234#k={KEY}&x=1").key == KEY


def test_a_link_with_no_fragment_has_no_key() -> None:
    assert parse_link("https://sikkerfil.no/s/ABCD1234").key is None


def test_the_key_is_not_left_anywhere_the_path_can_reach() -> None:
    """The property, asserted directly.

    ``reference`` is what gets interpolated into a request path. If the key ever
    appeared in it, every download would post the decryption key to the service
    — and the tests would still pass, because the download would work.
    """
    parsed = parse_link(f"https://sikkerfil.no/s/ABCD1234#k={KEY}")
    assert KEY not in parsed.reference
    assert KEY not in (parsed.share_id or "")
    assert KEY not in parsed.origin


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "ftp://sikkerfil.no/s/ABCD1234",
        "https://sikkerfil.no/s/lowercase",          # ids are uppercase
        "https://sikkerfil.no/s/AB",                 # too short
        "https://sikkerfil.no/Some/Deep/Path",
        "https://sikkerfil.no/UPPER-NAME",           # names are lowercase
        "not a link at all",
    ],
)
def test_rubbish_is_refused_rather_than_guessed_at(bad: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_link(bad)


def test_building_a_link_round_trips() -> None:
    link = build_link("https://sakerfil.se", "ABCD1234", KEY)
    assert link == f"https://sakerfil.se/s/ABCD1234#k={KEY}"
    assert parse_link(link).share_id == "ABCD1234"

    named = build_link("https://sikkerfil.no/", "kvartalsrapport", KEY)
    assert named == f"https://sikkerfil.no/kvartalsrapport#k={KEY}"
    assert parse_link(named).name == "kvartalsrapport"


def test_the_link_is_built_from_the_senders_own_market() -> None:
    # A Danish customer's recipients must not be sent to a domain they have
    # never heard of. The origin in, the origin out.
    assert build_link("https://sikkerfil.dk", "ABCD1234", KEY).startswith("https://sikkerfil.dk/")


def test_a_link_built_from_the_raw_key_bytes_is_still_a_working_link() -> None:
    # FOUND BY USING THE LIBRARY, not by reading it. new_key() and Sealed.key are
    # bytes; build_link's key is the base64url text. Hand it the bytes you have —
    # the obvious mistake, because it is the only key value in scope — and the old
    # version interpolated their repr:
    #
    #     https://sikkerfil.dk/s/ABCD1234#k=b'\x9c\x1f...
    #
    # Right shape, right length, opens for nobody. Nothing on the sending side
    # could tell; the recipient found out instead.
    raw = crypto.b64url_decode(KEY)
    assert build_link("https://sikkerfil.no", "ABCD1234", raw) == (
        f"https://sikkerfil.no/s/ABCD1234#k={KEY}"
    )
    assert parse_link(build_link("https://sikkerfil.no", "ABCD1234", raw)).key == KEY


def test_padding_from_a_config_file_does_not_reach_the_fragment() -> None:
    # '=' in a fragment is legal and gets helpfully escaped by things that rewrite
    # links, which is why the browser writes unpadded. A key read back out of a
    # file or a shell variable may have kept its padding.
    assert build_link("https://sakerfil.se", "ABCD1234", KEY + "=") == (
        f"https://sakerfil.se/s/ABCD1234#k={KEY}"
    )


@pytest.mark.parametrize(
    "not_a_key",
    [
        "",  # nothing at all
        "abc",  # decodes, but to two bytes
        "æøå",  # not even ASCII
        KEY[:-4],  # a key with the end lost in a mail client
        b"\x00" * 16,  # half a key, as bytes
        KEY.encode("ascii"),  # the TEXT as bytes: 43 bytes, not 32
    ],
)
def test_a_key_that_cannot_open_anything_is_refused_rather_than_published(
    not_a_key: str | bytes,
) -> None:
    # A link is handed to someone else. By the time it fails it is in their inbox
    # and the file is already uploaded, so the cheap place to fail is here.
    with pytest.raises(ConfigurationError):
        build_link("https://sikkerfil.no", "ABCD1234", not_a_key)


def test_any_bytes_like_spelling_of_the_key_normalises() -> None:
    # key_text does the widening for the whole library, so it takes bytes-like
    # rather than only bytes. The public callers advertise str | bytes, which are
    # the two spellings anybody actually holds.
    raw = crypto.b64url_decode(KEY)
    assert crypto.key_text(bytearray(raw)) == KEY
    assert crypto.key_text(memoryview(raw)) == KEY


@pytest.mark.parametrize(
    "spelling",
    [
        KEY + "\n",  # pasted from a terminal, or read with readline()
        KEY + "\r\n",  # the same, from a file written on Windows
        KEY + " ",
        "  " + KEY + "  ",
        "\t" + KEY + "\n",
        KEY + "=\n",  # padded AND newlined, from a config file
    ],
)
def test_whitespace_around_a_key_does_not_break_it(spelling: str) -> None:
    """THE MECHANISM IS MODULO FOUR, which is why this is parametrised.

    base64 decoding DISCARDS whitespace but COUNTS it when checking padding. So
    whether a stray character broke a key depended on how many of them there
    were: one newline made 44 characters, padding was calculated as if none were
    needed, and the 43 real characters were then rejected as badly padded —
    while two spaces either side made 47, one '=' was added, and it sailed
    through. A key surviving a copy-paste must not be a coin flip.
    """
    assert crypto.key_text(spelling) == KEY


def test_a_key_with_a_newline_still_builds_a_clean_link() -> None:
    # The regression that prompted the test above was reachable through the
    # public API, not just the helper: receive() used to .strip() and stopped.
    assert build_link("https://sikkerfil.no", "ABCD1234", KEY + "\n") == (
        f"https://sikkerfil.no/s/ABCD1234#k={KEY}"
    )
