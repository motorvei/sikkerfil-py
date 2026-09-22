"""
Link parsing — and the one rule it exists to keep.

THE KEY MUST NEVER END UP IN A REQUEST. It lives after ``#``, which a browser
never sends and a log never records. A parser that let the fragment through into
a path or a query string would undo the entire product, quietly, and it would
look like it was working.
"""

from __future__ import annotations

import pytest

from sikkerfil import build_link, parse_link
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
