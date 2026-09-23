"""
THE KEY MUST NOT APPEAR IN AN ERROR MESSAGE.

``links.py`` says a log line carrying the fragment quietly undoes the product. An
exception message IS a log line: applications log what they did not catch, and
error trackers keep it for months. So the rule is not "do not log the key" — the
library cannot control what a caller logs — it is that the library never hands a
caller a message with the key in it.

THE CASES THAT MATTER ARE THE NEAR MISSES. A key that is obviously wrong is
usually not a key at all. A key that is one pasted character short, or has a
smart quote where a hyphen should be, or arrived in a link whose path we do not
recognise, IS the real key, and that is exactly when something raises.

This file feeds a real key through every failure it can reach and asserts the key
does not come back out. It found two leaks when it was written: one in
crypto.key_text, and one in parse_link that predates it.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from sikkerfil import Sikkerfil, build_link, crypto, inspect, parse_link, receive
from sikkerfil.errors import SikkerfilError

#: A real key, so a leak is unambiguous rather than a coincidental substring.
SECRET = crypto.b64url_encode(bytes(range(4, 36)))


#: A run this long is worth having: the rest of a 43-character key is a handful
#: of guesses away, and nothing legitimate quotes twelve characters of one.
RUN = 12


def _leaks(message: str) -> bool:
    """Any run of the key long enough to be worth having counts as a leak.

    EVERY OFFSET, not only the start. The first version of this checked prefixes
    — ``SECRET[:12]``, ``SECRET[:20]`` — and said in its own docstring that it
    checked runs. A message printing the key from its SECOND character discloses
    42 of 43, with one 64-way guess left, and that version could not see it. A
    security test that overstates what it checks is worse than one that does
    less and says so.
    """
    return any(SECRET[i : i + RUN] in message for i in range(len(SECRET) - RUN + 1))


def _broken_things_holding_a_real_key() -> list[tuple[str, Callable[[], object]]]:
    """Every way I can get the library to raise while it is holding a real key."""
    client = Sikkerfil(api_key="sikkerfil_sk_" + "x" * 43, retries=0)
    return [
        # A link whose path we do not recognise, which is a recipient pasting
        # something from a future version or with a typo in the middle.
        ("parse_link: unknown path", lambda: parse_link(f"https://sikkerfil.no/A/B/C#k={SECRET}")),
        ("parse_link: bad bare ref", lambda: parse_link(f"UPPER_CASE#k={SECRET}")),
        ("parse_link: not https", lambda: parse_link(f"ftp://sikkerfil.no/s/ABCD1234#k={SECRET}")),
        # THE KEY ON ITS OWN, with no fragment to strip. A sender who stored the
        # id and the key separately and passed the key where the id belongs gets
        # here — and the first version of this sweep did not include it, which is
        # exactly how the leak it was written to catch stayed in.
        ("parse_link: the bare key", lambda: parse_link(SECRET)),
        ("parse_link: the key as a path", lambda: parse_link(f"https://sikkerfil.no/{SECRET}")),
        # '?' WHERE '#' BELONGS. No slash before the query, so splitting the URL
        # on '/' took the key to be part of the host. urlsplit knows better.
        ("parse_link: ? instead of #", lambda: parse_link(f"https://sikkerfil.no?k={SECRET}")),
        ("parse_link: query and fragment", lambda: parse_link(f"https://sikkerfil.no/x?k={SECRET}#k={SECRET}")),
        ("parse_link: a bad IPv6 authority", lambda: parse_link(f"https://[oops/x#k={SECRET}")),
        ("parse_link: the key with a newline", lambda: parse_link(SECRET + "\n")),
        ("receive: the bare key", lambda: receive(SECRET)),
        # One character lost or mangled on the way through a mail client.
        ("key_text: a character short", lambda: crypto.key_text(SECRET[:-1])),
        ("key_text: a character extra", lambda: crypto.key_text(SECRET + "x")),
        # chr() rather than the character itself: a literal smart quote in a source
        # file is exactly the ambiguity that puts one in a pasted key.
        ("key_text: a smart quote in it", lambda: crypto.key_text(SECRET[:-1] + chr(0x2019))),
        ("key_text: non-ASCII", lambda: crypto.key_text(SECRET[:-1] + "ø")),
        # The same near misses through the public surface rather than the helper.
        ("build_link", lambda: build_link("https://sikkerfil.no", "ABCD1234", SECRET[:-1])),
        ("receive: bad key", lambda: receive(f"https://sikkerfil.no/s/ABCD1234#k={SECRET[:-1]}")),
        (
            "receive: two keys",
            lambda: client.receive(f"https://sikkerfil.no/s/ABCD1234#k={SECRET}", key=SECRET[:-1]),
        ),
        ("inspect: unknown path", lambda: inspect(f"https://sikkerfil.no/A/B/C#k={SECRET}")),
    ]


@pytest.mark.parametrize("label,call", _broken_things_holding_a_real_key(), ids=lambda v: v)
def test_no_failure_hands_the_key_back_in_its_message(
    label: str, call: Callable[[], object]
) -> None:
    with pytest.raises(SikkerfilError) as caught:
        call()
    message = str(caught.value)
    assert not _leaks(message), f"{label} put the key in its message:\n  {message}"

    # The whole exception chain, not just the message we wrote: a __cause__ or a
    # note carries into the same log.
    chain = []
    exc: BaseException | None = caught.value
    while exc is not None:
        chain.append(str(exc))
        exc = exc.__cause__ or exc.__context__
    assert not _leaks("\n".join(chain)), f"{label} leaked the key through its cause chain"


def test_the_guard_can_actually_see_a_leak() -> None:
    # A test that cannot fail is decoration. These are the shapes the real leaks
    # produced, so a future 'helpful' f-string is caught.
    assert _leaks(f"{SECRET!r} is not a share link")
    assert _leaks(f"the key {SECRET[:-1]} will not decode")

    # AND AT EVERY OFFSET. These three are what the prefix-only version missed.
    assert _leaks("leaked " + SECRET[1:]), "a suffix leak is still a leak"
    assert _leaks("leaked " + SECRET[5:35]), "a middle slice is still a leak"
    assert _leaks(SECRET[-RUN:]), "the last run of the key is still a leak"

    # And it must not fire on the redacted forms, or it would be useless noise.
    assert not _leaks("https://sikkerfil.no/<unrecognised> does not look like a share link")
    assert not _leaks("a 43-character value that is not repeated here, in case it is a key")


def test_the_redaction_does_not_echo_userinfo_either() -> None:
    """A password in the authority is a credential in an error message.

    Not one Codex named — found by asking what ELSE a URL can carry that we would
    not want in a log, once splitting on '/' turned out to be the wrong tool.
    netloc keeps ``user:password@``; hostname does not, which is why redaction
    uses the parsed hostname rather than the raw authority.
    """
    from sikkerfil.links import redacted

    out = redacted(f"https://user:hunter2@sikkerfil.no/Deep/Path#k={SECRET}")
    assert "hunter2" not in out, out
    assert "user" not in out, out
    assert out == "https://sikkerfil.no/<unrecognised>"


def test_the_redaction_keeps_what_a_caller_needs() -> None:
    # Safe is not enough — if it redacted everything it would be useless, and the
    # next person would go back to printing the link. The market a caller aimed at
    # is the useful part, and a port matters for a stub or a self-hosted origin.
    from sikkerfil.links import redacted

    assert redacted(f"https://sikkerfil.dk/A/B#k={SECRET}") == "https://sikkerfil.dk/<unrecognised>"
    assert redacted("http://127.0.0.1:54321/A/B") == "http://127.0.0.1:54321/<unrecognised>"
