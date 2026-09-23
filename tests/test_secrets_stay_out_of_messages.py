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
from sikkerfil.errors import ConfigurationError, SikkerfilError
from sikkerfil.links import base_url_for

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

    AND CASE-INSENSITIVELY, which the second version still got wrong. urlsplit's
    ``hostname`` lowercases, so when a key reached a message through the authority
    this could not see it: the runs were there, in the wrong case. A lowercased key
    is not a redacted key — it gives away everything but the capitalisation, and
    guessing that offline against a downloaded ciphertext is a couple of billion
    tries, not a wall. Anything that mangles a key on the way into a message still
    counts as leaking it.
    """
    haystack = message.lower()
    return any(
        SECRET[i : i + RUN].lower() in haystack for i in range(len(SECRET) - RUN + 1)
    )


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
        # THE CANONICAL SHARE PATH. The shape every recipient sees, and the one my
        # sweep did not have: /s/ takes its own branch, which echoed the candidate.
        ("parse_link: the key under /s/", lambda: parse_link(f"https://sikkerfil.no/s/{SECRET}")),
        # THE KEY AS THE WHOLE ADDRESS, so it lands in the authority. I had written
        # down that a hostname is never a secret. It is when it is a key.
        ("parse_link: the key as the host", lambda: parse_link(f"https://{SECRET}/A/B")),
        ("parse_link: the key as a scheme", lambda: parse_link(f"{SECRET}://x/y")),
        ("base_url_for: the key as a market", lambda: base_url_for(SECRET)),
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


# --- Not a message at all: the repr of an object the caller holds --------------
#
# Everything above is about text the library WRITES. This is about a default it
# inherits. Found by asking what else puts a key somewhere nobody chose to put
# it, after three rounds of review in which I fixed the case I was shown and not
# the class.


def test_a_sent_share_does_not_print_its_own_key_or_token() -> None:
    from sikkerfil.models import SentShare

    sent = SentShare(
        id="ABCD1234",
        url=f"https://sikkerfil.dk/s/ABCD1234#k={SECRET}",
        write_token="wt_" + "z" * 20,
        key=SECRET,
        expires_at=1700000000,
        size_bytes=99,
    )
    text = repr(sent)
    assert not _leaks(text), text
    assert "wt_zzz" not in text, "the write token is issued once and is a credential"
    # Still useful, or the next person goes back to printing the whole object.
    assert "ABCD1234" in text
    assert "https://sikkerfil.dk" in text


def test_a_named_share_does_not_print_its_key_either() -> None:
    """The case my own first version of that repr got wrong.

    It took everything before "/s/" as the origin, and str.partition returns the
    WHOLE string when the separator is absent — so a named link, which has no
    "/s/", came back complete with its fragment. Fixing the shape I had in front
    of me and not the question is the mistake this whole file exists to catch.
    """
    from sikkerfil.models import SentShare

    sent = SentShare(
        id="ABCD1234",
        url=f"https://sikkerfil.no/kvartalsrapport#k={SECRET}",
        write_token="wt_x",
        key=SECRET,
        expires_at=0,
        size_bytes=1,
        name="kvartalsrapport",
    )
    assert not _leaks(repr(sent)), repr(sent)


def test_a_sealed_envelope_does_not_print_its_key() -> None:
    sealed = crypto.seal(b"kvartalsrapport")
    text = repr(sealed)
    assert repr(sealed.key) not in text, text
    assert str(sealed.key) not in text, text
    assert "<hidden>" in text


def test_a_received_file_does_not_print_the_file() -> None:
    # The plaintext is the thing being protected. A repr that dumps it is the
    # same failure as one that dumps the key.
    from sikkerfil.models import ReceivedFile, Share

    share = Share(
        id="ABCD1234",
        state="ready",
        size_bytes=1,
        content_type="application/pdf",
        expires_at=0,
        downloads_remaining=None,
        password_required=False,
    )
    got = ReceivedFile(
        data=b"Omsetning: 4 200 000 NOK", filename="r.pdf", content_type="x", share=share
    )
    assert b"Omsetning".decode() not in repr(got), repr(got)
    assert "24 bytes" in repr(got)


def test_the_ordinary_logging_line_does_not_write_the_key() -> None:
    """THE PATH THAT MATTERS, end to end. Nobody reprs an object on purpose.

        logger.info("sent %s", sent)

    is an unremarkable line to write, and with the default dataclass repr it put
    the decryption key and the once-issued write token into whatever the
    application logs to.
    """
    import io
    import logging

    from sikkerfil.models import SentShare

    stream = io.StringIO()
    logging.basicConfig(stream=stream, level=logging.INFO, force=True)
    sent = SentShare(
        id="ABCD1234",
        url=f"https://sikkerfil.no/s/ABCD1234#k={SECRET}",
        write_token="wt_" + "z" * 20,
        key=SECRET,
        expires_at=0,
        size_bytes=1,
    )
    logging.getLogger("an.application").info("sent %s", sent)
    written = stream.getvalue()

    assert "sent SentShare" in written, "the log line did not happen — the test proves nothing"
    assert not _leaks(written), written
    assert "wt_zzz" not in written, written


#: A key whose base64url spelling contains NO uppercase at all. Constructed rather
#: than searched for — about one in ten billion random keys is like this — because
#: the point it makes is not statistical. ``urlsplit().hostname`` lowercases, and I
#: had treated that as making a host safe to print. For this key it changes nothing
#: at all, and for any other it still hands over everything but the capitalisation.
LOWERCASE_KEY = crypto.key_text("abcdefghijklmnopqrstuvwxyz0123456789-_abcde")


def test_the_constructed_lowercase_key_is_really_a_key() -> None:
    # Otherwise the test below proves nothing: a 43-character string that is not a
    # valid key would be refused for its length and never reach the host logic.
    assert LOWERCASE_KEY.lower() == LOWERCASE_KEY
    assert len(crypto.b64url_decode(LOWERCASE_KEY)) == crypto.KEY_BYTES


@pytest.mark.parametrize(
    "shape",
    [
        "https://{key}/A/B",  # the key IS the authority
        "https://sikkerfil.no/s/{key}",  # the canonical share path
        "https://sikkerfil.no/{key}",  # a named link's slot
        "https://sikkerfil.no?k={key}",  # '?' where '#' belongs
        "{key}",  # no scheme at all
    ],
)
def test_a_lowercase_key_is_not_echoed_from_any_slot(shape: str) -> None:
    """Lowercasing is not redaction, which is the correction this encodes.

    Every slot, with a key that survives being lowercased intact. If any of these
    regress, the message hands over a working key rather than a mangled one.
    """
    with pytest.raises(SikkerfilError) as caught:
        parse_link(shape.format(key=LOWERCASE_KEY))
    message = str(caught.value)
    assert LOWERCASE_KEY not in message, message
    assert not any(
        LOWERCASE_KEY[i : i + RUN] in message for i in range(len(LOWERCASE_KEY) - RUN + 1)
    ), message


# --- The three fixes that reverting proved had no test ------------------------
#
# Reverting each fix and counting failures is how these were found: four of seven
# broke NOTHING when undone. The sweep caught two once it began reading what a
# successful call returns; these three are shapes it does not construct.


def test_a_parsed_link_does_not_print_its_key() -> None:
    """The object `parse_link` HANDS BACK, from the module about not leaking keys.

    Masking SentShare, Sealed and ReceivedFile and not this one was an oversight
    rather than a distinction: `log.debug("parsed %s", parse_link(url))` is at
    least as ordinary as logging a send result.
    """
    parsed = parse_link(f"https://sikkerfil.no/s/ABCD1234#k={SECRET}")
    text = repr(parsed)
    assert not _leaks(text), text
    assert "ABCD1234" in text, "it stopped being useful"
    assert "<hidden>" in text, "it does not say a key is there"

    # A link with no key must not claim to have one.
    assert "None" in repr(parse_link("https://sikkerfil.no/s/ABCD1234"))


def test_an_accepted_link_does_not_carry_userinfo_into_its_origin() -> None:
    """THE ONE THAT WAS NOT JUST A MESSAGE.

    `ParsedLink.origin` was built from `netloc`, which keeps `user:password@` —
    and `_client_for` installs that origin as `base_url`, so the credential would
    have gone into every request URL and back out of any transport failure. The
    redaction path stopped using netloc; the OPERATIONAL path had not.
    """
    parsed = parse_link(f"https://user:{SECRET}@sikkerfil.no/s/ABCD1234#k={SECRET}")
    assert parsed.origin == "https://sikkerfil.no", parsed.origin
    assert not _leaks(parsed.origin)
    assert "user" not in parsed.origin

    # A port is not a credential and must survive, or a stub or self-hosted origin
    # silently stops working.
    assert parse_link("http://127.0.0.1:5000/s/ABCD1234").origin == "http://127.0.0.1:5000"


def test_a_decrypted_filename_does_not_reach_a_repr() -> None:
    """The name is encrypted for the same reason the bytes are.

    "oppsigelse-ansatt-4412.pdf" gives away the document without a byte of it,
    which is precisely why the service never learns it. Decrypting it locally and
    then printing it into the application's logs hands back what sealing it
    bought, so masking the bytes and not the name is no protection at all.
    """
    from sikkerfil.models import ReceivedFile, Share

    share = Share(
        id="ABCD1234",
        state="ready",
        size_bytes=1,
        content_type="application/pdf",
        expires_at=0,
        downloads_remaining=None,
        password_required=False,
    )
    got = ReceivedFile(
        data=b"Omsetning: 4 200 000 NOK",
        filename="oppsigelse-ansatt-4412.pdf",
        content_type="application/pdf",
        share=share,
    )
    text = repr(got)
    assert "oppsigelse" not in text, text
    assert "Omsetning" not in text, text
    assert "24 bytes" in text and "ABCD1234" in text, "it stopped being useful"


def test_a_refused_key_leaves_no_exception_to_walk() -> None:
    """Belt and braces, and the braces are what is asserted here.

    The VALUE no longer reaches these messages because b64url_decode stopped
    putting it in one. This asserts the other half: nothing is raised while an
    exception is being handled, so there is no `__context__` for a tracker to walk
    at all. Reverting the restructure alone breaks no test today — the value is
    masked either way — so without this the second layer could be removed and
    nobody would know until it mattered.
    """
    for bad in (SECRET[:-1] + "ø", SECRET[:-1] + chr(0x2019), "abc"):
        with pytest.raises(ConfigurationError) as caught:
            crypto.key_text(bad)
        assert caught.value.__context__ is None, repr(caught.value.__context__)
        assert caught.value.__cause__ is None

    with pytest.raises(ConfigurationError) as caught:
        parse_link(f"https://[oops/x#k={SECRET}")
    assert caught.value.__context__ is None, repr(caught.value.__context__)
