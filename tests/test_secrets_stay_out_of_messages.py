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

import contextlib
import io
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

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


def test_a_credential_with_a_newline_in_it_never_reaches_http_client() -> None:
    """ASCII was not enough, and the stdlib's own validation is not safe to reach.

    CR and LF are ASCII, so a credential wrapped across two lines in a config file
    passed the first version of this guard — and then http.client raised
    ValueError("Invalid header value b'<the whole credential>'"), which is neither
    one of our errors nor redacted. A control character in a header is also how
    header injection is spelled, so there was never a reason to allow one.
    """
    from sikkerfil import Sikkerfil

    client = Sikkerfil(api_key="sikkerfil_sk_" + "x" * 43, retries=0, base_url="http://127.0.0.1:9")
    for bad in (f"wt_{SECRET}\r\nX: y", f"wt_{SECRET}\n", f"wt_{SECRET}\x7f", f"wt_{SECRET}\x00"):
        # REFUSED BY THE SHAPE NOW, not by the control character — a write token is
        # wt_ and exactly 43 characters, and a wrapped one is longer than that. Which
        # guard catches it is not the property under test: that it never reaches
        # http.client, and that none of it comes back in the message, is.
        with pytest.raises(ConfigurationError, match="not shaped like a credential"):
            client.revoke("ABCD1234", write_token=bad)
        try:
            client.revoke("ABCD1234", write_token=bad)
        except ConfigurationError as exc:
            assert not _leaks(str(exc)), str(exc)
            assert exc.__context__ is None

    # AND THE CONTROL-CHARACTER CHECK IS STILL LOAD-BEARING, on the header a caller
    # can put anything into: content-type on the upload PUT. The credential headers
    # are now shape-checked first, so testing only those would have left this guard
    # covered by nothing while still looking covered.
    # Straight at put_bytes, because send() has to create the share first and there
    # is nothing listening on port 9 — the refusal under test happens before any
    # socket, and going through send() would prove only that the port is closed.
    from sikkerfil.transport import Transport

    upload = Transport("http://127.0.0.1:9", retries=0)
    for bad_type in ("text/plain\r\nX: y", "text/plain\n", "text/plain\x00", "tekst/plæin"):
        with pytest.raises(ConfigurationError, match="cannot be sent"):
            upload.put_bytes("http://127.0.0.1:9/upload", b"x", content_type=bad_type)


def test_saving_under_a_key_shaped_name_is_refused_before_it_touches_the_disk() -> None:
    """Worse than a message: this one would CREATE a file named after the key.

    In directory listings, in backups, in whatever indexes that folder. Both the
    directory and the explicit filename are caller values, and both reach a path.
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
        data=b"x", filename="rapport.pdf", content_type="application/pdf", share=share
    )

    for kwargs in ({"directory": SECRET}, {"directory": ".", "filename": SECRET}):
        with pytest.raises(ConfigurationError) as caught:
            got.save(**kwargs)
        assert not _leaks(str(caught.value)), str(caught.value)


def test_an_ordinary_save_still_works(tmp_path: object) -> None:
    # The guards above must not cost the normal case, which is the whole point of
    # using the path threshold rather than the value one.
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
    got = ReceivedFile(data=b"hei", filename="rapport.pdf", content_type="x", share=share)
    written = got.save(str(tmp_path))
    assert written.endswith("rapport.pdf")
    assert got.save(str(tmp_path), filename="kvartalsrapport-2026-q3.pdf").endswith(".pdf")


# --- Round nine: the decoder's permissiveness was the root of the whole class ----


@pytest.mark.parametrize(
    "separator",
    [".", ",", "/", "+", ":", "*", "%", "\x00"],
)
def test_a_key_smuggled_past_the_run_check_by_punctuation_is_refused(separator: str) -> None:
    """THE ROOT CAUSE, and the reason chasing spellings was the wrong strategy.

    urlsafe_b64decode DISCARDS every character outside the alphabet, not only the
    whitespace this library strips on purpose. So a key with dots sprinkled through
    it decoded to the key while containing no twelve-character run — and the leak
    check, which reads runs, echoed the whole thing. Deleting the dots gave it back.

    I had been answering each of these by teaching the CHECK another transformation:
    whitespace, then NFKC. That is an open-ended list and I would have kept losing
    it. Strict decoding closes the set instead — base64url plus the whitespace we
    remove, and nothing else — so there is no third spelling to discover.
    """
    spelled = separator.join(SECRET[i : i + 11] for i in range(0, len(SECRET), 11))
    with pytest.raises((ConfigurationError, ValueError)):
        crypto.key_text(spelled)


def test_whitespace_and_padding_are_still_tolerated() -> None:
    # Strictness must not cost the leniency that was deliberate. A key wrapped by a
    # mail client or padded by a config file is a correct key.
    for spelling in (
        SECRET,
        SECRET + "=",
        SECRET + "==",
        " ".join(SECRET),
        SECRET[:20] + "\n" + SECRET[20:],
        "\t" + SECRET + "\n",
        SECRET + "==\n",
    ):
        assert crypto.key_text(spelling) == SECRET, spelling[:24]


@pytest.mark.parametrize(
    "link",
    ["https:///s/ABCD1234", "http://localhost:bad/s/ABCD1234", "https://:8080/s/ABCD1234"],
)
def test_an_absolute_link_with_no_usable_origin_is_refused(link: str) -> None:
    """Otherwise a typo in a self-hosted link silently goes to production.

    These parsed: the share path was fine and the origin came back EMPTY — which is
    indistinguishable from "they typed just the id", so _client_for fell back to the
    default market. The lookup for a staging share went to the live service.
    """
    with pytest.raises(ConfigurationError):
        parse_link(link)

    # A bare reference still works, because that ambiguity was the whole problem.
    assert parse_link("ABCD1234").share_id == "ABCD1234"


def test_build_link_refuses_an_origin_that_could_carry_a_key() -> None:
    """The other half of everything before the '#'.

    I fixed `reference` last round and left `origin`. A key as the origin puts it in
    the link; "https://<key>.example" is worse, because it looks valid and sends the
    key through DNS and the request authority on the first click.
    """
    for origin in (SECRET, f"https://{SECRET}.example", "not-an-origin", ""):
        with pytest.raises(ConfigurationError):
            build_link(origin, "ABCD1234", SECRET)


@pytest.mark.parametrize(
    "origin",
    [
        "https://sikkerfil.no",
        "https://sikkerfil.no/",
        "http://127.0.0.1:5000",
        "http://[::1]:5000",
    ],
)
def test_build_link_still_accepts_every_real_origin(origin: str) -> None:
    assert build_link(origin, "ABCD1234", SECRET).endswith(SECRET)


def test_a_sender_cannot_make_the_recipient_write_a_file_named_after_the_key() -> None:
    """The guard tested the ARGUMENT and not the value it defaults to.

    self.filename is the DECRYPTED name, which save()'s own docstring already calls
    attacker-controlled. So a sender could send(data, filename=<a key>) and the
    recipient's perfectly ordinary save(dir) wrote a file named after it — no mistake
    required at the receiving end at all. Guarding the caller's argument protected
    them from themselves and not from the sender, which is the wrong threat.
    """
    import tempfile

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
    hostile = ReceivedFile(data=b"x", filename=SECRET, content_type="x", share=share)
    directory = tempfile.mkdtemp()

    with pytest.raises(ConfigurationError) as caught:
        hostile.save(directory)
    assert not _leaks(str(caught.value)), str(caught.value)

    # The recipient is not stuck: they can name it themselves.
    assert hostile.save(directory, filename="rapport.pdf").endswith("rapport.pdf")


# --- Round eleven: two of these say an earlier fix of mine was wrong -------------


@pytest.mark.parametrize("alias", ["/", "+"])
def test_standard_base64_aliases_are_not_accepted_as_base64url(alias: str) -> None:
    """"Strict" was not the same as "only base64url".

    b64decode(..., altchars=b"-_", validate=True) accepts the URL-safe pair AND
    standard base64's "+/" — so ("A"*10 + "/")*3 + "A"*10 is 43 characters, decodes
    to 32 bytes, and carries no run the leak check can see. The alphabet is checked
    here now rather than delegated, which is the second time on this branch I have
    believed a closed set was closed.
    """
    spelled = (("A" * 10 + alias) * 3) + "A" * 10
    assert len(spelled) == 43
    with pytest.raises((ConfigurationError, ValueError)):
        crypto.key_text(spelled)


def test_a_decryption_key_is_never_sent_as_a_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE WORST MIX-UP THE LIBRARY CAN BE HANDED.

    Every other disclosure on this branch went into a log the operator already had.
    This one sent the key TO THE SERVICE, in x-sikkerfil-token, beside the share id
    it opens — handing over the one secret the design exists to withhold. No
    downstream redaction helps, because the request itself is the disclosure.
    """
    import urllib.error
    import urllib.request

    from sikkerfil import Sikkerfil

    sent: dict[str, str] = {}

    def spy(request: Any, *args: Any, **kwargs: Any) -> Any:
        sent.update(dict(request.header_items()))
        raise urllib.error.URLError("the test does not use the network")

    monkeypatch.setattr(urllib.request, "urlopen", spy)

    client = Sikkerfil(
        api_key="sikkerfil_sk_" + "x" * 43, retries=0, base_url="http://127.0.0.1:9"
    )
    # THE KEY IS THE WHOLE KEY HERE, not a near miss, and it used to be undecidable:
    # a write token was 43 characters of base64url and so is a key, so no test of the
    # value could separate them. The service mints wt_ in front of a token now
    # (sikkerfil#62), which is what makes this refusal possible at all.
    with pytest.raises(ConfigurationError, match=r"(?i)decryption key"):
        client.revoke("ABCD1234", write_token=SECRET)
    assert not any(_leaks(value) for value in sent.values()), sent

    with pytest.raises(ConfigurationError, match=r"(?i)decryption key"):
        Sikkerfil(api_key=SECRET, retries=0, base_url="http://127.0.0.1:9").shares()
    assert not any(_leaks(value) for value in sent.values()), sent

    # A NEAR MISS IS STILL A DISCLOSURE. A key one character short decodes to 31
    # bytes — it is not "a key" to anything that decodes it, and it carries 252 of
    # the key's 256 bits to the service with sixteen completions left to try.
    for near in (SECRET[:-1], SECRET + "=", SECRET[:21] + "\n" + SECRET[21:], SECRET.upper()):
        sent.clear()
        with pytest.raises(ConfigurationError):
            client.revoke("ABCD1234", write_token=near)
        assert not sent, sent

    # A real token still goes, or the guard has broken the feature it protects.
    sent.clear()
    with contextlib.suppress(Exception):
        client.revoke("ABCD1234", write_token="wt_" + "y" * 43)
    assert any(value.startswith("wt_") for value in sent.values()), sent


@pytest.mark.parametrize(
    "host",
    [
        "abcdefghijkl.example",
        "my-company-files.example.com",
        "sikkerfil-staging-eu-north.example",
        "aVeryLongSubdomainLabel.example.com",
    ],
)
def test_an_ordinary_long_hostname_is_still_usable(host: str) -> None:
    """A CORRECTION TO MY OWN FIX, and the most damaging thing in this round.

    Running the 12-character VALUE heuristic over a whole hostname rejected ordinary
    names — "my-company-files.example.com" among them — so every self-hosted origin
    stopped working, in parse_link AND build_link, while looking like a security
    improvement. A label is a path component in all but name and gets the path
    threshold. Breaking supported deployments outright is worse than the leak the
    check was added for.
    """
    from sikkerfil.links import origin_of

    # Lowercased, because hostnames are case-insensitive and urlsplit normalises them.
    # The mixed-case entry is here for that reason: the first version of this test
    # compared against the input and failed on correct behaviour.
    expected = f"https://{host.lower()}"
    assert origin_of(f"https://{host}/s/ABCD1234") == expected
    assert parse_link(f"https://{host}/s/ABCD1234").origin == expected
    assert build_link(f"https://{host}", "ABCD1234", SECRET).startswith(expected + "/")


def test_a_key_split_across_labels_or_path_components_is_still_a_key() -> None:
    """NO SINGLE PIECE IS LONG ENOUGH TO LOOK WRONG, and the whole is still a key.

    ``<key[:21]>.<key[21:]>`` is two labels of twenty-one and twenty-two characters,
    each under the 32-character threshold a path component gets and each perfectly
    ordinary to look at — and DNS hands the resolver all forty-three of them. The
    same trick works down a path, where ``/a/<half>/<half>`` reads as two harmless
    directories.

    So every CONTIGUOUS RUN of components is joined and tested for being exactly a
    key, which is a test a fixed-size secret allows and a heuristic would not: joining
    the labels of ``my-company-files.example.com`` gives twenty-six base64url
    characters, and exactness is what keeps that ordinary name working.

    THIS TEST IS HERE BECAUSE DELETING THAT LOOP BROKE NOTHING. The behaviour was
    checked by hand in a shell, and I recorded it as verified — a fix nothing holds
    on to is a fix that leaves with the next refactor.
    """
    from sikkerfil.links import origin_of, path_carries_key_material, redacted_path

    for cut in (21, 12, 30):
        halves = (SECRET[:cut], SECRET[cut:])
        assert origin_of(f"https://{halves[0]}.{halves[1]}/x") == "", cut
        assert path_carries_key_material(f"/a/{halves[0]}/{halves[1]}"), cut
        redacted = redacted_path(f"/a/{halves[0]}/{halves[1]}")
        assert not _leaks(redacted), redacted
        # Three pieces, and the join has to span all three.
        thirds = f"/{SECRET[:14]}/{SECRET[14:28]}/{SECRET[28:]}"
        assert path_carries_key_material(thirds)
        assert not _leaks(redacted_path(thirds))

    # And the ordinary name the exactness protects is untouched.
    assert origin_of("https://my-company-files.example.com/x") == (
        "https://my-company-files.example.com"
    )
    assert not path_carries_key_material("/home/me/Documents/kvartalsrapport-2026-q3.pdf")


def test_a_key_hidden_in_a_host_by_percent_encoding_or_a_scheme_is_refused() -> None:
    """urllib decodes a host before resolving it, and a key is a valid URI scheme.

    Percent-encoding every eleventh character hid the key from a check reading raw
    text while DNS would still have seen all of it. And "a"*42 + "g" is both a
    32-byte key and a syntactically valid scheme, so it reached the front of a link.
    """
    from sikkerfil.links import origin_of

    lowercase = crypto.key_text("abcdefghijklmnopqrstuvwxyz0123456789-_abcde")
    encoded = "".join(
        f"%{ord(c):02X}" if i % 11 == 10 else c for i, c in enumerate(lowercase)
    )
    assert origin_of(f"https://{encoded}/x") == ""

    scheme_shaped = "a" * 42 + "g"
    assert len(crypto.b64url_decode(scheme_shaped)) == crypto.KEY_BYTES
    assert origin_of(f"{scheme_shaped}://example.com/x") == ""
    with pytest.raises(ConfigurationError):
        build_link(f"{scheme_shaped}://example.com", "ABCD1234", SECRET)


def test_a_key_as_base_url_is_refused_at_construction() -> None:
    """A constructor parameter is a caller value; it just took longer to notice.

    Sikkerfil(base_url=<key>).health() reached urllib, which says what it was given:
    ValueError("unknown url type: '<the whole key>/api/v1/health'") — in the message
    and in args, and not one of our errors either.
    """
    from sikkerfil import Sikkerfil

    for bad in (SECRET, f"https://{SECRET}", "nonsense"):
        with pytest.raises(ConfigurationError) as caught:
            Sikkerfil(api_key="sikkerfil_sk_" + "x" * 43, base_url=bad, retries=0)
        assert not _leaks(str(caught.value)), str(caught.value)

    # EVERY PART OF THE STRING THAT IS KEPT, not just the part origin_of reads. The
    # verdict comes from origin_of and the caller's own string is what gets used — so
    # the components origin_of drops were validated by nothing, and a key in the path
    # went into every request. Query, fragment and userinfo are refused outright:
    # none of them belongs in a base URL, and each is another place to hide a secret.
    #
    # THIS WAS HELD BY NO TEST until it was written down here. I checked it in a shell,
    # saw the right answers and recorded it as verified; deleting the checks broke
    # nothing at all.
    for retained in (
        f"https://host.example/{SECRET}",
        f"https://host.example/a/{SECRET[:21]}/{SECRET[21:]}",
        f"https://host.example/?k={SECRET}",
        f"https://host.example/#k={SECRET}",
        f"https://user:{SECRET}@host.example",
    ):
        with pytest.raises(ConfigurationError) as caught:
            Sikkerfil(api_key="sikkerfil_sk_" + "x" * 43, base_url=retained, retries=0)
        assert not _leaks(str(caught.value)), str(caught.value)

    # A DELIMITER WITH NOTHING AFTER IT IS STILL A DELIMITER. "https://host?" parses
    # with an empty query, so a truthiness test accepted it — and the caller's string
    # is what gets kept, so the next request asked for "https://host?/api/v1/health"
    # and the API path became a query aimed at the host root.
    for delimiter in (
        "https://host.example?",
        "https://host.example#",
        "https://host.example?#",
    ):
        with pytest.raises(ConfigurationError):
            Sikkerfil(api_key="sikkerfil_sk_" + "x" * 43, base_url=delimiter, retries=0)

    # A KEY PERCENT-ENCODED INTO THE PATH, which breaks every run while urllib hands
    # the server all 43 characters back. The same bypass as the hostname one, in the
    # component the hostname fix did not cover.
    lowercase = crypto.key_text("a" * 42 + "g")
    encoded = "".join(f"%{ord(c):02X}" if i % 11 == 10 else c for i, c in enumerate(lowercase))
    with pytest.raises(ConfigurationError):
        Sikkerfil(
            api_key="sikkerfil_sk_" + "x" * 43,
            base_url=f"https://host.example/{encoded}",
            retries=0,
        )

    # AND A PATH PREFIX IS REFUSED, which is a feature I added last round and have
    # now taken back out. It was accepted for reverse-proxy deployments and produced
    # a base URL that cannot work: send() hands base_url to build_link, origin_of
    # drops the path, and the recipient gets https://host.example/s/<id> — the wrong
    # route — while parse_link cannot read a prefixed link at all, so receive() would
    # refuse this library's own output. Supporting a prefix means teaching build_link
    # and parse_link about it, which is a feature rather than a fix.
    with pytest.raises(ConfigurationError):
        Sikkerfil(
            api_key="sikkerfil_sk_" + "x" * 43,
            base_url="https://host.example/sikkerfil",
            retries=0,
        )

    # An IPv6 literal and a bare origin still work, which a previous version of this
    # area broke twice.
    for good in (
        "http://[::1]:5000",
        "https://my-company-files.example.com",
        "https://host.example/",
    ):
        client = Sikkerfil(api_key="sikkerfil_sk_" + "x" * 43, base_url=good, retries=0)
        assert client.base_url == good.rstrip("/")


# --- Round thirteen: the separator, the alphabet, and the case of a header ----


def test_a_decorated_key_split_across_components_is_caught() -> None:
    """FOUR CHARACTERS DEFEATED THE PREVIOUS FIX.

    Testing whether the join of two components was EXACTLY a key read as precise:
    ``<key[:21]>.<key[21:]>-old`` joins to 47 characters that are not a key and
    contain one, so the host was accepted and DNS got every character. Every
    key-sized window of the join is tested now.
    """
    from sikkerfil.links import origin_of, path_carries_key_material, redacted_path

    lowercase = crypto.key_text("a" * 42 + "g")
    for decoration in ("-old", "_v2", "2026"):
        host = f"{lowercase[:21]}.{lowercase[21:]}{decoration}"
        assert origin_of(f"https://{host}/x") == "", host
        path = f"/a/{lowercase[:21]}/{lowercase[21:]}{decoration}"
        assert path_carries_key_material(path), path
        assert not _leaks(redacted_path(path))

    # AND THE COMPONENT THAT COULD HOLD A WHOLE KEY ALONE DOES NOT IMPLICATE ITS
    # NEIGHBOURS. A window straddling a long directory name and a key-named file is
    # 43 characters of the alphabet like any other, so marking the whole run withheld
    # this suite's own tmp_path — the thing the message exists to show.
    keyed = f"/tmp/pytest-of-user/pytest-180/test_a_key_shaped_filename_is_0/{SECRET}"
    assert redacted_path(keyed).startswith("/tmp/pytest-of-user/pytest-180/test_a_key")
    assert not _leaks(redacted_path(keyed))

    # And an ordinary deep path, which a window scan with no other condition eats:
    # "homemeDocumentswork2026rapporterkvartalq3final" is 45 characters of perfectly
    # good base64url alphabet.
    ordinary = "/home/me/Documents/work/2026/rapporter/kvartal/q3/final"
    assert not path_carries_key_material(ordinary)
    assert redacted_path(ordinary) == ordinary


def test_a_key_split_with_backslashes_is_caught_too() -> None:
    """Windows separators. The same disclosure with a different key on the keyboard.

    Splitting on "/" alone made ``C:\\Users\\me\\<half>\\<half>`` a single component
    with no long run in it, so both halves printed in full — and ReceivedFile.save
    would have written the file.
    """
    from sikkerfil.links import path_carries_key_material, redacted_path

    windows = f"C:\\Users\\me\\{SECRET[:21]}\\{SECRET[21:]}"
    assert path_carries_key_material(windows)
    assert not _leaks(redacted_path(windows))
    # The separators survive redaction, or the message names a path nobody has.
    assert redacted_path(windows).startswith("C:\\Users\\me\\")
    ordinary = "C:\\Users\\me\\Documents\\kvartal-2026-q3.xlsx"
    assert redacted_path(ordinary) == ordinary


def test_standard_base64_spelling_is_refused_where_it_would_be_sent() -> None:
    """REFUSING IT AS INPUT SAID NOTHING ABOUT PRINTING IT.

    ``("A" * 10 + "/") * 3 + "A" * 10`` is 43 characters that become a working key
    the moment somebody swaps the slashes for underscores. The decoder rightly
    refuses that spelling — and the guard on send()'s body parameters used the PATH
    predicate, which splits on "/", so it read four short components and let the
    whole thing through to the service.
    """
    from sikkerfil.links import opaque_carries_key_material

    alias = ("A" * 10 + "/") * 3 + "A" * 10
    assert len(alias) == 43
    assert opaque_carries_key_material(alias)
    assert opaque_carries_key_material(alias.replace("/", "+"))
    # And the values these guards must not refuse.
    for ordinary in (
        "application/octet-stream",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "kvartalsrapport-2026-q3",
        "hemmelig-passord-2026",
        "text/csv",
    ):
        assert not opaque_carries_key_material(ordinary), ordinary


def test_a_credential_header_is_recognised_whatever_its_case() -> None:
    """HTTP header names are case-insensitive; a dict lookup is not.

    Nothing in this library spells them any way but through the constants, so the
    check was never missed here — but Transport is public, "X-Sikkerfil-Token" is the
    conventional spelling, and the service reads that header just the same.
    """
    from sikkerfil.transport import Transport

    attempted: list[str] = []

    def spy(request: Any, *args: Any, **kwargs: Any) -> Any:
        attempted.extend(f"{n}: {v}" for n, v in request.header_items())
        raise urllib.error.URLError("the test does not use the network")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(urllib.request, "urlopen", spy)
        spellings = ("X-Sikkerfil-Token", "x-sikkerfil-token", "X-SIKKERFIL-KEY", "X-Sikkerfil-Key")
        for spelling in spellings:
            with pytest.raises(ConfigurationError, match="not shaped like a credential"):
                Transport("http://127.0.0.1:9", retries=0).get_json(
                    "/api/v1/health", headers={spelling: SECRET}
                )
    assert not any(_leaks(line) for line in attempted), attempted


def test_a_truncated_key_is_not_a_named_link() -> None:
    """The service's own pattern says what a name IS, not what it CARRIES.

    ``"a" * 40`` is a valid named link by that regex and the first 40 characters of a
    real key: 240 of its 256 bits before the '#', with about 65,536 completions left
    to try offline. Both questions have to be asked.
    """
    lowercase = crypto.key_text("a" * 42 + "g")
    for prefix in (40, 36, 33):
        with pytest.raises(ConfigurationError) as caught:
            build_link("https://sikkerfil.no", lowercase[:prefix], SECRET)
        assert not _leaks(str(caught.value)), str(caught.value)
    # And the named links that must keep working.
    for name in ("kvartalsrapport-2026-q3", "rapport", "q3-2026-endelig"):
        assert build_link("https://sikkerfil.no", name, SECRET).startswith(
            f"https://sikkerfil.no/{name}#k="
        )


def test_argparse_cannot_echo_a_key_from_any_slot() -> None:
    """EVERY argparse REFUSAL, not the two options I fixed one at a time.

    ``choices=`` came off --market and ``type=int`` came off --max-downloads, and the
    SUBCOMMAND slot was still argparse's: ``sikkerfil <a key>`` formats "invalid
    choice: '<the whole key>'" onto stderr itself, and the SystemExit it then raises
    carries nothing, so the exception was spotless and the terminal had the key.
    """
    from sikkerfil import cli

    wide = "".join(chr(ord(ch) + 0xFEE0) if "!" <= ch <= "~" else ch for ch in SECRET)
    for argv in (
        [SECRET],
        [wide],
        [" ".join(SECRET)],
        ["--market", SECRET, "list"],
        ["send", "rapport.pdf", "--max-downloads", SECRET],
        ["send", "rapport.pdf", "--expires", SECRET],
    ):
        out, err = io.StringIO(), io.StringIO()
        with (
            contextlib.suppress(BaseException),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            cli.main(argv)
        written = out.getvalue() + err.getvalue()
        assert not _leaks(written), written
        assert wide not in written, written

    # AND THE ORDINARY MESSAGES STILL SAY SOMETHING. A run test over the
    # whitespace-folded spelling withheld "the following arguments are required:
    # file", because that is 32 characters of the alphabet once the spaces come out.
    err = io.StringIO()
    with (
        contextlib.suppress(BaseException),
        contextlib.redirect_stderr(err),
        contextlib.redirect_stdout(io.StringIO()),
    ):
        cli.main(["send"])
    assert "required" in err.getvalue() and "file" in err.getvalue(), err.getvalue()


# --- Round fourteen: the space between the characters, and the separator as one --


def test_a_spaced_near_key_is_not_printed_by_argparse() -> None:
    """THE WHOLE-KEY FALLBACK WAS TOO NARROW, and I had just made it that way.

    ``sikkerfil <42 key characters separated by spaces>`` has no run for the
    substitution to find and is not a whole key either, so the message printed every
    character; deleting the spaces gives back 252 of the key's 256 bits.

    The fix is not a better pattern. argparse is refusing an argv element we are
    holding, so the value does not have to be RECOGNISED — it can be matched. What
    remains pattern-based is only the backstop for a value we were not given.
    """
    from sikkerfil import cli

    key = crypto.b64url_encode(bytes(range(32)))
    for spelling in (
        " ".join(key[:-1]),  # 42 characters, spaced
        " ".join(key),
        key[:21] + "\n" + key[21:],  # wrapped, so argparse escapes it in %r
        key[:-1],
        key[:36],
    ):
        err = io.StringIO()
        with (
            contextlib.suppress(BaseException),
            contextlib.redirect_stderr(err),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            cli.main([spelling])
        folded = "".join(err.getvalue().split())
        for length in (43, 42, 36, 30, 24):
            assert key[:length] not in folded, err.getvalue()

    # The same value in an option slot, not only the subcommand one.
    for argv in (
        ["--market", " ".join(key[:-1]), "list"],
        ["send", "r.pdf", "--max-downloads", " ".join(key[:-1])],
        ["send", "r.pdf", "--expires", " ".join(key[:-1])],
    ):
        err = io.StringIO()
        with (
            contextlib.suppress(BaseException),
            contextlib.redirect_stderr(err),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            cli.main(argv)
        assert key[:30] not in "".join(err.getvalue().split()), err.getvalue()


def test_a_key_chunked_across_path_components_is_caught() -> None:
    """THE SEPARATOR CAN BE PART OF THE KEY, which the join pass cannot see.

    Standard base64 spells with "/", so ``("A" * 10 + "/") * 3 + "A" * 10`` is four
    ten-character path components AND a 43-character key once the slashes are read as
    underscores. A key cut into four pieces by hand is the same shape. Neither piece
    reaches KEY_RUN, so neither is a fragment and the join pass never ran.

    Reading every path that way redacts half of them — aliasing the separators of
    this repository's own source files produces 43 characters of the alphabet too.
    What separates them is uniformity: a key cut into pieces is cut at a fixed width.
    """
    from sikkerfil.links import path_carries_key_material, redacted_path

    key = crypto.b64url_encode(bytes(range(32)))
    chunked = [
        ("A" * 10 + "/") * 3 + "A" * 10,
        "/".join([key[:11], key[11:22], key[22:33], key[33:]]),
        "/".join([key[:15], key[15:30], key[30:]]),
        "\\".join([key[:11], key[11:22], key[22:33], key[33:]]),
        "/".join(key[i : i + 9] for i in range(0, 43, 9)),
    ]
    for value in chunked:
        assert path_carries_key_material(value), value
        assert not _leaks(redacted_path(value)), redacted_path(value)
        assert not _leaks(redacted_path(value).replace("/", "_").replace("\\", "_"))

    # AND THE PATHS THIS MUST NOT EAT. Measured over 99,595 real paths on the machine
    # this was written on, the rule redacts 0.06% of them; aliasing every separator
    # unconditionally redacts 50%, this repository's own modules among them.
    for ordinary in (
        "/home/user/sikkerfil-py/src/sikkerfil/errors.py",
        "/home/me/Documents/work/2026/rapporter/kvartal/q3/final",
        "/tmp/pytest-of-user/pytest-63/test_a_key_pasted_with_whi0/rapport.pdf",
        "C:\\Users\\me\\Documents\\kvartal-2026-q3.xlsx",
        "/var/folders/9z/abcdefgh/T/tmp1234/rapport.pdf",
        # THIS ONE PINS THE SLACK. dist-packages/setuptools/_distutils/__pycache__
        # is 13/10/11/11 — four evenly-ish sized components of pure alphabet that
        # join past 43 characters — so it is redacted the moment the tolerance goes
        # to three, and it is an ordinary path on any machine with setuptools on it.
        "/usr/lib/python3/dist-packages/setuptools/_distutils/__pycache__/_log.cpython-312.pyc",
    ):
        assert not path_carries_key_material(ordinary), ordinary
        assert redacted_path(ordinary) == ordinary


# --- Round fifteen: where the slashes fall, and a prefix worn by the wrong secret


def test_a_key_spelled_in_standard_base64_is_caught_however_it_falls() -> None:
    """THE SLASHES FALL WHERE THE BYTES FALL, not at a width somebody chose.

    A key re-encoded with standard base64 puts "/" and "+" wherever the data puts
    them — 20/6/15, not 11/11/11/10 — so the uniformity gate that catches a
    hand-chunked key does nothing, and dropping the separators does nothing either,
    because here the separators ARE key characters.
    """
    import base64

    from sikkerfil.links import path_carries_key_material, redacted_path

    spellings = [
        "A" * 20 + "/" + "A" * 6 + "/" + "A" * 15,
        ("A" * 10 + "/") * 3 + "A" * 10,
        base64.b64encode(bytes(range(32))).decode().rstrip("="),
        base64.b64encode(bytes(range(200, 232))).decode().rstrip("="),
        # PADDED, WHICH IS THE CANONICAL FORM AND THE ONE I MISSED. b64encode ends a
        # 32-byte key with "=", so the spelling the standard library actually
        # produces is FORTY-FOUR characters — and I had measured the anchor against a
        # spelling I wrote myself with .rstrip("=") on the end of it.
        "A" * 20 + "/" + "A" * 6 + "/" + "A" * 15 + "=",
        ("A" * 10 + "+") * 3 + "A" * 10 + "=",
        base64.b64encode(bytes(range(32))).decode(),
        base64.b64encode(bytes(range(60, 92))).decode(),
    ]
    for spelling in spellings:
        assert len(spelling.rstrip("=")) == 43, spelling
        assert path_carries_key_material(spelling), spelling
        assert redacted_path(spelling) == f"<{len(spelling)} characters, not repeated>"

    # THE DOCUMENTED GAP, asserted so that it stays a decision rather than becoming a
    # surprise: the same spelling nested inside a longer path is NOT caught, because
    # every anchor that catches it reads ordinary separators as key characters and
    # costs between 7.7% and 50% of the real paths on this machine.
    assert not path_carries_key_material("./" + spellings[0])

    # THE COST, MEASURED AND ACCEPTED: a path that is exactly 43 characters with no
    # dot in it loses its name in a "no such file" message. 0.18% of the real paths
    # on the machine this was written on; every wider anchor costs far more (7.7% for
    # separator-delimited spans, 50% for every window).
    assert path_carries_key_material("/usr/share/clang/scan-view-18/bin/scan-view")
    # One character either side and it prints again, which is what "anchored" means.
    assert not path_carries_key_material("/usr/share/clang/scan-view-18/bin/scan-vie")
    assert not path_carries_key_material("/usr/share/clang/scan-view-18/bin/scan-view2")


def test_an_ordinary_custom_origin_with_even_labels_still_works() -> None:
    """THE FOURTH TIME A LEAK FIX OF MINE BROKE A WORKING DEPLOYMENT.

    The run that catches a chunked key was joining components with "_" — which works
    only because an underscore is a base64url character — and the same function
    answers for DNS labels. So private.secure.files.company.internal.example, whose
    labels are 7/6/5/7/8/7 and therefore "uniform", joined to 45 characters and was
    refused.

    The separators are DROPPED now rather than translated, which is also the correct
    reading of the thing being caught: somebody chunked a key, and the separators are
    not part of it. Those labels join to 40 characters, which is not a key.
    """
    from sikkerfil.links import origin_of

    for host in (
        "private.secure.files.company.internal.example",
        "files.secure.internal.example",
        "a.b.c.d.e.f.example",
        "delivery.sikkerfil-staging.example.com",
    ):
        assert origin_of(f"https://{host}/x") == f"https://{host}", host
        assert parse_link(f"https://{host}/s/ABCD1234").origin == f"https://{host}"

    # And the split key the rule exists for is still caught — in halves and in
    # thirds, where every piece clears KEY_RUN.
    lowercase = crypto.key_text("a" * 42 + "g")
    assert origin_of(f"https://{lowercase[:21]}.{lowercase[21:]}/x") == ""
    thirds = ".".join([lowercase[:15], lowercase[15:30], lowercase[30:]])
    assert origin_of(f"https://{thirds}/x") == ""

    # THE GAP, NARROWED DELIBERATELY AND ASSERTED AS A GAP. A key cut into four
    # eleven-character labels is no longer refused, because catching it means letting
    # a run form out of labels shorter than KEY_RUN — and a domain is a handful of
    # short labels, so that is what refused
    # private.secure.files.company.internal.example.com twice. On a host a piece of a
    # key has to be at least KEY_RUN characters; four pieces of eleven is a
    # construction nobody registers by accident, and five hostname regressions on
    # this branch is enough.
    quartered = ".".join([lowercase[:11], lowercase[11:22], lowercase[22:33], lowercase[33:]])
    assert origin_of(f"https://{quartered}/x") != ""
    # It is still refused as a PATH, where short components are not the norm.
    from sikkerfil.links import path_carries_key_material

    assert path_carries_key_material(quartered.replace(".", "/"))


def test_the_share_key_wearing_a_credential_prefix_is_still_the_key() -> None:
    """The prefix that makes a credential recognisable makes a key unrecognisable.

    ``revoke(sent, write_token="wt_" + sent.key)`` is what an application produces
    when it stores the wrong secret and adds the documented prefix around it: the
    comparison tried to decode the whole thing, failed, and said "not the key" — and
    transport then saw wt_ and 43 characters of base64url, which is exactly what a
    real write token is.
    """
    from sikkerfil.models import SentShare

    key = crypto.b64url_encode(bytes(range(32)))
    sent = SentShare(
        id="ABCD1234",
        url=f"https://sikkerfil.no/s/ABCD1234#k={key}",
        write_token="wt_" + "y" * 43,
        key=key,
        expires_at=1_700_000_000,
        size_bytes=10,
    )
    attempted: list[str] = []

    def spy(request: Any, *args: Any, **kwargs: Any) -> Any:
        attempted.extend(f"{n}: {v}" for n, v in request.header_items())
        raise urllib.error.URLError("the test does not use the network")

    client = Sikkerfil(api_key="sikkerfil_sk_" + "x" * 43, retries=0, base_url="http://127.0.0.1:9")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(urllib.request, "urlopen", spy)
        for worn in ("wt_" + key, "sikkerfil_sk_" + key, "wt_" + key + "==", key):
            with pytest.raises(ConfigurationError, match=r"this share's DECRYPTION KEY"):
                client.revoke(sent, write_token=worn)
        assert not attempted, attempted

        # The token it was actually issued still goes.
        with contextlib.suppress(Exception):
            client.revoke(sent)
    assert any("wt_yyy" in line for line in attempted), attempted


# --- Round seventeen: what a key looks like when the standard library writes it --


def _every_rendering_the_standard_library_makes(raw: bytes) -> dict[str, str]:
    """Every way the standard library writes 32 raw bytes down.

    THE VECTORS DO NOT COME FROM MY HAND ANY MORE, and that is the point of this
    function. Three rounds running, a guard was calibrated against spellings I had
    typed myself — with the padding already stripped, or in the alphabet I happened
    to think of — and the review found the one the library actually produces. So the
    list is generated, and anything added to it is added by naming a stdlib call.
    """
    import base64

    renderings = {
        "b64encode": base64.b64encode(raw).decode(),
        "b64encode unpadded": base64.b64encode(raw).decode().rstrip("="),
        "urlsafe_b64encode": base64.urlsafe_b64encode(raw).decode(),
        "urlsafe unpadded": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "encodebytes (MIME)": base64.encodebytes(raw).decode(),
        "b32encode": base64.b32encode(raw).decode(),
        "b16encode": base64.b16encode(raw).decode(),
        "hex": raw.hex(),
        "hex with colons": raw.hex(":"),
        "hex with dashes": raw.hex("-"),
        "repr": repr(raw),
        "a85encode adobe": base64.a85encode(raw, adobe=True).decode(),
        "a85encode foldspaces": base64.a85encode(raw, foldspaces=True).decode(),
        "a85encode adobe+foldspaces": base64.a85encode(raw, adobe=True, foldspaces=True).decode(),
        # EVERY SEPARATOR bytes.hex() will take, not the two I thought of.
        **{f"hex({sep!r})": raw.hex(sep) for sep in ".:-_|+ "},
        "hex grouped": raw.hex(" ", 4),
        # BOTH SIGNS OF bytes_per_sep, at sizes that do NOT divide 32. Negative
        # counts groups from the left and positive from the right, so the short
        # group changes ends — and every grouped vector here used to divide 32,
        # which is exactly where the two layouts agree.
        **{f"hex(' ', {n})": raw.hex(" ", n) for n in (3, 5, 6, 7, 9, 12, 20, 31)},
        **{f"hex(' ', -{n})": raw.hex(" ", -n) for n in (3, 5, 6, 7, 9, 12, 20, 31)},
        "hex 0x": "0x" + raw.hex(),
    }
    # z85 exists from 3.13, which this package supports; the interpreter running the
    # tests is not the only one a caller has.
    if hasattr(base64, "z85encode"):
        renderings["z85encode"] = base64.z85encode(raw).decode()
    return renderings


@pytest.mark.parametrize("payload", [bytes(range(32)), b"?" * 32, bytes(range(200, 232))])
def test_every_standard_rendering_of_a_key_is_refused_as_a_value(payload: bytes) -> None:
    """A KEY IN TEXT WAS NEVER ONLY BASE64.

    The library hands callers raw bytes as ``Sealed.key``, and every one of these is
    what the standard library does with those bytes — so each is a spelling somebody
    can paste into a password field and reverse afterwards. Asking "is this spelled
    like base64" chased them one round at a time; asking "does this DECODE to 32
    bytes" closes the set around what a key actually is.
    """
    from sikkerfil.links import opaque_carries_key_material

    unreversible = {"b32encode", "b16encode"}  # see the assertion below
    for label, spelling in _every_rendering_the_standard_library_makes(payload).items():
        if label in unreversible:
            continue
        assert opaque_carries_key_material(spelling), f"{label}: {spelling[:40]}"

    # b32 and b16 are NOT claimed: they are 56 and 64 characters of an alphabet the
    # run check already refuses at 32, so they are caught — by a different rule, and
    # this says so rather than letting the parametrised list imply a claim the
    # renderer does not make.
    for label in unreversible:
        spelling = _every_rendering_the_standard_library_makes(payload)[label]
        assert opaque_carries_key_material(spelling), label


@pytest.mark.parametrize("width", [6, 8, 9, 10, 11, 12, 14, 15, 20, 21])
def test_a_key_wrapped_at_any_width_is_caught(width: int) -> None:
    """THE LAST PIECE OF A FIXED-WIDTH SPLIT IS SHORT, ALWAYS.

    ``textwrap.wrap(key, 10)`` gives 10/10/10/10/3, and the three closed the run
    before it could be counted: forty characters is not a key, and the remainder was
    left stranded. Every width from six to twenty-one now, because picking one width
    to test is how the first version of this passed.
    """
    import base64
    import textwrap

    from sikkerfil.links import path_carries_key_material, redacted_path

    key = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    for separator in ("/", "\\"):
        chunked = separator.join(textwrap.wrap(key, width))
        assert path_carries_key_material(chunked), f"width {width}: {chunked}"
        assert not _leaks(redacted_path(chunked))


@pytest.mark.parametrize("payload", [bytes(range(32)), b"?" * 32])
def test_every_standard_rendering_of_a_key_is_refused_as_a_path(payload: bytes) -> None:
    """THE SAME QUESTION ON THE PATH SIDE, which is where the MIME spelling bit.

    ``encodebytes`` wraps its output with a NEWLINE AFTER THE PADDING, so stripping
    "=" removed nothing and the 45-character value missed a length anchor — while
    its many "/" characters cut it into three-character components that no run test
    looks at twice. The value predicate caught it by accident, because 44 characters
    of base64 alphabet is a long run; the path predicate, which splits on "/" first,
    did not.

    So this asserts the path side separately. It is the same mistake as testing a
    rule against one of its two callers, which is what round fifteen was about.
    """
    from sikkerfil.links import path_carries_key_material, redacted_path

    for label, spelling in _every_rendering_the_standard_library_makes(payload).items():
        assert path_carries_key_material(spelling), f"{label}: {spelling[:40]!r}"
        assert not _leaks(redacted_path(spelling)), label
        folded = "".join(redacted_path(spelling).split())
        assert not _leaks(folded), label


def test_the_renderings_a_path_message_must_still_print() -> None:
    """The other side of the same rule, measured rather than asserted by feel.

    Over 99,600 real paths on the machine this was written on, the whole-value
    rendering anchor redacts 0.18% and the chunked-run rule 0.02%. The rest of what
    the predicate refuses is PATH_RUN on single components of 32 characters, which
    has been the documented trade since it was introduced.
    """
    from sikkerfil.links import path_carries_key_material, redacted_path

    for ordinary in (
        "/home/me/Documents/kvartalsrapport-2026-q3.pdf",
        "/home/me/Documents/work/2026/rapporter/kvartal/q3/final",
        "/usr/lib/python3/dist-packages/setuptools/_distutils/__pycache__/_log.cpython-312.pyc",
        "/tmp/pytest-of-user/pytest-63/test_a_key_pasted_with_whi0/rapport.pdf",
        "C:\\Users\\me\\Documents\\kvartal-2026-q3.xlsx",
        "/var/folders/9z/abcdefgh/T/tmp1234/rapport.pdf",
        "relative/path/to/a/file.txt",
    ):
        assert not path_carries_key_material(ordinary), ordinary
        assert redacted_path(ordinary) == ordinary


# --- Round eighteen: base85, a media type, and a path that only exists joined ---


def test_base85_renderings_are_refused_as_a_value() -> None:
    """The set was "what the standard library produces" and I left two encoders out.

    WHAT THIS TEST IS ACTUALLY WORTH, stated because the code says it too: b85's
    alphabet covers every letter and digit, so any forty alphanumeric characters
    decode to 32 bytes — a sha1 digest does. This is a length test at forty, exactly
    as the base64 one is a length test at forty-three. It is asked only about a whole
    value for that reason, and a caller whose password is forty characters of that
    alphabet is refused by name.
    """
    import base64

    from sikkerfil.links import opaque_carries_key_material, path_carries_key_material

    for payload in (bytes(range(32)), b"?" * 32):
        for rendering in (base64.a85encode(payload), base64.b85encode(payload)):
            spelling = rendering.decode()
            assert len(spelling) == 40
            assert opaque_carries_key_material(spelling), spelling
            assert path_carries_key_material(spelling), spelling


def test_a_registered_media_type_is_not_a_key() -> None:
    """A run of 32 characters in a MIME type is a registered subtype, not a key.

    ``mimetypes.guess_type("x.cii")`` returns a 54-character media type, and the run
    threshold refused it while ``_guess_type`` generated and sent the identical value
    when ``content_type`` was left out. Refusing a value the library itself produces
    is not a security property, it is a bug with a security-shaped excuse.
    """
    import mimetypes

    from sikkerfil.client import _is_a_content_type

    # Every type the standard library will hand us for a plausible attachment.
    for suffix in (".cii", ".pdf", ".xlsx", ".docx", ".csv", ".odt", ".zip", ".json", ".bin"):
        guessed = mimetypes.guess_type("x" + suffix)[0] or "application/octet-stream"
        assert _is_a_content_type(guessed), guessed

    # And the shapes that are not media types, including the one that is BOTH a valid
    # media type by RFC 6838 and a key in standard base64.
    for refused in (
        SECRET,
        f"{SECRET[:20]}/{SECRET[20:]}",
        "A" * 20 + "/" + "A" * 22,
        "not a media type",
        "application/",
        "",
    ):
        assert not _is_a_content_type(refused), refused


def test_a_rendering_that_only_exists_once_the_path_is_joined_is_refused(tmp_path) -> None:
    """Neither half carries it; the join does.

    ``b64encode`` of 32 bytes is ``Pz8/Pz8/…/Pz8=`` — which ``os.path.split`` turns
    into ten three-character directories and a four-character filename, so the
    directory check and the name check both passed and ``open()`` got the whole
    reversible thing. The same route runs through the CLI's ``receive -o``.
    """
    import base64

    from sikkerfil.links import joined_path_spells_a_key

    rendering = base64.b64encode(b"?" * 32).decode()
    assert joined_path_spells_a_key(rendering)
    # A key cut in two by the join, which is the other way a path spells one. (An
    # extra separator pushed INTO a rendering that already has its own — 45
    # characters of which one must be deleted and the others kept — is not caught,
    # and I wrote that assertion before checking it: a gap, not a behaviour.)
    assert joined_path_spells_a_key(f"{SECRET[:21]}/{SECRET[21:]}")

    # AND THE PATHS THIS SUITE ITSELF WRITES TO, because the first version of this
    # check asked the full predicate and refused them: "…/test_a_hostile_filename_
    # canno0/authorized_keys" is 30 characters and 15, the shape of a split at width
    # thirty, and "…/test_a_tilde_in_the_directory_0/Downloads" is 31 and 9, which is
    # forty characters and therefore a base85 rendering of something.
    for ordinary in (
        str(tmp_path / "rapport.pdf"),
        "/tmp/pytest-of-user/pytest-257/test_a_hostile_filename_canno0/authorized_keys",
        "/tmp/pytest-of-user/pytest-257/test_a_tilde_in_the_directory_0/Downloads/rapport.pdf",
        "/home/me/Downloads/kvartalsrapport-2026-q3.pdf",
    ):
        assert not joined_path_spells_a_key(ordinary), ordinary


# --- Round twenty-one: which renderings may be asked where ----------------------


def test_base32_and_every_hex_separator_are_renderings_too() -> None:
    """Two more encoders, and a separator that is itself a hex digit.

    ``hex("a")`` was the third attempt at that one: I named ":" and "-", then took
    "whatever character is not a hex digit" — which hex("a") walks past — and then
    deleting every "a" also deletes the "a" inside "0a". What bytes.hex produces is
    fixed-size groups with one character between them, so the SHAPE is what is
    checked, at every group size.
    """
    import base64

    from sikkerfil.links import renders_key_bytes, renders_key_bytes_strictly

    raw = bytes(range(32))
    for separator in ".:-_|+ abcdefABCDEF0123456789xyz/\\":
        for per_group in (1, 2, 4, 8, 16):
            spelling = raw.hex(separator, per_group)
            assert renders_key_bytes(spelling), spelling[:40]
            assert renders_key_bytes_strictly(spelling), spelling[:40]
    for spelling in (base64.b32encode(raw).decode(), base64.b32hexencode(raw).decode()):
        assert renders_key_bytes(spelling)
        assert renders_key_bytes_strictly(spelling)


def test_the_strict_renderings_may_be_asked_of_joins_and_the_others_may_not() -> None:
    """THE DIVISION THIS ROUND IS ABOUT, asserted from both sides.

    Some renderings carry information in every character — hex is 64 characters of
    sixteen, base32 is 56 of thirty-two — and some are a length test in costume:
    base64 is any 43 alphanumerics, base85 any 40 printable characters, and z85
    (3.13) decodes both 40 AND 41. The second group may only be asked about a whole
    value a caller handed over; the first may be asked about joins, subsequences and
    windows, because a hostname does not accidentally contain 64 hex digits.
    """
    import base64

    from sikkerfil.links import origin_of, path_carries_key_material, renders_key_bytes_strictly

    raw = bytes(range(32))
    # A domain whose labels join to 43 characters of base64url — the degenerate test
    # would call this a key, and it is an ordinary name.
    assert not renders_key_bytes_strictly("privatesecurefilescompanyinternalexamplecom")
    assert origin_of("https://private.secure.files.company.internal.example.com/x") != ""

    # The strict renderings, split by the structure rather than by a caller.
    assert origin_of("https://" + raw.hex(".") + "/x") == ""
    assert path_carries_key_material("/tmp/" + raw.hex("/"))
    assert path_carries_key_material(raw.hex("/"))
    for spelling in (base64.b64encode(raw).decode(), base64.b85encode(raw).decode()):
        assert not renders_key_bytes_strictly(spelling), spelling


def test_our_own_refusals_do_not_print_a_rendering() -> None:
    """quoted() is the chokepoint, so it asks the whole question.

    ``base_url_for(key.hex("."))`` put ninety-five characters of dotted hex into its
    own refusal: every run in it is two characters long, so the run test — which is
    all quoted() asked — saw nothing.
    """
    import base64

    from sikkerfil.links import base_url_for, quoted

    raw = bytes(range(32))
    for spelling in (
        raw.hex("."),
        raw.hex(),
        base64.b32encode(raw).decode(),
        base64.b64encode(raw).decode(),
        base64.b85encode(raw).decode(),
    ):
        assert "not repeated" in quoted(spelling), spelling[:40]
        with pytest.raises(ConfigurationError) as caught:
            base_url_for(spelling)
        assert spelling[:20] not in str(caught.value)

    # And what a person actually mistypes still prints, or the message is useless.
    for ordinary in ("nope", "NO", "sv", "x", "no/"):
        assert repr(ordinary) == quoted(ordinary), ordinary


# --- Round twenty-two: the sign of a separator, the cost of a scan --------------


def test_hex_groups_are_counted_from_the_right_too() -> None:
    """``bytes_per_sep`` IS SIGNED, and the shape parser knew only one of the signs.

    ``bytes.hex(sep, n)`` counts groups from the LEFT when ``n`` is negative and from
    the RIGHT when it is positive — and positive is what a reader types. So when the
    group size does not divide 32 the short group is FIRST, and the parser, which
    built its groups left to right with the remainder at the end, walked straight
    past ``bytes(range(32)).hex(".", 3)``: "0001." and then ten groups of six.

    Every size from one to thirty-one, both signs, because the sizes that divide 32
    are exactly the ones where the two layouts agree — and 1, 2, 4, 8 and 16 were the
    sizes the round before this one tested.
    """
    from sikkerfil.links import (
        opaque_carries_key_material,
        path_carries_key_material,
        quoted,
        renders_key_bytes,
        renders_key_bytes_strictly,
    )

    raw = bytes(range(32))
    for per_group in range(1, 32):
        for signed in (per_group, -per_group):
            for separator in ".:-_| abcdef0123":
                spelling = raw.hex(separator, signed)
                assert renders_key_bytes(spelling), f"{signed} {separator!r}"
                assert renders_key_bytes_strictly(spelling), f"{signed} {separator!r}"
                assert opaque_carries_key_material(spelling), f"{signed} {separator!r}"
                assert "not repeated" in quoted(spelling), f"{signed} {separator!r}"
            assert path_carries_key_material(raw.hex("/", signed)), signed

    # And the shape is a shape: a group short by one character is not 32 bytes.
    assert not renders_key_bytes_strictly(raw.hex(".", 3)[1:])
    assert not renders_key_bytes_strictly("0" + raw.hex(".", 3))


def test_base64_in_an_alphabet_the_caller_chose_is_still_a_key() -> None:
    """``b64encode(raw, altchars=b"~!")`` is reversible by anyone holding those two.

    The two alphabets this module knew — standard and url-safe — are just the two
    that have names. ``altchars`` is two arbitrary bytes, so there are thousands of
    alphabets and enumerating them was never going to work; what is fixed is the
    other sixty-two characters, and the shape: 43 characters of which at most two
    are not letters or digits.

    THIS IS A DEGENERATE TEST AND IT STAYS WHERE THEY LIVE. The second half of this
    asserts the containment: a whole value a caller handed over, never a hostname
    label, never a join.
    """
    import base64

    from sikkerfil.links import (
        opaque_carries_key_material,
        origin_of,
        quoted,
        renders_key_bytes,
        renders_key_bytes_strictly,
    )

    raw = b"?" * 32  # the payload whose standard base64 is all "/"
    for altchars in (b"~!", b"$%", b"()", b"*,", b"+/", b"-_"):
        spelling = base64.b64encode(raw, altchars=altchars).decode()
        assert base64.b64decode(spelling, altchars=altchars) == raw, altchars
        assert renders_key_bytes(spelling), altchars
        assert opaque_carries_key_material(spelling), altchars
        assert "not repeated" in quoted(spelling), altchars
        # It is NOT strict, which is what keeps it out of the path and host scans.
        assert not renders_key_bytes_strictly(spelling), altchars

    # THE COST, MEASURED, and asserted rather than described. Of 120,003 real
    # filenames on this machine, 87 — 0.073% — are 43 characters with at most two
    # kinds of punctuation in them, and "gnome-mime-application-x-compressed-tar.svg"
    # is one of them. That is the same order as the 0.085% the base85 test already
    # costs, which is the line round twenty-one drew and this is staying inside.
    #
    # The slots that ask this question are name, content_type and password — a value
    # a caller typed, where a refusal by name costs them a retype. send(filename=)
    # does not ask it, so the filename above still sends; that is measured here
    # rather than assumed, because the list of slots is the whole cost.
    from sikkerfil.errors import TransportError

    assert opaque_carries_key_material("gnome-mime-application-x-compressed-tar.svg")
    with contextlib.suppress(TransportError):
        Sikkerfil(
            api_key="sikkerfil_sk_" + "x" * 43, retries=0, base_url="http://127.0.0.1:9"
        ).send(b"hello", filename="gnome-mime-application-x-compressed-tar.svg")

    # The width this buys is real and it is the width every degenerate test has: a
    # 43-character value with punctuation in it. What it must not touch is a name.
    assert origin_of("https://private.secure.files.company.internal.example.com/x") != ""
    for ordinary in ("kvartalsrapport-2026-q3", "hemmelig-passord-2026", "text/csv"):
        assert not opaque_carries_key_material(ordinary), ordinary
    # AND THE MEDIA TYPES, ASKED WHERE THEY ARE ACTUALLY ASKED. content_type does not
    # go through opaque_carries_key_material — a registered subtype is a 38-character
    # run and the run threshold refuses it, which is why _is_a_content_type reads the
    # RFC 6838 grammar and looks at the tokens instead. The new test must not creep
    # into that path either.
    from sikkerfil.client import _is_a_content_type

    for registered in (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.anser-web-certificate-issue-initiation",
        "application/tamp-community-update-confirm",
        "text/csv",
    ):
        assert _is_a_content_type(registered), registered


def test_a_path_with_many_components_is_answered_promptly() -> None:
    """A SCAN THAT TAKES TWENTY-FIVE SECONDS IS A BROKEN CALL, not a safe one.

    The subsequence pass joined and tested every contiguous run — quadratically many
    runs, each join linear — so ``send("/".join(["a"] * 1600))`` sat for 25 seconds
    before it could say "no such file". A strict rendering of 32 bytes has a known
    length, so a run past the longest one cannot become one by growing; the scan has
    a ceiling now, and this asserts the ceiling at the call site rather than on the
    predicate that has it.
    """
    import time

    from sikkerfil.links import path_carries_key_material

    client = Sikkerfil(api_key="sikkerfil_sk_" + "x" * 43, retries=0, base_url="http://127.0.0.1:9")
    # Up to what a path can actually be: PATH_MAX is 4096, so 1600 two-character
    # components is near the longest path an operating system will carry — and it is
    # the length that took twenty-five seconds.
    for count in (400, 1000, 1600):
        missing = "/" + "/".join(["a"] * count)
        started = time.perf_counter()
        with pytest.raises(ConfigurationError, match="no such file"):
            client.send(missing)
        spent = time.perf_counter() - started
        assert spent < 5.0, f"{count} components took {spent:.1f}s"

    # And the thing the scan is FOR still works, at the same ceiling.
    raw = bytes(range(32))
    assert path_carries_key_material("/tmp/" + raw.hex("/"))
    assert path_carries_key_material("/tmp/" + raw.hex("/", 3))
    assert not path_carries_key_material("/home/me/Downloads/kvartalsrapport-2026-q3.pdf")
