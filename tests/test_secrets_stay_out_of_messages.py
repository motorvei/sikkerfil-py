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
        with pytest.raises(ConfigurationError, match="cannot be sent"):
            client.revoke("ABCD1234", write_token=bad)
        # And nothing of it comes back, through the message or the chain.
        try:
            client.revoke("ABCD1234", write_token=bad)
        except ConfigurationError as exc:
            assert not _leaks(str(exc)), str(exc)
            assert exc.__context__ is None


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
    with pytest.raises(ConfigurationError, match="decryption key"):
        client.revoke("ABCD1234", write_token=SECRET)
    assert not any(_leaks(value) for value in sent.values()), sent

    with pytest.raises(ConfigurationError, match="decryption key"):
        Sikkerfil(api_key=SECRET, retries=0, base_url="http://127.0.0.1:9").shares()
    assert not any(_leaks(value) for value in sent.values()), sent

    # A real token still goes, or the guard has broken the feature it protects.
    sent.clear()
    with contextlib.suppress(Exception):
        client.revoke("ABCD1234", write_token="wt_" + "y" * 20)
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

    # And a reverse-proxy path prefix still works, since origin_of's answer is used
    # as a verdict and not as the value.
    client = Sikkerfil(
        api_key="sikkerfil_sk_" + "x" * 43, base_url="https://host.example/sikkerfil", retries=0
    )
    assert client.base_url == "https://host.example/sikkerfil"
