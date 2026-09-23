"""
The whole flow, over a real socket: encrypt, create, upload, complete, download,
decrypt.

THE PROPERTY EVERY TEST HERE SERVES. What leaves this process is ciphertext and
nothing else. The service gets a size, a declared type and an opaque name; it
never gets the key, the plaintext, or the filename. Several of these tests do
nothing but assert that — by searching everything the stub received for things
that must not be in it.
"""

from __future__ import annotations

import base64
import contextlib
import json
from typing import Any

import pytest

from sikkerfil import Sikkerfil, crypto
from sikkerfil.errors import (
    ConfigurationError,
    DecryptionError,
    DownloadsExhaustedError,
    PasswordRequiredError,
)
from sikkerfil.transport import API_PREFIX, DIGEST_HEADER, sha256_hex

PLAINTEXT = b"Kvartalsrapport Q3\nOmsetning: 4 200 000 NOK\n"

#: A KEY OF THE SHAPE THE SERVICE MINTS — sikkerfil_sk_ and 43 characters of
#: base64url, as app/src/key-format.ts spells it. Transport refuses anything else on
#: the credential header, so "k" used to be enough here only because nothing checked.
API_KEY = "sikkerfil_sk_" + "a" * 43


@pytest.fixture
def client(stub) -> Sikkerfil:
    return Sikkerfil(api_key=API_KEY, base_url=stub.base_url, retries=0)


# --- The round trip ----------------------------------------------------------


def test_a_file_survives_the_round_trip(client: Sikkerfil, stub) -> None:
    sent = client.send(PLAINTEXT, filename="rapport.pdf")
    got = client.receive(sent.url)

    assert got.data == PLAINTEXT
    assert got.filename == "rapport.pdf"
    assert got.share.id == sent.id


def test_the_link_carries_the_key_and_the_service_never_saw_it(
    client: Sikkerfil, stub
) -> None:
    sent = client.send(PLAINTEXT, filename="rapport.pdf")

    assert f"#k={sent.key}" in sent.url

    # THE TEST THIS LIBRARY IS FOR. Everything the stub received, in one blob,
    # searched for the three things that must never have been sent.
    everything = b"".join(
        r.body + r.path.encode() + json.dumps(r.headers).encode() for r in stub.requests
    )
    assert sent.key.encode() not in everything, "the decryption key was sent to the service"
    assert PLAINTEXT not in everything, "the plaintext was sent to the service"
    assert b"rapport.pdf" not in everything, "the filename was sent in the clear"


def test_the_bytes_uploaded_are_the_envelope_and_nothing_else(
    client: Sikkerfil, stub
) -> None:
    sent = client.send(PLAINTEXT, filename="x.bin")
    uploaded = stub.objects[sent.id]

    assert len(uploaded) == crypto.IV_BYTES + len(PLAINTEXT) + crypto.TAG_BYTES
    assert uploaded[: crypto.IV_BYTES] != b"\x00" * crypto.IV_BYTES, "the IV is not random"
    # And it opens with the key from the link, which is the only copy.
    assert crypto.open_sealed(uploaded, crypto.b64url_decode(sent.key)) == PLAINTEXT


def test_the_share_is_created_for_the_ciphertext_size(client: Sikkerfil, stub) -> None:
    """S3 PINS THE LENGTH INTO THE PRESIGNED SIGNATURE.

    A share created for the plaintext size produces an upload S3 refuses with
    SignatureDoesNotMatch — 28 bytes short, every time, for every file. The stub
    enforces the same rule, so this would fail loudly rather than subtly.
    """
    sent = client.send(PLAINTEXT, filename="x.bin")
    created = json.loads(next(r for r in stub.requests if r.path == f"{API_PREFIX}/shares").body)
    assert created["sizeBytes"] == len(PLAINTEXT) + crypto.IV_BYTES + crypto.TAG_BYTES
    assert sent.size_bytes == created["sizeBytes"]


def test_every_post_in_the_flow_carried_its_digest(client: Sikkerfil, stub) -> None:
    # The end-to-end version of the structural check in test_transport.py: not
    # "post_json sets the header" but "every POST this flow made had it".
    client.send(PLAINTEXT, filename="x.bin")
    posts = [r for r in stub.requests if r.method == "POST"]
    assert len(posts) >= 2, "expected at least the create and the complete"
    for request in posts:
        assert request.headers.get(DIGEST_HEADER) == sha256_hex(request.body), (
            f"POST {request.path} would be refused by CloudFront"
        )


def test_the_upload_is_a_put_of_octet_stream(client: Sikkerfil, stub) -> None:
    client.send(PLAINTEXT, filename="x.bin")
    put = next(r for r in stub.requests if r.method == "PUT")
    # Not the caller's content type: an object served back with a type the
    # uploader chose is how a file share becomes an HTML host.
    assert put.headers["content-type"] == "application/octet-stream"
    assert put.headers["content-length"] == str(len(put.body))


# --- Sources -----------------------------------------------------------------


def test_a_path_sends_its_own_name(client: Sikkerfil, tmp_path) -> None:
    path = tmp_path / "kontrakt.pdf"
    path.write_bytes(PLAINTEXT)
    sent = client.send(path)
    assert client.receive(sent.url).filename == "kontrakt.pdf"


def test_an_open_file_works_and_text_mode_is_refused(client: Sikkerfil, tmp_path) -> None:
    path = tmp_path / "notat.txt"
    path.write_bytes(PLAINTEXT)
    with path.open("rb") as handle:
        assert client.send(handle).size_bytes > 0
    with path.open("r") as handle, pytest.raises(ConfigurationError, match="binary mode"):
        client.send(handle)


def test_bytes_with_no_name_seal_no_name(client: Sikkerfil, stub) -> None:
    sent = client.send(PLAINTEXT)
    created = json.loads(next(r for r in stub.requests if r.path == f"{API_PREFIX}/shares").body)
    assert "encryptedName" not in created
    assert client.receive(sent.url).filename is None


def test_a_missing_file_fails_before_anything_is_sent(client: Sikkerfil, stub) -> None:
    with pytest.raises(ConfigurationError, match="no such file"):
        client.send("/nope/not/here.pdf")
    assert stub.requests == [], "a doomed send still talked to the service"


# --- Options -----------------------------------------------------------------


def test_options_reach_the_service(client: Sikkerfil, stub) -> None:
    client.send(
        PLAINTEXT,
        filename="x.pdf",
        expires_in=3600,
        max_downloads=2,
        password="hemmelig",
        name="kvartalsrapport",
    )
    created = json.loads(next(r for r in stub.requests if r.path == f"{API_PREFIX}/shares").body)
    assert created["expiresInSeconds"] == 3600
    assert created["maxDownloads"] == 2
    assert created["password"] == "hemmelig"
    assert created["name"] == "kvartalsrapport"
    assert created["contentType"] == "application/pdf"


def test_a_named_share_gets_a_named_link_and_resolves_by_it(
    client: Sikkerfil, stub
) -> None:
    sent = client.send(PLAINTEXT, filename="x.pdf", name="kvartalsrapport")
    assert sent.url.startswith(f"{stub.base_url}/kvartalsrapport#k=")
    # And the name resolves back to the file, through /api/navn/<name>.
    assert client.receive(sent.url).data == PLAINTEXT


def test_the_origin_is_sent_only_for_a_real_market(stub) -> None:
    """The service checks it against an allowlist and refuses an unknown one.

    Sending our stub's ``http://127.0.0.1:port`` would be refused with
    ``bad_origin`` — so the market check is not cosmetic, it is what keeps a
    custom base URL usable at all.
    """
    client = Sikkerfil(api_key=API_KEY, base_url=stub.base_url, retries=0)
    client.send(PLAINTEXT)
    created = json.loads(next(r for r in stub.requests if r.path == f"{API_PREFIX}/shares").body)
    assert "origin" not in created

    from sikkerfil.client import Sikkerfil as Real

    real = Real(api_key=API_KEY, market="dk")
    assert real.base_url == "https://sikkerfil.dk"


def test_a_password_is_required_and_a_wrong_guess_is_named(
    client: Sikkerfil, stub
) -> None:
    sent = client.send(PLAINTEXT, password="hemmelig")

    with pytest.raises(PasswordRequiredError, match="password-protected"):
        client.receive(sent.url)
    with pytest.raises(PasswordRequiredError, match="costs nothing"):
        client.receive(sent.url, password="feil")

    assert client.receive(sent.url, password="hemmelig").data == PLAINTEXT


def test_downloads_run_out(client: Sikkerfil, stub) -> None:
    sent = client.send(PLAINTEXT, max_downloads=1)
    assert client.receive(sent.url).data == PLAINTEXT
    with pytest.raises(DownloadsExhaustedError, match="no downloads left"):
        client.receive(sent.url)


# --- Refusals that should never cost a round trip ----------------------------


def test_sending_without_a_key_says_where_to_get_one(stub, monkeypatch) -> None:
    monkeypatch.delenv("SIKKERFIL_API_KEY", raising=False)
    client = Sikkerfil(base_url=stub.base_url, retries=0)
    with pytest.raises(ConfigurationError) as caught:
        client.send(PLAINTEXT)
    message = str(caught.value)
    assert "konto" in message, "the error does not say where keys come from"
    assert "receive" in message, "it does not mention that receiving needs nothing"


def test_a_missing_credential_is_caught_before_the_file_is_even_read(
    stub, tmp_path, monkeypatch
) -> None:
    """A 4 GB file must not be encrypted on the way to a refusal we could have
    made instantly."""
    monkeypatch.delenv("SIKKERFIL_API_KEY", raising=False)
    missing = tmp_path / "never-read.bin"          # deliberately not created
    client = Sikkerfil(base_url=stub.base_url, retries=0)

    with pytest.raises(ConfigurationError) as caught:
        client.send(missing)
    # The complaint is about the key, not about the file — which proves the
    # credential check ran first, before the source was touched.
    assert "API key" in str(caught.value)
    assert stub.requests == []


def test_a_link_without_a_key_is_refused_before_the_download(
    client: Sikkerfil, stub
) -> None:
    sent = client.send(PLAINTEXT)
    bare = sent.url.split("#")[0]
    before = len(stub.requests)
    with pytest.raises(ConfigurationError, match="no decryption key"):
        client.receive(bare)
    assert len(stub.requests) == before, "a hopeless download was attempted anyway"


def test_the_wrong_key_is_a_decryption_error_not_a_silent_mess(
    client: Sikkerfil, stub
) -> None:
    sent = client.send(PLAINTEXT)
    other = crypto.b64url_encode(crypto.new_key())
    with pytest.raises(DecryptionError, match="authentication tag"):
        client.receive(f"{sent.url.split('#')[0]}#k={other}")


def test_revoking_needs_the_write_token_not_the_api_key(client: Sikkerfil, stub) -> None:
    sent = client.send(PLAINTEXT)
    with pytest.raises(ConfigurationError, match="write token"):
        client.revoke(sent.id)

    client.revoke(sent)  # the SentShare carries it
    assert sent.id not in stub.shares


# --- Housekeeping ------------------------------------------------------------


def test_listing_and_audit(client: Sikkerfil, stub) -> None:
    sent = client.send(PLAINTEXT)
    assert [s.id for s in client.shares()] == [sent.id]

    events = client.audit(sent)
    assert [e.action for e in events] == ["created", "downloaded"]
    assert events[1].country == "NO"
    # The format the SERVICE emits (toCsv in app/src/http.ts), not one the stub
    # made up: ISO timestamps rather than epoch seconds, and CRLF per RFC 4180.
    csv = client.audit_csv(sent)
    assert csv.startswith("share_id,timestamp_utc,action,country\r\n"), csv[:80]
    assert "2023-11-14T22:13:20.000Z" in csv, "timestamps are not ISO 8601"
    assert csv.endswith("\r\n")


def test_health(client: Sikkerfil) -> None:
    assert client.health() is True


def test_inspect_reports_metadata_without_downloading(client: Sikkerfil, stub) -> None:
    sent = client.send(PLAINTEXT, filename="x.pdf", max_downloads=3)
    before = len(stub.objects)
    share = client.inspect(sent.url)
    assert share.downloads_remaining == 3
    assert share.password_required is False
    # The name is there but sealed — the service holds ciphertext, not a name.
    assert share.encrypted_name and "x.pdf" not in share.encrypted_name
    assert len(stub.objects) == before


def test_a_client_is_configured_from_the_environment(monkeypatch, stub) -> None:
    monkeypatch.setenv("SIKKERFIL_API_KEY", API_KEY)
    monkeypatch.setenv("SIKKERFIL_BASE_URL", stub.base_url)
    client = Sikkerfil()
    assert client.api_key == API_KEY
    assert client.base_url == stub.base_url


def test_market_and_base_url_together_is_refused() -> None:
    # They contradict each other and silently preferring one is how somebody
    # ships to the wrong market.
    with pytest.raises(ConfigurationError, match="not both"):
        Sikkerfil(api_key=API_KEY, market="se", base_url="https://example.test")


def test_the_key_opens_the_file_however_it_is_spelled(client: Sikkerfil, stub) -> None:
    """One key has three spellings, and a caller holds whichever they were handed.

    ``SentShare.key`` is base64url text, ``Sealed.key`` and ``new_key()`` are raw
    bytes, and a key that has been through a config file or a shell variable may
    have kept its ``=`` padding. All three are the same key. Only one of them used
    to work here.
    """
    sent = client.send(PLAINTEXT, filename="rapport.pdf")
    raw = crypto.b64url_decode(sent.key)

    for spelling in (sent.key, raw, sent.key + "="):
        got = client.receive(sent.id, key=spelling)
        assert got.data == PLAINTEXT, f"{type(spelling).__name__} did not open the file"


def test_the_same_key_twice_is_not_two_different_keys(client: Sikkerfil, stub) -> None:
    """The link's fragment and ``key=`` agreeing must not read as a contradiction.

    The check compared the spellings rather than the keys, so passing the bytes of
    the very key in the link — or the same text with its padding — was reported as
    two different keys. A correct caller was told they had made a mistake.
    """
    sent = client.send(PLAINTEXT, filename="rapport.pdf")
    raw = crypto.b64url_decode(sent.key)

    assert client.receive(sent.url, key=raw).data == PLAINTEXT
    assert client.receive(sent.url, key=sent.key + "=").data == PLAINTEXT


def test_two_genuinely_different_keys_are_still_refused(client: Sikkerfil, stub) -> None:
    # The check must still do its job: one of them opens the file and the other
    # does not, and choosing silently means debugging a decryption failure.
    sent = client.send(PLAINTEXT, filename="rapport.pdf")
    with pytest.raises(ConfigurationError, match="two different keys"):
        client.receive(sent.url, key=crypto.new_key())


def test_a_key_that_opens_nothing_is_refused_before_any_request(
    client: Sikkerfil, stub
) -> None:
    """It used to reach the service first and then raise TypeError from inside
    crypto — a traceback about concatenating str to bytes, for a caller who passed
    a key of the wrong size."""
    before = len(stub.requests)
    with pytest.raises(ConfigurationError, match="32 bytes"):
        client.receive("ABCD1234", key=b"too short")
    assert len(stub.requests) == before, "it spoke to the service before checking the key"


@pytest.mark.parametrize("trailing", ["\n", "\r\n", " ", "   "])
def test_a_key_pasted_with_whitespace_still_opens_the_file(
    client: Sikkerfil, stub, trailing: str
) -> None:
    """receive() used to .strip() the key; moving that into key_text dropped it.

    This is the case Codex named: key=sent.key + "\\n", which is what you get
    from a terminal, a readline() or a config file. Whether it worked depended on
    how many whitespace characters there were modulo four, because base64
    decoding discards them but counts them when checking padding.
    """
    sent = client.send(PLAINTEXT, filename="rapport.pdf")
    assert client.receive(sent.id, key=sent.key + trailing).data == PLAINTEXT


def test_a_key_shaped_filename_is_not_echoed_but_the_path_around_it_is(
    client: Sikkerfil, tmp_path
) -> None:
    """A path must normally print; a key must never. Settled per COMPONENT.

    "no such file" without the name is the commonest error this library raises, so
    refusing the whole string is not an option. Only a component that could carry
    most of a key is replaced, and the directories the caller typed still print —
    which is usually the half of the message that identifies the mistake anyway.
    """
    key_shaped = crypto.b64url_encode(bytes(range(32)))

    with pytest.raises(ConfigurationError) as caught:
        client.send(str(tmp_path / key_shaped))
    message = str(caught.value)
    assert key_shaped[:12] not in message, message
    assert "43 characters" in message, "it did not say what it withheld"
    # The directories are still there, or the message identifies nothing.
    assert str(tmp_path) in message, message


@pytest.mark.parametrize(
    "path",
    [
        "rapport.pdf",
        "data/2026/kvartalsrapport.pdf",
        "/home/user/Documents/rapport.pdf",
        "/tmp/pytest-of-user/pytest-63/test_send0/x",  # this suite's own tmp_path shape
        "kvartalsrapport",  # no extension, fifteen characters
    ],
)
def test_an_ordinary_missing_file_is_still_named_in_full(
    client: Sikkerfil, path: str
) -> None:
    """The redaction must not swallow the normal case, which it did once.

    With the value threshold (twelve) applied to path components, "pytest-of-user"
    and "test_the_absolute_path_esc0" were both replaced by their lengths — so this
    suite's own temporary directories came back unreadable. A path component gets
    the higher PATH_RUN threshold for exactly that reason, and these are the shapes
    that proved it was needed.
    """
    with pytest.raises(ConfigurationError) as caught:
        client.send(path)
    assert path in str(caught.value), str(caught.value)


def test_the_shares_own_key_passed_as_its_write_token_is_refused(client: Sikkerfil) -> None:
    """The column mix-up, caught where both values are in hand.

    ``wt_`` in front of a real token means transport can refuse a key on a credential
    header by shape alone — but only because the service was changed to mint it
    (sikkerfil#62). This guard does not depend on that: SentShare carries the key and
    the token, so the two can be compared rather than recognised, and the message can
    say which of them was handed over.

    Every spelling of the key, because one key has three and a caller holds whichever
    they were given: bytes are not the mistake anyone makes here, but a padded or
    line-wrapped paste out of a config file is.
    """
    sent = client.send(PLAINTEXT, filename="rapport.pdf")
    for spelling in (sent.key, sent.key + "=", sent.key[:21] + "\n" + sent.key[21:]):
        # THE PHRASE IS THE POINT, and the first version of this test did not have
        # it: transport's own refusal also contains "DECRYPTION KEY", so matching on
        # that alone passed with this guard deleted. "this share's" is only sayable
        # where the share's key is in hand — which is the thing under test.
        with pytest.raises(ConfigurationError, match=r"this share's DECRYPTION KEY") as caught:
            client.revoke(sent, write_token=spelling)
        # And the message does not repeat the thing it is refusing.
        assert sent.key not in str(caught.value)
        assert sent.key[:12] not in str(caught.value)

    # The share is still revocable with the token it was actually issued.
    client.revoke(sent)


@pytest.mark.parametrize("slot", ["name", "content_type", "password"])
def test_a_key_in_a_send_parameter_never_reaches_the_body(
    slot: str, client: Sikkerfil, stub
) -> None:
    """THE BODY IS THE WIRE TOO.

    ``name``, ``content_type`` and ``password`` go to the service as they were given,
    in the JSON that creates the share. The credential headers were guarded and these
    were not, so ``send(data, name=<the key>)`` posted the decryption key beside the
    size and the expiry — to the one party the whole design exists to keep it from.

    With an affix, because that is where "only a value that IS a key" broke: a key
    with ``user:`` in front of it or ``-old`` after it is not a key to a strict
    comparison, and carries all 256 bits regardless.
    """
    key = crypto.new_key()
    text = crypto.b64url_encode(key)
    before = len(stub.requests)
    for spelling in (text, f"user:{text}", f"{text}-old", text + "=="):
        given: dict[str, Any] = {slot: spelling}
        with pytest.raises(ConfigurationError) as caught:
            client.send(PLAINTEXT, **given)
        assert text not in str(caught.value)
        assert "decryption key" in str(caught.value)
    assert len(stub.requests) == before, "the share was created before the refusal"

    # And an ordinary value of each still goes through, or the guard has taken the
    # feature away rather than protected it.
    ordinary: dict[str, Any] = {
        slot: {
            "name": "kvartalsrapport-2026-q3",
            "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "password": "hemmelig-passord",
        }[slot]
    }
    client.send(PLAINTEXT, **ordinary)


def test_a_key_as_the_receive_password_never_reaches_the_download(
    client: Sikkerfil, stub
) -> None:
    """THE LIKELIER OF THE TWO MIX-UPS, and the one the send() guard did not cover.

    A recipient holds a link and a password in the same hand, so
    ``receive(link, password=<the link's own key>)`` is an ordinary slip — and it
    posted the key that opens the file to the service that stores it, in the request
    that asks for it. Only send()'s three parameters were guarded.

    Checked against the stub rather than a dead port, because receive() reads the
    share's metadata first: pointed at a closed socket it fails on that request and
    never assembles the download body, which is why this leak did not show up in the
    sweep's own network-refusing fixture.
    """
    sent = client.send(PLAINTEXT, filename="rapport.pdf")
    before = len(stub.requests)
    for spelling in (sent.key, f"user:{sent.key}", sent.key + "-old"):
        with pytest.raises(ConfigurationError) as caught:
            client.receive(sent.url, password=spelling)
        assert "decryption key" in str(caught.value)
        assert sent.key not in str(caught.value)
    assert len(stub.requests) == before, "a request went out before the refusal"

    # A password that is a password still gets through to the service.
    with contextlib.suppress(Exception):
        client.receive(sent.url, password="hemmelig")
    posted = [r for r in stub.requests[before:] if r.body and b"hemmelig" in r.body]
    assert posted, "an ordinary password no longer reaches the download"


@pytest.mark.parametrize(
    "spelling",
    [
        ("A" * 10 + "/") * 3 + "A" * 10,  # standard base64's alphabet
        ("A" * 10 + "+") * 3 + "A" * 10,
    ],
)
def test_a_standard_base64_key_never_reaches_a_request_body(
    spelling: str, client: Sikkerfil, stub
) -> None:
    """THE WIRING, not the predicate.

    ``opaque_carries_key_material`` had a test and the three call sites did not, so
    swapping them back to the path predicate — which splits on "/" and reads this as
    four short components — broke nothing at all. The predicate being right is not
    the property; what send() and receive() actually ask is.
    """
    before = len(stub.requests)
    for slot in ("password", "name", "content_type"):
        given: dict[str, Any] = {slot: spelling}
        with pytest.raises(ConfigurationError):
            client.send(PLAINTEXT, **given)
    assert len(stub.requests) == before

    sent = client.send(PLAINTEXT, filename="rapport.pdf")
    before = len(stub.requests)
    with pytest.raises(ConfigurationError):
        client.receive(sent.url, password=spelling)
    assert len(stub.requests) == before


def test_a_long_registered_content_type_reaches_the_service(client: Sikkerfil, stub) -> None:
    """THROUGH send(), not through the predicate.

    ``mimetypes.guess_type("x.cii")`` returns a 54-character media type, and the run
    threshold refused it — while leaving the argument out sent the identical value,
    because ``_guess_type`` generates it. A guard that refuses what the library itself
    produces is a bug with a security-shaped excuse.

    The predicate had a test and this call site did not, so swapping the check back to
    the run heuristic broke nothing.
    """
    import mimetypes

    guessed = mimetypes.guess_type("x.cii")[0]
    assert guessed and len(guessed) > 32

    client.send(PLAINTEXT, filename="x.cii", content_type=guessed)
    created = json.loads(stub.requests[-3].body)
    assert created["contentType"] == guessed

    # Leaving it out sends the same thing, which is the inconsistency that made the
    # refusal indefensible.
    client.send(PLAINTEXT, filename="x.cii")
    assert json.loads(stub.requests[-3].body)["contentType"] == guessed

    # A key with a separator pushed into it is still refused: the grammar accepts it
    # and deleting the slash gives back the key.
    key = crypto.b64url_encode(bytes(range(32)))
    for shaped in (f"{key[:20]}/{key[20:]}", key, "A" * 20 + "/" + "A" * 22):
        with pytest.raises(ConfigurationError):
            client.send(PLAINTEXT, content_type=shaped)


def test_a_parameterised_content_type_reaches_the_service(client: Sikkerfil, stub) -> None:
    """``text/plain; charset=utf-8`` is an ordinary Content-Type.

    My first version of the media-type grammar took only the bare type/subtype, so
    fixing one over-refusal in this parameter introduced another one round later.

    And allowing parameters opens a place to put a key that none of the other
    questions reach — "text/plain; charset=<a key>" is a valid media type and is not
    a rendering of anything as a whole string — so each parameter value is asked
    about on its own. Nobody reported that; it arrived with the fix.
    """
    for accepted in (
        "text/plain; charset=utf-8",
        "text/plain;charset=utf-8",
        'text/csv; charset="utf-8"',
        "multipart/form-data; boundary=----abc",
    ):
        client.send(PLAINTEXT, content_type=accepted)
        assert json.loads(stub.requests[-3].body)["contentType"] == accepted

    key = crypto.b64url_encode(bytes(range(32)))
    before = len(stub.requests)
    for refused in (
        f"text/plain; charset={key}",
        f'text/plain; charset="{key}"',
        f"text/plain; charset={base64.b85encode(bytes(range(32))).decode()}",
        "text/plain; charset",
    ):
        with pytest.raises(ConfigurationError):
            client.send(PLAINTEXT, content_type=refused)
    assert len(stub.requests) == before
