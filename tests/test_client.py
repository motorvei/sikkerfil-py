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

import json

import pytest

from sikkerfil import Sikkerfil, crypto
from sikkerfil.errors import (
    ConfigurationError,
    DecryptionError,
    DownloadsExhaustedError,
    PasswordRequiredError,
)
from sikkerfil.transport import DIGEST_HEADER, sha256_hex

PLAINTEXT = b"Kvartalsrapport Q3\nOmsetning: 4 200 000 NOK\n"


@pytest.fixture
def client(stub) -> Sikkerfil:
    return Sikkerfil(api_key="sikkerfil_sk_" + "a" * 43, base_url=stub.base_url, retries=0)


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
    created = json.loads(next(r for r in stub.requests if r.path == "/api/shares").body)
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
    created = json.loads(next(r for r in stub.requests if r.path == "/api/shares").body)
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
    created = json.loads(next(r for r in stub.requests if r.path == "/api/shares").body)
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
    client = Sikkerfil(api_key="k", base_url=stub.base_url, retries=0)
    client.send(PLAINTEXT)
    created = json.loads(next(r for r in stub.requests if r.path == "/api/shares").body)
    assert "origin" not in created

    from sikkerfil.client import Sikkerfil as Real

    real = Real(api_key="k", market="dk")
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
    with pytest.raises(ConfigurationError, match="no key"):
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
    assert "share,action" in client.audit_csv(sent)


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
    monkeypatch.setenv("SIKKERFIL_API_KEY", "sikkerfil_sk_from_env")
    monkeypatch.setenv("SIKKERFIL_BASE_URL", stub.base_url)
    client = Sikkerfil()
    assert client.api_key == "sikkerfil_sk_from_env"
    assert client.base_url == stub.base_url


def test_market_and_base_url_together_is_refused() -> None:
    # They contradict each other and silently preferring one is how somebody
    # ships to the wrong market.
    with pytest.raises(ConfigurationError, match="not both"):
        Sikkerfil(api_key="k", market="se", base_url="https://example.test")
