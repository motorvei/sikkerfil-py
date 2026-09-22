"""
THE KEY DOES NOT HAVE TO ARRIVE GLUED TO A URL.

A recipient holds a link, so the link works. But a SENDER who kept the share has
the id and the key in two columns — SentShare hands them over separately, which
is an invitation to store them that way — and until this existed there was no
way to hand them back. The only route was to rebuild a URL by string-concatenation,
which nothing documented.

AND THE DOMAIN WAS NEVER ROUTING. One CloudFront distribution serves
sikkerfil.no, sakerfil.se and sikkerfil.dk from one table, with Host excluded
from the cache key, so any market answers for any share. The origin is the
client's business; the link only has to supply the id and, if the caller has not
kept it, the key.
"""

from __future__ import annotations

import pytest

from sikkerfil import Sikkerfil, crypto
from sikkerfil.errors import ConfigurationError

PLAINTEXT = b"Kvartalsrapport Q3"


@pytest.fixture
def client(stub) -> Sikkerfil:
    return Sikkerfil(api_key="sikkerfil_sk_" + "a" * 43, base_url=stub.base_url, retries=0)


def test_an_id_and_a_key_are_enough(client: Sikkerfil) -> None:
    """The case the API had no answer for. No URL is constructed anywhere."""
    sent = client.send(PLAINTEXT, filename="rapport.pdf")

    got = client.receive(sent.id, key=sent.key)
    assert got.data == PLAINTEXT
    assert got.filename == "rapport.pdf"


def test_what_sentshare_hands_you_is_what_receive_takes_back(client: Sikkerfil) -> None:
    # The round trip through the two attributes a caller would put in a database,
    # rather than through the one string they would give a recipient.
    sent = client.send(PLAINTEXT)
    stored = {"id": sent.id, "key": sent.key}

    assert client.receive(stored["id"], key=stored["key"]).data == PLAINTEXT


def test_the_link_still_works_on_its_own(client: Sikkerfil) -> None:
    sent = client.send(PLAINTEXT)
    assert client.receive(sent.url).data == PLAINTEXT


def test_a_link_with_the_fragment_stripped_plus_a_key(client: Sikkerfil) -> None:
    # Exactly what a shell leaves behind when the link was not quoted: the '#'
    # started a comment. The caller who still has the key can now recover.
    sent = client.send(PLAINTEXT)
    truncated = sent.url.split("#")[0]
    assert client.receive(truncated, key=sent.key).data == PLAINTEXT


def test_two_different_keys_is_a_refusal_rather_than_a_precedence_rule(
    client: Sikkerfil,
) -> None:
    """One of them opens the file and the other does not.

    Picking silently means the caller debugs a decryption failure instead of the
    typo they actually made.
    """
    sent = client.send(PLAINTEXT)
    other = crypto.b64url_encode(crypto.new_key())

    with pytest.raises(ConfigurationError, match="two different keys"):
        client.receive(sent.url, key=other)

    # The same key in both places is not a contradiction, so it is allowed.
    assert client.receive(sent.url, key=sent.key).data == PLAINTEXT


def test_no_key_anywhere_names_both_ways_out(client: Sikkerfil) -> None:
    sent = client.send(PLAINTEXT)
    with pytest.raises(ConfigurationError) as caught:
        client.receive(sent.url.split("#")[0])

    message = str(caught.value)
    assert "key=" in message, "the error does not mention passing the key directly"
    assert "Recipient" in message and "Sender" in message, "it addresses only one of them"
    assert "comment" in message, "it does not warn about the unquoted '#' in a shell"


def test_a_named_share_resolves_from_its_name_plus_a_key(client: Sikkerfil) -> None:
    sent = client.send(PLAINTEXT, name="kvartalsrapport")
    assert client.receive("kvartalsrapport", key=sent.key).data == PLAINTEXT


def test_the_market_picks_the_front_door_not_the_share(monkeypatch) -> None:
    # Any market answers for any share, so this only decides which host is
    # dialled — never whether the share is found.
    monkeypatch.delenv("SIKKERFIL_BASE_URL", raising=False)
    from sikkerfil.client import _client_for

    assert _client_for("ABCD1234", 30.0, "dk").base_url == "https://sikkerfil.dk"
    assert _client_for("ABCD1234", 30.0, "se").base_url == "https://sakerfil.se"
    # A link that names an origin still wins when no market is given.
    assert (
        _client_for("https://sakerfil.se/s/ABCD1234#k=x", 30.0).base_url
        == "https://sakerfil.se"
    )


def test_a_stray_key_is_trimmed(client: Sikkerfil) -> None:
    # Copied out of a config file or a terminal, a key arrives with whitespace
    # more often than not. Refusing a correct key over that is not a security
    # property.
    sent = client.send(PLAINTEXT)
    assert client.receive(sent.id, key=f"  {sent.key}\n").data == PLAINTEXT
