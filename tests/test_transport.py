"""
EVERY POST MUST CARRY x-amz-content-sha256, and nothing else may build a POST.

THE BUG THIS EXISTS FOR reached production in the web client. CloudFront reaches
the service's Function URL through an origin access control with
``signing_behavior = "always"``, so it signs every origin request with SigV4 —
and SigV4 covers the BODY. The caller supplies the body's digest in
``x-amz-content-sha256`` or that signature cannot be computed, and the edge
refuses the request with

    403  x-amzn-errortype: InvalidSignatureException

before any route runs. Nothing is logged. The caller sees a 403 that explains
nothing. The account-keys form shipped with a bare ``fetch()`` and did exactly
that.

NO FUNCTIONAL TEST IN THIS REPOSITORY CAN CATCH IT. The stub server below will
cheerfully accept a request CloudFront would reject; the signing layer exists
only in production. So the check is structural, in two halves: there is ONE
place that builds a POST, and it computes the digest from the bytes it sends.

The same shape as ``app/src/signing.test.ts`` in the service repository, for the
same reason, because this is the second client and the mistake generalises.
"""

from __future__ import annotations

import base64
import inspect
import re
from typing import TYPE_CHECKING

import pytest

from sikkerfil import transport
from sikkerfil.errors import (
    ApiError,
    AuthenticationError,
    BudgetError,
    ConfigurationError,
    NotFoundError,
    SignatureError,
    TransportError,
)
from sikkerfil.transport import DIGEST_HEADER, Transport, sha256_hex

if TYPE_CHECKING:  # the stub fixture, for the annotations below
    from tests.conftest import StubService

SOURCE = inspect.getsource(transport)


def test_exactly_one_place_builds_a_post() -> None:
    builders = re.findall(r"""["']POST["']""", SOURCE)
    assert len(builders) == 1, (
        f"found {len(builders)} places naming the POST method in transport.py; "
        "there must be exactly one, inside post_json. A POST built anywhere else "
        "omits the digest header and is refused by CloudFront with "
        "InvalidSignatureException before our code runs."
    )
    body = inspect.getsource(Transport.post_json)
    assert '"POST"' in body, "the one POST builder is no longer inside post_json"


def test_post_json_computes_the_digest_from_the_bytes_it_sends() -> None:
    body = inspect.getsource(Transport.post_json)
    assert "DIGEST_HEADER" in body, "post_json no longer sends the digest header"
    assert "sha256_hex(body)" in body, "the digest is not computed from the payload"
    # From the bytes assigned to `body`, which is what goes on the wire — not
    # from the payload dict, which would be a second serialisation and could
    # differ from the first in separators, ordering or encoding.
    assert re.search(r"body = json\.dumps\(.*\)\.encode\(\)", body, re.S), (
        "post_json no longer serialises once into `body`"
    )
    # Computed, not a constant somebody pasted in — including the empty-body
    # digest, which is the plausible wrong answer because it is right until the
    # first request that has a body.
    assert "e3b0c442" not in SOURCE, "a hard-coded empty-body digest appeared"


def test_no_other_method_in_the_module_sends_a_body_without_a_digest() -> None:
    # put_bytes is the one exception and it is allowed, because a presigned S3
    # URL carries its own signature and is not signed by CloudFront's OAC.
    senders = [
        name
        for name, member in vars(Transport).items()
        if callable(member) and not name.startswith("_")
    ]
    assert set(senders) == {
        "get_json",
        "get_bytes",
        "post_json",
        "put_bytes",
        "delete",
    }, f"the transport grew a public method: {senders}. Does it send a body?"


def test_authorization_bearer_appears_nowhere_as_a_credential() -> None:
    """CloudFront REPLACES Authorization with its own signature in transit.

    Documenting it once cost a week on the service side. A client that sent a
    key that way would get a 401 with nothing in any log to explain it.
    """
    # The prose above may — and must — explain why not. What may not appear is
    # the header being SET: an assignment, a dict entry, or an add_header call.
    offenders = [
        line.strip()
        for line in SOURCE.splitlines()
        if re.search(r"""["']authorization["']\s*[:=]""", line, re.I)
        or re.search(r"""add_header\(\s*["']authorization""", line, re.I)
    ]
    assert not offenders, f"transport.py sets an Authorization header: {offenders}"

    # And the credential headers are the two the service actually reads.
    assert transport.KEY_HEADER == "x-sikkerfil-key"
    assert transport.TOKEN_HEADER == "x-sikkerfil-token"


def test_the_digest_is_the_real_sha256() -> None:
    assert sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert sha256_hex(b'{"sizeBytes":1234}') == sha256_hex(b'{"sizeBytes":1234}')
    assert sha256_hex(b"a") != sha256_hex(b"b")


# --- What the header actually ends up as, over a real socket -----------------


def test_a_post_puts_the_digest_of_its_own_body_on_the_wire(stub: StubService) -> None:
    client = Transport(stub.base_url, retries=0)
    client.post_json(
        "/api/shares",
        {"sizeBytes": 1234},
        headers={transport.KEY_HEADER: "sikkerfil_sk_" + "x" * 43},
    )

    request = stub.requests[-1]
    assert request.method == "POST"
    assert request.headers[DIGEST_HEADER] == sha256_hex(request.body)
    # And the digest covers the bytes SENT, not a re-serialisation of them.
    assert request.body == b'{"sizeBytes":1234}'


def test_a_post_with_no_payload_still_carries_a_digest(stub: StubService) -> None:
    # The complete call posts `{}`. An empty body is still a body to SigV4, and
    # this is the call that finishes every upload — it failing is a file nobody
    # can download. The response is scripted so this test is about what LEAVES,
    # not about the stub's routing.
    stub.respond(status=200, body=b"{}", headers={"content-type": "application/json"})
    Transport(stub.base_url, retries=0).post_json("/api/shares/ABCD1234/complete")
    request = stub.requests[-1]
    assert request.body == b"{}"
    assert request.headers[DIGEST_HEADER] == sha256_hex(b"{}")


def test_a_get_sends_no_digest_and_no_body(stub: StubService) -> None:
    # Not a nicety: a GET has no body, so there is nothing to digest, and the
    # documented examples say so. Sending one would be harmless but misleading.
    Transport(stub.base_url, retries=0).get_json("/api/health")
    request = stub.requests[-1]
    assert request.body == b""
    assert DIGEST_HEADER not in request.headers


# --- Refusals become the right exception -------------------------------------


@pytest.mark.parametrize(
    ("status", "body", "headers", "expected"),
    [
        (401, b'{"error":"unauthorized"}', {}, AuthenticationError),
        (403, b'{"error":"session_required"}', {}, AuthenticationError),
        (404, b'{"error":"not_found"}', {}, NotFoundError),
        (400, b'{"error":"too_big","message":"file is larger"}', {}, ApiError),
        (503, b'{"error":"daily_budget_spent"}', {"retry-after": "1800"}, BudgetError),
    ],
)
def test_refusals_map_to_their_meanings(
    stub: StubService,
    status: int,
    body: bytes,
    headers: dict[str, str],
    expected: type[ApiError],
) -> None:
    stub.respond(status=status, body=body, headers=headers)
    with pytest.raises(expected) as caught:
        Transport(stub.base_url, retries=0).get_json("/api/account/shares")
    assert caught.value.status == status


def test_the_edge_refusal_is_told_apart_from_a_bad_credential(stub: StubService) -> None:
    """A 403 from CloudFront is OUR bug; a 403 from the service is the caller's.

    Reporting them identically is how a customer spends an afternoon rotating a
    key that was never the problem.
    """
    stub.respond(
        status=403,
        body=b"",
        headers={"x-amzn-errortype": "InvalidSignatureException", "x-amz-cf-id": "abc123"},
    )
    with pytest.raises(SignatureError) as caught:
        Transport(stub.base_url, retries=0).post_json("/api/shares", {"sizeBytes": 1})

    message = str(caught.value)
    assert DIGEST_HEADER in message, "the message does not name the header at fault"
    assert "bug in sikkerfil-python" in message, "the message blames the caller"
    assert caught.value.request_id == "abc123", "the one id support can search by was dropped"
    # And it is still an AuthenticationError, so a broad except still catches it.
    assert isinstance(caught.value, AuthenticationError)


def test_budget_refusal_carries_the_services_own_advice(stub: StubService) -> None:
    stub.respond(
        status=503, body=b'{"error":"daily_budget_spent"}', headers={"retry-after": "1800"}
    )
    with pytest.raises(BudgetError) as caught:
        Transport(stub.base_url, retries=0).get_json("/api/health")
    assert caught.value.retry_after == 1800


def test_an_unreachable_host_is_a_transport_error_not_an_api_error() -> None:
    # The distinction callers branch on: nothing was answered, so a retry is
    # reasonable. Port 1 is reserved and refuses immediately.
    with pytest.raises(TransportError):
        Transport("http://127.0.0.1:1", retries=0, timeout=2).get_json("/api/health")


def test_a_proxy_answering_html_is_named_as_such(stub: StubService) -> None:
    stub.respond(status=200, body=b"<html>captive portal</html>", headers={})
    with pytest.raises(TransportError) as caught:
        Transport(stub.base_url, retries=0).get_json("/api/health")
    assert "not JSON" in str(caught.value)



# --- What a credential is allowed to look like -------------------------------


def test_the_shape_a_real_write_token_has_is_accepted(stub: StubService) -> None:
    """THE REGRESSION THIS FILE EXISTS TO HOLD ON TO.

    The check on the credential headers once demanded a ``wt_`` prefix at a time
    when the service minted ``randomBytes(32).toString("base64url")`` and nothing
    else — 43 characters, no prefix. Every test here passed, because conftest minted
    ``wt-<id>``; every real caller's first revoke() or audit() would have raised.

    So this test spells out the value the service actually returns, rather than
    trusting a double to have got it right: app/src/ids.ts mints
    ``wt_`` + base64url(32 bytes), and app/src/key-format.ts mints
    ``sikkerfil_sk_`` + base64url(32 bytes). If either changes there, this fails
    here, which is the trade a positive check buys — a visible break rather than a
    silent disclosure.
    """
    token = "wt_" + base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    api_key = "sikkerfil_sk_" + base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    assert len(token) == 46 and len(api_key) == 56

    client = Transport(stub.base_url, retries=0)
    client.get_json("/api/health", headers={transport.TOKEN_HEADER: token})
    assert stub.requests[-1].headers[transport.TOKEN_HEADER] == token
    client.get_json("/api/health", headers={transport.KEY_HEADER: api_key})
    assert stub.requests[-1].headers[transport.KEY_HEADER] == api_key


@pytest.mark.parametrize(
    "value",
    [
        base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),  # a whole key
        "wt_" + "y" * 42,  # one character short
        "wt_" + "y" * 44,  # one too many
        "wt_" + "y" * 42 + "=",  # padded
        "wt_" + "y" * 21 + "+" + "y" * 21,  # standard base64, not base64url
        "wt-" + "y" * 43,  # the shape conftest used to invent
        "sikkerfil_sk_" + "y" * 43,  # an API key is not a write token
        "",
    ],
)
def test_a_value_that_is_not_a_write_token_never_reaches_the_wire(
    value: str, stub: StubService
) -> None:
    """A NEAR MISS IS THE DANGEROUS CASE, not an obviously wrong value.

    A key with its last character dropped is not a key to anything that decodes it,
    and it carries 252 of the key's 256 bits to the service with sixteen completions
    left. Refusing "exactly a key" let every one of these through.
    """
    before = len(stub.requests)
    with pytest.raises(ConfigurationError, match="not shaped like a credential"):
        Transport(stub.base_url, retries=0).get_json(
            "/api/health", headers={transport.TOKEN_HEADER: value}
        )
    assert len(stub.requests) == before, "the value reached the service"


@pytest.mark.parametrize(
    "value",
    [
        base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),  # a whole key
        "sikkerfil_sk_" + "y" * 42,  # one character short
        "sikkerfil_sk_" + "y" * 44,  # one too many
        "sikkerfil_sk" + "y" * 43,  # the underscore missing
        "sikkerfil_sk_",  # the prefix on its own
        "wt_" + "y" * 43,  # a write token is not an API key
        "k",  # what this repository's own fixtures used to pass
    ],
)
def test_a_value_that_is_not_an_api_key_never_reaches_the_wire(
    value: str, stub: StubService
) -> None:
    """The same shape check on the other credential header.

    THE FIXTURES ARE IN THIS LIST ON PURPOSE. Three tests in this repository passed
    ``api_key="k"``, which no service would have accepted — a stand-in that cannot be
    a real value teaches the suite to accept values the service refuses, which is how
    a check on the OTHER header came to demand a prefix nothing minted.
    """
    before = len(stub.requests)
    with pytest.raises(ConfigurationError, match="not shaped like a credential"):
        Transport(stub.base_url, retries=0).get_json(
            "/api/health", headers={transport.KEY_HEADER: value}
        )
    assert len(stub.requests) == before, "the value reached the service"
