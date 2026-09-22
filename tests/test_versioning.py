"""
EVERY ADDRESS THIS LIBRARY SENDS CARRIES /api/v1.

The service still answers the unversioned form, as a legacy alias for browser
bundles that were cached before the prefix existed. That alias is what makes
this easy to get wrong: a client that drops the version keeps working, silently,
right up until the alias is removed — and then breaks everywhere at once, in
code nobody has touched for a year.

So the version is not something the tests infer from a request happening to
succeed. It is asserted directly, on the addresses that actually went out.
"""

from __future__ import annotations

import inspect
import re

import pytest

from sikkerfil import Sikkerfil, transport
from sikkerfil import client as client_module
from sikkerfil.transport import API_PREFIX, API_VERSION

PLAINTEXT = b"versioned"


@pytest.fixture
def client(stub) -> Sikkerfil:
    return Sikkerfil(api_key="sikkerfil_sk_" + "a" * 43, base_url=stub.base_url, retries=0)


def test_the_prefix_is_what_the_service_publishes() -> None:
    assert API_VERSION == "v1"
    assert API_PREFIX == "/api/v1"


def test_a_whole_send_and_receive_only_ever_asks_for_v1(client: Sikkerfil, stub) -> None:
    sent = client.send(PLAINTEXT, filename="rapport.pdf")
    client.receive(sent.url)
    client.shares()
    client.audit(sent)

    api_calls = [r.path for r in stub.requests if r.path.startswith("/api")]
    assert len(api_calls) >= 6, f"only {len(api_calls)} API calls seen — the scan looks broken"

    for path in api_calls:
        assert path.startswith(f"{API_PREFIX}/"), (
            f"{path} was sent without the {API_VERSION} prefix. The service still "
            "answers it today as a legacy alias, so this would pass unnoticed "
            "until the alias is removed."
        )


def test_the_named_link_lookup_is_versioned_too(client: Sikkerfil, stub) -> None:
    # A separate path through _resolve, and the one most likely to be missed:
    # it is the only endpoint reached by name rather than by id.
    sent = client.send(PLAINTEXT, name="kvartalsrapport")
    client.receive(sent.url)
    assert any(r.path == f"{API_PREFIX}/navn/kvartalsrapport" for r in stub.requests), (
        "the named-link lookup did not go to the versioned address"
    )


def test_the_csv_export_is_versioned(client: Sikkerfil, stub) -> None:
    # Built from base_url rather than through _url(), so it does not inherit the
    # prefix automatically — exactly the shape that gets left behind.
    sent = client.send(PLAINTEXT)
    client.audit_csv(sent)
    assert any(r.path == f"{API_PREFIX}/shares/{sent.id}/audit.csv" for r in stub.requests)


def test_no_bare_api_path_is_hard_coded_anywhere_in_the_library() -> None:
    """The structural half, which catches an endpoint added later.

    A new call written as ``"/api/shares/..."`` would work against the live
    service and against the stub, and would be found only by reading the diff.
    """
    for module in (client_module, transport):
        source = inspect.getsource(module)
        # Every literal that starts an API path, minus the one constant that is
        # allowed to: API_PREFIX's own definition.
        bare = re.findall(r'["\']/api/(?!v\d)[a-z]', source)
        assert not bare, (
            f"{module.__name__} hard-codes an unversioned API path. Build it from "
            "API_PREFIX instead, so v2 is one edit rather than a search."
        )


def test_the_health_check_is_versioned(client: Sikkerfil, stub) -> None:
    assert client.health() is True
    assert stub.requests[-1].path == f"{API_PREFIX}/health"
