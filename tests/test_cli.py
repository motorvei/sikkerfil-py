"""
The command line, including the failure it exists to explain.

THE UNQUOTED ``#``. In every POSIX shell,

    sikkerfil receive https://sikkerfil.no/s/ABCD1234#k=abc

arrives as ``https://sikkerfil.no/s/ABCD1234`` — the shell started a comment at
the ``#`` and threw the key away before the process began. The resulting "this
link has no key" is true and useless. There is a test for the note that names
it, because the whole value of the note is that it fires at the right moment.
"""

from __future__ import annotations

import argparse
import json

import pytest

from sikkerfil.cli import duration, main
from sikkerfil.crypto import KEY_BYTES, b64url_encode
from sikkerfil.transport import API_PREFIX

#: A key of the real size. "abc" used to do for tests that never decrypt
#: anything, but receive() now refuses a key that cannot open a file BEFORE it
#: makes any request — so a placeholder short-circuits the very thing under test
#: and the test passes for the wrong reason.
A_KEY = b64url_encode(bytes(range(KEY_BYTES)))


@pytest.fixture
def env(monkeypatch, stub):
    monkeypatch.setenv("SIKKERFIL_API_KEY", "sikkerfil_sk_" + "a" * 43)
    monkeypatch.setenv("SIKKERFIL_BASE_URL", stub.base_url)
    return stub


def test_durations() -> None:
    assert duration("90") == 90
    assert duration("30m") == 1800
    assert duration("24h") == 86400
    assert duration("7d") == 604800
    assert duration("2w") == 1209600
    with pytest.raises(argparse.ArgumentTypeError, match="not a duration"):
        duration("soon")


def test_send_then_receive_from_the_command_line(env, tmp_path, capsys) -> None:
    source = tmp_path / "rapport.pdf"
    source.write_bytes(b"%PDF-1.4 kvartalsrapport")

    assert main(["send", str(source), "--json"]) == 0
    sent = json.loads(capsys.readouterr().out)

    out = tmp_path / "out"
    out.mkdir()
    assert main(["receive", sent["url"], "-o", str(out)]) == 0
    written = capsys.readouterr().out.strip()

    # The sealed filename came back, decrypted locally.
    assert written.endswith("rapport.pdf")
    assert (out / "rapport.pdf").read_bytes() == b"%PDF-1.4 kvartalsrapport"


def test_send_prints_the_link_alone_on_stdout(env, tmp_path, capsys) -> None:
    source = tmp_path / "x.txt"
    source.write_bytes(b"hei")
    main(["send", str(source)])
    captured = capsys.readouterr()

    # One line, so `sikkerfil send x | pbcopy` and `$(sikkerfil send x)` both do
    # the obvious thing. Everything else is stderr.
    assert len(captured.out.strip().splitlines()) == 1
    assert captured.out.strip().startswith("http")
    assert "#k=" in captured.out
    assert "write token" in captured.err


def test_the_write_token_warning_is_on_stderr_and_says_it_is_once(
    env, tmp_path, capsys
) -> None:
    source = tmp_path / "x.txt"
    source.write_bytes(b"hei")
    main(["send", str(source)])
    err = capsys.readouterr().err
    assert "issued once" in err
    assert "cannot be recovered" in err


def test_stdin_can_be_sent(env, tmp_path, capsys, monkeypatch) -> None:
    class FakeStdin:
        buffer = type("B", (), {"read": staticmethod(lambda: b"piped bytes")})()

    monkeypatch.setattr("sys.stdin", FakeStdin())
    assert main(["send", "-", "--json"]) == 0
    sent = json.loads(capsys.readouterr().out)
    assert sent["sizeBytes"] == len(b"piped bytes") + 12 + 16


def test_the_unquoted_hash_is_named_by_the_note(env, capsys) -> None:
    # The link with its fragment already eaten, exactly as the shell delivers it.
    main(["receive", "https://sikkerfil.no/s/ABCD1234"])
    err = capsys.readouterr().err
    assert "started a comment" in err, "the note that explains the shell did not fire"
    assert "'<the whole link>'" in err, "the note does not show the fix"


def test_the_note_does_not_fire_on_a_good_link(env, tmp_path, capsys) -> None:
    source = tmp_path / "x.txt"
    source.write_bytes(b"hei")
    main(["send", str(source), "--json"])
    sent = json.loads(capsys.readouterr().out)

    main(["receive", sent["url"], "-o", str(tmp_path)])
    assert "started a comment" not in capsys.readouterr().err


def test_inspect_says_the_filename_is_sealed(env, tmp_path, capsys) -> None:
    source = tmp_path / "lønnsslipp.pdf"
    source.write_bytes(b"x")
    main(["send", str(source), "--json"])
    sent = json.loads(capsys.readouterr().out)

    assert main(["inspect", sent["url"]]) == 0
    out = capsys.readouterr().out
    # The point of the line: a reader must not conclude the field is missing.
    assert "sealed" in out
    assert "lønnsslipp" not in out


def test_list_revoke_and_audit(env, tmp_path, capsys) -> None:
    source = tmp_path / "x.txt"
    source.write_bytes(b"hei")
    main(["send", str(source), "--json"])
    sent = json.loads(capsys.readouterr().out)

    assert main(["list"]) == 0
    assert sent["id"] in capsys.readouterr().out

    assert main(["audit", sent["id"], "--write-token", sent["writeToken"]]) == 0
    assert "created" in capsys.readouterr().out

    assert main(["revoke", sent["id"], "--write-token", sent["writeToken"]]) == 0
    assert "revoked" in capsys.readouterr().out

    assert main(["list"]) == 0
    assert "no live shares" in capsys.readouterr().out


def test_a_service_error_is_one_line_on_stderr_not_a_traceback(env, capsys) -> None:
    # A stack trace in a terminal tells the user we did not anticipate this.
    # The key has to be a real one or this never reaches the service and ends up
    # asserting about a local key error instead — passing, and testing nothing.
    assert main(["receive", f"https://sikkerfil.no/s/NOSUCH01#k={A_KEY}"]) == 1
    err = capsys.readouterr().err
    assert "sikkerfil:" in err
    assert "Traceback" not in err


def test_an_explicit_base_url_beats_the_links_own_origin(env, capsys) -> None:
    """Otherwise the test above would have talked to the live service.

    SIKKERFIL_BASE_URL is set by this fixture, and the link names production.
    Following the link would send a real request to sikkerfil.no — which is how
    a test suite quietly starts depending on someone else's uptime, and how a
    developer pointed at staging ends up writing to production.
    """
    main(["receive", f"https://sikkerfil.no/s/NOSUCH01#k={A_KEY}"])
    reached = [r.path for r in env.requests]
    assert reached, "the request did not go to the stub — it went somewhere else"
    assert reached[-1] == f"{API_PREFIX}/shares/NOSUCH01"
