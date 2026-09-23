"""
Saving a received file — where a decrypted filename meets the filesystem.

THE FILENAME IS ATTACKER-CONTROLLED INPUT. It was sealed by whoever sent the
file and is decrypted locally, which means it arrives as a string chosen by
someone else and goes straight into a path join. ``../../.ssh/authorized_keys``
is a perfectly valid sealed name. So is one with a leading dot, or a leading
slash, or backslashes because the sender was on Windows.

This is the one place in the library where a hostile input reaches something
outside the process, so it gets its own file.
"""

from __future__ import annotations

import os

import pytest

from sikkerfil.models import AuditEvent, ReceivedFile, Share

SHARE = Share(
    id="ABCD1234",
    state="ready",
    size_bytes=42,
    content_type="application/pdf",
    expires_at=1_700_086_400,
    downloads_remaining=3,
    password_required=False,
)


def received(filename: str | None) -> ReceivedFile:
    return ReceivedFile(data=b"contents", filename=filename, content_type="x", share=SHARE)


@pytest.mark.parametrize(
    "hostile",
    [
        "../../../etc/passwd",
        "../../.ssh/authorized_keys",
        "/etc/passwd",
        "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "....//....//etc/passwd",
        ".bashrc",
        "..",
        ".",
        "/",
    ],
)
def test_a_hostile_filename_cannot_escape_the_directory(hostile: str, tmp_path) -> None:
    written = received(hostile).save(str(tmp_path))

    parent = os.path.realpath(str(tmp_path))
    assert os.path.realpath(os.path.dirname(written)) == parent, (
        f"{hostile!r} escaped to {written}"
    )
    # And it did not arrive as a dotfile, which is how something lands where
    # nobody looks at it.
    assert not os.path.basename(written).startswith(".")
    assert os.path.isfile(written)


def test_a_tilde_in_the_directory_is_expanded(tmp_path, monkeypatch) -> None:
    """``save("~/Downloads")`` is the obvious thing to write, and the README
    writes it. Unexpanded it creates a directory literally named ``~``, or
    fails outright with a FileNotFoundError that blames the user."""
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "Downloads").mkdir()

    written = received("rapport.pdf").save("~/Downloads")
    assert written == str(tmp_path / "Downloads" / "rapport.pdf")
    assert (tmp_path / "Downloads" / "rapport.pdf").read_bytes() == b"contents"


def test_a_file_with_no_name_still_gets_one(tmp_path) -> None:
    written = received(None).save(str(tmp_path))
    assert os.path.basename(written) == "sikkerfil-ABCD1234.bin"


def test_an_explicit_filename_wins_and_is_still_sanitised(tmp_path) -> None:
    written = received("sealed.pdf").save(str(tmp_path), filename="../mine.pdf")
    assert os.path.basename(written) == "mine.pdf"
    assert os.path.realpath(os.path.dirname(written)) == os.path.realpath(str(tmp_path))


def test_times_come_back_as_aware_datetimes() -> None:
    # Naive datetimes are how a share looks expired to one caller and live to
    # another, depending on the machine's timezone.
    assert SHARE.expires.tzinfo is not None
    assert SHARE.expires.year == 2023
    event = AuditEvent(share_id="ABCD1234", action="downloaded", at=1_700_000_000, country="NO")
    assert event.when.tzinfo is not None


def test_a_share_knows_whether_it_has_bytes_yet() -> None:
    assert SHARE.is_ready is True
    pending = Share(**{**SHARE.__dict__, "state": "pending"})
    assert pending.is_ready is False


def test_a_received_file_reports_its_length() -> None:
    assert len(received("x")) == len(b"contents")


def test_a_rendering_split_across_directory_and_name_is_refused(tmp_path, monkeypatch) -> None:
    """THROUGH save(), not through the predicate.

    The predicate had a test and this call site did not, so deleting the check from
    save() broke nothing at all — the third time on this branch that a fix was held
    only by a test of the thing it calls rather than of the thing that calls it.

    ``b64encode`` of 32 bytes is ``Pz8/Pz8/…/Pz8=``: as a directory and a filename
    neither half carries a key, and the join is the whole reversible rendering.
    """
    import base64

    from sikkerfil.errors import ConfigurationError

    rendering = base64.b64encode(b"?" * 32).decode()
    directory, name = rendering.rsplit("/", 1)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ConfigurationError, match="joined"):
        received(name).save(directory)
    assert not list(tmp_path.iterdir()), "it wrote something before refusing"

    # And an ordinary save into a directory that does not exist yet still fails the
    # way it always did — as a filesystem error naming the path, not as a refusal.
    with pytest.raises(FileNotFoundError):
        received("rapport.pdf").save(str(tmp_path / "nope"))
