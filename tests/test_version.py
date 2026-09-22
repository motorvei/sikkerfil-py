"""
THE VERSION LIVES IN THREE PLACES AND THEY MUST AGREE.

pyproject.toml is what a wheel is built from. sikkerfil.__version__ is what a
caller reads at runtime and what a bug report quotes. uv.lock records the project
as an editable entry, and `uv sync --frozen` / `uv run --frozen` trust it — so a
stale lock makes those commands resolve the *previous* release while claiming to
honour the committed one.

HOW IT WENT WRONG, twice, and why a test rather than care: the release sequence
was `uv run pytest` (which refreshes the lock to whatever the version is NOW),
then bump pyproject and __version__, then commit. The lock therefore captured the
number from before the bump, every time the bump came last. Nothing failed, the
wheel built, the tests passed, and the mismatch shipped. Only reading all three
at once shows it, and nobody does that while editing one of them.
"""

from __future__ import annotations

import pathlib
import re

import sikkerfil

ROOT = pathlib.Path(__file__).resolve().parent.parent


def pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"', text, re.M)
    assert match, "pyproject.toml has no top-level version"
    return match.group(1)


def lock_version() -> str:
    """The version uv.lock records for this project's own editable entry.

    Not any dependency's: the file lists twenty packages, and `sikkerfil` is the
    one whose source is `editable = "."`.
    """
    text = (ROOT / "uv.lock").read_text()
    for block in text.split("[[package]]"):
        if re.search(r'^name = "sikkerfil"$', block, re.M) and 'editable = "."' in block:
            match = re.search(r'^version = "([^"]+)"', block, re.M)
            assert match, "the sikkerfil entry in uv.lock has no version"
            return match.group(1)
    raise AssertionError("uv.lock has no editable sikkerfil entry")


def test_all_three_version_sources_agree() -> None:
    sources = {
        "pyproject.toml": pyproject_version(),
        "sikkerfil.__version__": sikkerfil.__version__,
        "uv.lock": lock_version(),
    }
    distinct = set(sources.values())
    assert len(distinct) == 1, (
        "the version disagrees across its three sources:\n"
        + "\n".join(f"  {where:24} {what}" for where, what in sources.items())
        + "\nRun `uv lock` after bumping pyproject.toml and __version__ — never "
        "edit uv.lock by hand."
    )


def test_the_version_looks_like_a_version() -> None:
    # A bump that lands as "0.3.3 " or "v0.3.3" installs and then confuses every
    # tool that compares releases.
    assert re.fullmatch(r"\d+\.\d+\.\d+", sikkerfil.__version__), sikkerfil.__version__
