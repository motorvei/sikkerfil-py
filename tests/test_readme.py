"""
THE README IS DOCUMENTATION THAT ROTS SILENTLY.

Nothing typechecks a code fence. A field renamed in models.py leaves the README
telling people to read an attribute that no longer exists, and the only way that
surfaces is a confused user — which is exactly how two false sentences shipped on
/utviklere in one morning.

So: every fenced Python block must compile, and every attribute the README reads
off a Share or a SentShare must actually be on it.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
import re

from sikkerfil.models import ReceivedFile, SentShare, Share

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"

#: The objects the README walks attributes off, by the variable names it uses.
SUBJECTS = {
    "share": Share,
    "sent": SentShare,
    "file": ReceivedFile,
    "got": ReceivedFile,
}


def python_blocks() -> list[str]:
    return re.findall(r"```python\n(.*?)```", README.read_text(), re.S)


def test_the_readme_has_examples_at_all() -> None:
    blocks = python_blocks()
    assert len(blocks) >= 5, f"only {len(blocks)} python blocks — the scan looks broken"


def test_every_python_block_parses() -> None:
    for i, block in enumerate(python_blocks()):
        try:
            ast.parse(block)
        except SyntaxError as exc:  # pragma: no cover - only on a broken README
            raise AssertionError(f"README python block {i} does not parse: {exc}") from exc


def test_every_attribute_the_readme_reads_exists() -> None:
    """The drift that actually happens: a field renamed, the README left behind."""
    fields = {
        name: {f.name for f in dataclasses.fields(cls)}
        | {a for a in dir(cls) if not a.startswith("_")}
        for name, cls in SUBJECTS.items()
    }

    seen = 0
    for block in python_blocks():
        for node in ast.walk(ast.parse(block)):
            if not isinstance(node, ast.Attribute):
                continue
            if not isinstance(node.value, ast.Name):
                continue
            known = fields.get(node.value.id)
            if known is None:
                continue
            seen += 1
            assert node.attr in known, (
                f"README reads {node.value.id}.{node.attr}, which is not on "
                f"{SUBJECTS[node.value.id].__name__}. Either the README is stale "
                "or the attribute was renamed without it."
            )

    assert seen >= 8, f"only {seen} attribute reads checked — the scan looks broken"


def test_the_readme_does_not_promise_pypi_before_it_exists() -> None:
    """`pip install sikkerfil` is not true yet, and a docs lie costs a week.

    Flip this the day the package is published — the failure message is the
    reminder that both places need changing together.
    """
    text = README.read_text()
    assert "pip install git+https://github.com/motorvei/sikkerfil-py" in text, (
        "the README no longer shows the git install. If sikkerfil is on PyPI now, "
        "update this test and the install line together."
    )
