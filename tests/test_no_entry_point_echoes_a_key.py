"""
THE PROOF I DID NOT HAVE, in place of a case list I kept getting wrong.

Four reviews in a row found a place a key reached an error message, and every
time the fix was right and my ENUMERATION was what had failed: I covered the
fragment and not the path, the root path and not ``/s/``, the path and not the
host. Each round I added the case I was shown and believed the set was closed.

So this does not enumerate. It walks the public surface, puts a real key in
every string parameter of every callable in turn, and checks every exception it
raises — message, ``repr``, and the whole ``__cause__``/``__context__`` chain —
for any run of that key. A new entry point that echoes its argument fails this
without anyone remembering to add it, which is the only property worth having
after four rounds of remembering badly.

BOTH SPELLINGS, because case is not redaction: ``urlsplit().hostname``
lowercases, and a leak that arrives lowercased is still a leak worth a few
billion offline guesses. One key is ordinary; the other is constructed so that
its base64url spelling has no uppercase to lose.
"""

from __future__ import annotations

import collections.abc
import contextlib
import inspect as pyinspect
import io
import typing
from typing import Any

import pytest

import sikkerfil
from sikkerfil import cli, crypto, links

#: An ordinary key, and one that survives lowercasing intact.
KEYS = {
    "mixed case": crypto.b64url_encode(bytes(range(32))),
    "all lowercase": crypto.key_text("abcdefghijklmnopqrstuvwxyz0123456789-_abcde"),
}

#: Matches the threshold in test_secrets_stay_out_of_messages.py.
RUN = 12


def _chain(exc: BaseException) -> str:
    """Everything a tracker could read off this exception, lowercased.

    The chain matters: ``base_url_for`` had a clean message and a KeyError on
    ``__context__`` holding the key. ``repr`` matters because a dataclass field
    shows up there and not in ``str``.
    """
    seen: set[int] = set()
    parts: list[str] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(f"{type(current).__name__}: {current}")
        parts.append(repr(current))
        current = current.__cause__ or current.__context__
    return "\n".join(parts).lower()


def _callables() -> list[tuple[str, Any]]:
    """Every public function, plus the client's methods and the two helper modules."""
    found: list[tuple[str, Any]] = []
    for name in dir(sikkerfil):
        if name.startswith("_"):
            continue
        obj = getattr(sikkerfil, name)
        if callable(obj) and not isinstance(obj, type):
            found.append((f"sikkerfil.{name}", obj))

    client = sikkerfil.Sikkerfil(api_key="sikkerfil_sk_" + "x" * 43, retries=0)
    for name in dir(client):
        if name.startswith("_"):
            continue
        obj = getattr(client, name)
        if callable(obj):
            found.append((f"Sikkerfil.{name}", obj))

    for module in (links, crypto, cli):
        for name in dir(module):
            obj = getattr(module, name)
            if (
                callable(obj)
                and not isinstance(obj, type)
                and getattr(obj, "__module__", "").startswith("sikkerfil")
            ):
                found.append((f"{module.__name__}.{name}", obj))
    return found


def _takes_a_string(annotation: object) -> bool:
    """Whether a parameter would accept ``str``, through aliases and unions.

    RESOLVED, NOT PATTERN-MATCHED. The first version read the annotation as text
    and looked for "str", which silently skipped ``send(source: FileSource)`` —
    an alias whose name does not contain the word. That is the one slot in this
    sweep where a real leak was found, so the filter that hid it would have hidden
    the finding.
    """
    if annotation is str:
        return True
    args = typing.get_args(annotation)
    return any(_takes_a_string(arg) for arg in args) if args else False


#: ``main(argv)`` takes a SEQUENCE of strings. Handing it one makes argparse iterate
#: the characters and complain about 'a' — noise, and noise is how a sweep like this
#: gets deleted rather than fixed.
_CONTAINERS = (list, tuple, set, frozenset)


def _string_parameters(fn: Any) -> list[str]:
    try:
        signature = pyinspect.signature(fn)
        hints = typing.get_type_hints(fn)
    except (TypeError, ValueError, NameError):
        return []
    chosen = []
    for parameter in signature.parameters.values():
        if parameter.kind not in (parameter.POSITIONAL_OR_KEYWORD, parameter.KEYWORD_ONLY):
            continue
        if parameter.name == "self":
            continue
        annotation = hints.get(parameter.name, parameter.annotation)
        origin = typing.get_origin(annotation)
        if origin in _CONTAINERS or (origin is not None and origin is collections.abc.Sequence):
            continue
        if isinstance(annotation, str):  # an unresolvable forward reference
            continue
        if _takes_a_string(annotation):
            chosen.append(parameter.name)
    return chosen


@pytest.mark.parametrize("spelling", list(KEYS), ids=list(KEYS))
def test_no_public_entry_point_echoes_a_key_it_was_handed(spelling: str) -> None:
    key = KEYS[spelling]
    targets = _callables()
    assert len(targets) >= 20, f"only {len(targets)} callables found — the scan is broken"

    raised = 0
    reached: set[str] = set()
    leaked: list[str] = []

    for label, fn in targets:
        signature = pyinspect.signature(fn)
        for parameter in _string_parameters(fn):
            arguments: dict[str, Any] = {}
            for candidate in signature.parameters.values():
                if candidate.name == "self":
                    continue
                if candidate.name == parameter:
                    arguments[candidate.name] = key
                elif candidate.default is candidate.empty:
                    arguments[candidate.name] = "ABCD1234"

            # STDOUT AND STDERR ARE READ TOO, and not as a nicety: the CLI writes
            # its refusals to stderr and exits, carrying nothing in the exception.
            # An exception-only sweep would have declared the command line clean
            # without reading one of its messages.
            out, err = io.StringIO(), io.StringIO()
            written = ""
            try:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    fn(**arguments)
            except KeyboardInterrupt:  # never ours to swallow
                raise
            except BaseException as exc:
                # BaseException because argparse raises SystemExit, which is not an
                # Exception — and which aborted this loop before it was caught,
                # silently ending the sweep partway through.
                raised += 1
                reached.add(f"{label}({parameter})")
                written = _chain(exc)
            written += "\n" + out.getvalue().lower() + err.getvalue().lower()

            if any(key[i : i + RUN].lower() in written for i in range(len(key) - RUN + 1)):
                leaked.append(f"{label}({parameter}=<key>)")

    # A sweep where nothing refused anything would pass while testing nothing.
    assert raised >= 30, f"only {raised} calls raised — the sweep is not exercising refusals"

    # Named anchors, so a sweep that quietly stops reaching things is visible. Each
    # of these is a slot a key has actually been mispasted into, or could be.
    for anchor in (
        "sikkerfil.receive(link)",
        "sikkerfil.inspect(link)",
        "Sikkerfil.send(source)",
        "sikkerfil.links.base_url_for(market)",
        "sikkerfil.cli.duration(text)",
    ):
        assert anchor in reached, f"the sweep no longer reaches {anchor}"

    assert not leaked, "these echoed the key they were handed:\n  " + "\n  ".join(leaked)
