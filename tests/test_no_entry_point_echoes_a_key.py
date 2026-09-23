"""
THE PROOF I DID NOT HAVE, in place of a case list I kept getting wrong.

Five reviews in a row found a place a key could be read back, and every time the
fix was right and my ENUMERATION was what had failed: I covered the fragment and
not the path, the root path and not ``/s/``, the path and not the host,
``key_text`` and not ``b64url_decode``. Each round I added the case I was shown
and believed the set was closed.

So this does not enumerate. It walks the public surface, hands a key to every
string parameter of every callable in turn, and reads everything an application
could end up logging: the message, the ``repr``, the whole
``__cause__``/``__context__`` chain including each exception's own ATTRIBUTES,
and stdout and stderr.

ITS FIRST VERSION MISSED TWO LEAKS A REVIEW THEN FOUND IN MINUTES, and both
reasons are what this file is now most careful about:

  - IT PASSED ONLY VALID KEYS. The code that echoes runs on REFUSAL, and a valid
    key is accepted — so the messages that reproduce one were never reached.
    Every variant below is a near miss: it carries the key and is not one.
  - IT LEFT OPTIONAL PARAMETERS UNSET. ``revoke(share, *, write_token=None)``
    refused for a missing token long before reaching the line that echoed the
    share. Each call is made twice now, once with the optional arguments filled.
"""

from __future__ import annotations

import collections.abc
import contextlib
import functools
import inspect as pyinspect
import io
import typing
from typing import Any

import pytest

import sikkerfil
from sikkerfil import cli, crypto, links

#: The key this file hunts for. Every variant is derived from it, and it is always
#: what the search looks for — the point of "a character short" is that 42 of 43
#: characters came back out.
BASE = crypto.b64url_encode(bytes(range(32)))

#: No uppercase at all, so lowercasing changes nothing about it. Constructed rather
#: than searched for: about one random key in ten billion looks like this. It exists
#: because ``urlsplit().hostname`` lowercases, and a leak that arrives lowercased is
#: still a leak — capitalisation is a few billion offline guesses, not a wall.
LOWERCASE = crypto.key_text("abcdefghijklmnopqrstuvwxyz0123456789-_abcde")

#: What a real mistake hands the library. NONE OF THESE IS A KEY, which is the
#: point: each one reaches a refusal, and each still carries enough of a key to be
#: worth having.
KEYS = {
    "the key itself": BASE,
    "all lowercase": LOWERCASE,
    "a character short": BASE[:-1],
    "a smart quote in it": BASE[:-1] + chr(0x2019),
    "non-ASCII in it": BASE[:-1] + "ø",
    "as a hostname label": BASE + ".example",
    "as userinfo": "user:" + BASE,
    "with a suffix": BASE + "-old",
}

#: One definition, in the library, of how long a run has to be to matter — so what
#: the code refuses to echo and what this file calls a leak cannot drift apart.
RUN = links.KEY_RUN

#: Plausible values for the parameters that gate a call, so filling them reaches the
#: code under test instead of stopping at the door.
_PLAUSIBLE = {
    "write_token": "wt_" + "y" * 20,
    "password": "hemmelig",
    "market": "no",
    "api_key": "sikkerfil_sk_" + "x" * 43,
    "filename": "rapport.pdf",
    "content_type": "application/pdf",
    "directory": ".",
}


#: Functions whose RETURN VALUE is key material on purpose, exempt from the
#: return-value check only — their messages and exceptions are read like everything
#: else's.
#:
#: BY FUNCTION, NOT BY NAME. The first version listed labels, and missed that
#: ``key_text`` is re-exported and reachable as both ``crypto.key_text`` and
#: ``links.key_text`` — the exemption applied to one spelling and the sweep failed
#: on the other. Identity covers every re-export for free.
#:
#: A LIST LIKE THIS IS WHERE FAILURES HIDE, so it is closed and every entry is a
#: function whose whole job is to hand back a key: two spell one, one canonicalises
#: one, and ``build_link`` assembles a link that carries one — which is what a link
#: IS. Private helpers are skipped separately, because no caller holds their
#: results; ``_key_from_fragment`` is the reason that rule exists.
_RETURNS_KEY_MATERIAL = frozenset(
    {
        crypto.key_text,
        crypto.b64url_encode,
        crypto.b64url_decode,
        links.build_link,
    }
)


def _chain(exc: BaseException) -> str:
    """Everything a tracker could read off this exception, lowercased.

    THE CHAIN AND THE ATTRIBUTES, not just the message. ``base_url_for`` had a
    clean message and a ``KeyError`` on ``__context__`` holding the key. A
    ``UnicodeEncodeError`` carries the whole rejected string on ``.object``, where
    neither ``str()`` nor the message shows it. ``from None`` suppresses the
    formatted display of a context; it does not remove the object.
    """
    parts: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(f"{type(current).__name__}: {current}")
        parts.append(repr(current))
        for attribute in ("object", "args", "filename", "filename2", "reason"):
            value = getattr(current, attribute, None)
            if value is not None:
                parts.append(repr(value))
        current = current.__cause__ or current.__context__
    return "\n".join(parts).lower()


def _callables() -> list[tuple[str, Any]]:
    """Every public function, the client's methods, and the helper modules."""
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
    and looked for "str", which silently skipped ``send(source: FileSource)`` — an
    alias whose name does not contain the word, and the one slot where this sweep
    found a real leak. The filter would have hidden the finding.
    """
    if annotation is str:
        return True
    args = typing.get_args(annotation)
    return any(_takes_a_string(arg) for arg in args) if args else False


#: ``main(argv)`` takes a SEQUENCE of strings. Handing it one makes argparse iterate
#: the characters and complain about 'a' — noise, and noise is how a sweep like this
#: gets deleted rather than fixed.
_CONTAINERS = (list, tuple, set, frozenset)


@functools.cache
def _hints(fn: Any) -> tuple[tuple[str, Any], ...]:
    """Resolved annotations as pairs, or empty when resolution failed.

    Failure is REPORTED rather than swallowed: an earlier version returned nothing
    and silently dropped the whole callable out of the sweep. A sweep that quietly
    stops covering things is worse than no sweep.
    """
    try:
        return tuple(typing.get_type_hints(fn).items())
    except Exception:
        return ()


def _hint_map(fn: Any) -> dict[str, Any]:
    return dict(_hints(fn))


def _string_parameters(fn: Any) -> tuple[list[str], bool]:
    """The parameters that take a string, and whether annotations resolved."""
    try:
        signature = pyinspect.signature(fn)
    except (TypeError, ValueError):
        return [], True
    hints = _hint_map(fn)
    resolved = bool(hints) or not signature.parameters
    chosen = []
    for parameter in signature.parameters.values():
        if parameter.kind not in (parameter.POSITIONAL_OR_KEYWORD, parameter.KEYWORD_ONLY):
            continue
        if parameter.name == "self":
            continue
        annotation = hints.get(parameter.name, parameter.annotation)
        origin = typing.get_origin(annotation)
        if origin in _CONTAINERS or origin is collections.abc.Sequence:
            continue
        if isinstance(annotation, str):  # an unresolvable forward reference
            continue
        if _takes_a_string(annotation):
            chosen.append(parameter.name)
    return chosen, resolved


@pytest.mark.parametrize("spelling", list(KEYS), ids=list(KEYS))
def test_no_public_entry_point_echoes_a_key_it_was_handed(spelling: str) -> None:
    handed = KEYS[spelling]
    # Always hunt for the REAL key, whatever variant went in.
    key = LOWERCASE if spelling == "all lowercase" else BASE

    targets = _callables()
    assert len(targets) >= 20, f"only {len(targets)} callables found — the scan is broken"

    calls = raised = 0
    reached: set[str] = set()
    unresolved: list[str] = []
    leaked: list[str] = []

    for label, fn in targets:
        try:
            signature = pyinspect.signature(fn)
        except (TypeError, ValueError):
            continue
        parameters, resolved = _string_parameters(fn)
        if not resolved and signature.parameters:
            unresolved.append(label)

        for parameter in parameters:
            # BOTH SHAPES OF CALL: an early gate hid everything behind it.
            for fill_optional in (False, True):
                arguments: dict[str, Any] = {}
                for candidate in signature.parameters.values():
                    if candidate.name == "self":
                        continue
                    if candidate.name == parameter:
                        arguments[candidate.name] = handed
                    elif candidate.default is candidate.empty or (fill_optional and _takes_a_string(
                        _hint_map(fn).get(candidate.name, candidate.annotation)
                    )):
                        arguments[candidate.name] = _PLAUSIBLE.get(candidate.name, "ABCD1234")

                # STDOUT AND STDERR TOO: the CLI writes its refusals there and
                # exits, carrying nothing at all in the exception.
                out, err = io.StringIO(), io.StringIO()
                written = ""
                calls += 1
                try:
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        result = fn(**arguments)
                except KeyboardInterrupt:  # never ours to swallow
                    raise
                except BaseException as exc:
                    # BaseException because argparse raises SystemExit, which is not
                    # an Exception — and which aborted this loop before it was
                    # caught, silently ending the sweep partway through.
                    raised += 1
                    reached.add(f"{label}({parameter})")
                    written = _chain(exc)
                else:
                    # WHAT A SUCCESSFUL CALL HANDS BACK, which this did not look at
                    # until reverting a fix produced no failures at all. parse_link
                    # of a valid link SUCCEEDS, so nothing raised and nothing was
                    # read — and the ParsedLink it returned printed the key from its
                    # generated repr. An object a caller holds is as loggable as a
                    # message, and more likely to be logged.
                    if fn not in _RETURNS_KEY_MATERIAL and "._" not in label:
                        written = repr(result).lower()
                written += "\n" + out.getvalue().lower() + err.getvalue().lower()

                if any(key[i : i + RUN].lower() in written for i in range(len(key) - RUN + 1)):
                    leaked.append(f"{label}({parameter}=<{spelling}>)")

    # A sweep where nothing refused anything would pass while testing nothing.
    assert raised >= 40, f"only {raised} of {calls} calls raised — refusals are not reached"
    assert not unresolved, "annotations did not resolve, so these went unswept:\n  " + "\n  ".join(
        unresolved
    )

    # Named anchors, so a sweep that quietly stops reaching things says so. Each is a
    # slot a key has actually been mispasted into, or plainly could be.
    for anchor in (
        "sikkerfil.receive(link)",
        "sikkerfil.inspect(link)",
        "Sikkerfil.send(source)",
        "Sikkerfil.revoke(share)",
        "Sikkerfil.audit(share)",
        "sikkerfil.links.base_url_for(market)",
        "sikkerfil.cli.duration(text)",
    ):
        assert anchor in reached, f"the sweep no longer reaches {anchor}"

    assert not leaked, "these echoed the key they were handed:\n  " + "\n  ".join(
        sorted(set(leaked))
    )
