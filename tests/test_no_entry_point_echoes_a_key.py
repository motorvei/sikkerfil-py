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
import pathlib
import typing
import unicodedata
import urllib.error
import urllib.request
from typing import Any

import pytest

import sikkerfil
from sikkerfil import cli, crypto, links, models

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
    # SPELLED WITH SPACES, which key_text accepts on purpose and a run-based check
    # could not see: this one was echoed in full, and deleting the spaces gave back
    # a working key. Anything the decoder accepts belongs in this table.
    "spaced between every character": " ".join(BASE),
    "wrapped across two lines": BASE[:20] + "\n" + BASE[20:],
    # FULLWIDTH, which key_text REFUSES — base64 needs ASCII — and which therefore
    # looked safe to print by the old reasoning. It NFKC-folds straight back to a
    # working key, and anybody reading a log can do that fold. "Not a value we would
    # accept" is not the same as "not a disclosure".
    "fullwidth transcription": "".join(
        chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in BASE
    ),
}

#: One definition, in the library, of how long a run has to be to matter — so what
#: the code refuses to echo and what this file calls a leak cannot drift apart.
RUN = links.KEY_RUN

#: Plausible values for the parameters that gate a call, so filling them reaches the
#: code under test instead of stopping at the door.
_PLAUSIBLE: dict[str, Any] = {
    # BYTES, AND NOT A FILENAME, so send() gets past _read_source and assembles a
    # request. With "ABCD1234" here it stopped at a missing file, and send() — which
    # puts three caller-supplied values in the body that creates the share — was
    # swept only as far as its front door. name, content_type and password each sent
    # the key to the service, and this dict is why nothing said so.
    "source": b"payload",
    # THE SHAPE THE SERVICE MINTS: wt_ and 43 characters. A shorter stand-in is
    # refused on the credential header, which stops revoke() and audit() at the
    # header instead of letting the sweep reach what they do with the value.
    "write_token": "wt_" + "y" * 43,
    "password": "hemmelig",
    "market": "no",
    "api_key": "sikkerfil_sk_" + "x" * 43,
    "filename": "rapport.pdf",
    "content_type": "application/pdf",
    # NOT "." — see _sealed_off. The sweep hands a key to this parameter, and a
    # relative directory means the working tree.
    "directory": "written-here",
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


def _leaks_in(text: str, key: str) -> bool:
    """Any run of ``key`` in ``text``, in any spelling a reader could undo.

    Compatibility-normalised as well as raw, for the same reason the library's own
    check is: a fullwidth transcription is not a key the library would accept, and
    folds back to one in a single call. A hunt that reads only the literal spelling
    cannot see the disclosure it is looking for.
    """
    # WHITESPACE OUT OF THE HAYSTACK TOO. The library strips it before decoding, so an
    # entry point that echoes the spaced or wrapped spelling verbatim has disclosed a
    # key the library would accept — and searching only contiguous substrings could not
    # see it. My own predicate had the exact hole I had just fixed in links.py.
    folded = unicodedata.normalize("NFKC", text)
    haystacks = (
        text.lower(),
        folded.lower(),
        "".join(text.split()).lower(),
        "".join(folded.split()).lower(),
    )
    return any(
        key[i : i + RUN].lower() in haystack
        for haystack in haystacks
        for i in range(len(key) - RUN + 1)
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

    # NOT PRODUCTION. With no base_url this client defaulted to https://sikkerfil.no
    # and several generated calls passed validation and went to the WIRE: one run
    # made fourteen real requests to the live service, and every 404 or DNS failure
    # then counted toward "a refusal was reached", so the sweep could look thorough
    # while exercising nothing. 127.0.0.1:9 is the discard port — nothing listens,
    # the connection is refused locally and instantly, and _no_network below turns
    # any request that still escapes into a failure rather than a passing case.
    client = sikkerfil.Sikkerfil(
        api_key="sikkerfil_sk_" + "x" * 43, retries=0, base_url="http://127.0.0.1:9"
    )
    for name in dir(client):
        if name.startswith("_"):
            continue
        obj = getattr(client, name)
        if callable(obj):
            found.append((f"Sikkerfil.{name}", obj))

    # METHODS ON THE OBJECTS THE LIBRARY HANDS BACK. Excluding every class meant
    # the sweep never saw a public method outside Sikkerfil — and ReceivedFile.save
    # takes a DIRECTORY from the caller, which is the receiving-side twin of
    # send(<key>). It raised a FileNotFoundError whose `.filename` held the key,
    # an attribute this file explicitly claims to read. Claiming to read it while
    # never constructing the object that produces it is the kind of coverage that
    # looks thorough on paper.
    share = models.Share(
        id="ABCD1234",
        state="ready",
        size_bytes=1,
        content_type="application/pdf",
        expires_at=0,
        downloads_remaining=None,
        password_required=False,
    )
    instances: list[tuple[str, Any]] = [
        ("ReceivedFile", models.ReceivedFile(b"x", "rapport.pdf", "application/pdf", share)),
        ("Share", share),
        (
            "SentShare",
            models.SentShare(
                id="ABCD1234",
                url="http://127.0.0.1:9/s/ABCD1234#k=" + BASE,
                write_token="wt_" + "y" * 43,
                key=BASE,
                expires_at=0,
                size_bytes=1,
            ),
        ),
        ("Sealed", crypto.seal(b"x")),
    ]
    for kind, instance in instances:
        for name in dir(instance):
            if name.startswith("_"):
                continue
            obj = getattr(instance, name)
            if callable(obj):
                found.append((f"{kind}.{name}", obj))

    # CONSTRUCTORS, which excluding every class also skipped. Sikkerfil(base_url=KEY)
    # reaches urllib and raises ValueError("unknown url type: '<the whole key>/…'") —
    # in the message AND in args — while the sweep stayed green because it only ever
    # built one fixed, safe client. A constructor parameter is a string parameter.
    # NAMED PARAMETERS, not **kwargs: the sweep reads a signature, and a VAR_KEYWORD
    # has no named parameters to substitute into — so the first version of this was
    # skipped silently and the anchor below is what said so.
    def _construct_and_use(
        api_key: str = "sikkerfil_sk_" + "x" * 43,
        base_url: str = "http://127.0.0.1:9",
        market: str | None = None,
    ) -> object:
        """Build a client and make it try ONE request; base_url only bites on use."""
        client = (
            sikkerfil.Sikkerfil(api_key=api_key, market=market, retries=0)
            if market is not None
            else sikkerfil.Sikkerfil(api_key=api_key, base_url=base_url, retries=0)
        )
        return client.health()

    found.append(("Sikkerfil(...).health", _construct_and_use))

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


@pytest.fixture(autouse=True)
def _sealed_off(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> list[str]:
    """No network, and no writing into the working tree.

    A sweep that reaches the network is measuring somebody else's uptime. Worse, the
    exception it gets back is a transport error that happens to contain no key, so
    the case PASSES and looks covered. Recording the attempts lets the test assert
    it stayed local rather than assume it.

    AND IT RUNS IN A TEMPORARY DIRECTORY, because handing a key to every string
    parameter includes the ones that name a file. ``ReceivedFile.save`` took the
    plausible directory ".", so while the guard on key-shaped filenames was reverted
    to check it, the sweep wrote EIGHT FILES NAMED AFTER KEYS into the repository
    root — one of them with a newline in its name. A test that leaves secrets on
    disk where they can be committed is the bug this whole file is about, committed
    by the file itself.
    """
    monkeypatch.chdir(tmp_path)
    # THE MODULE-LEVEL receive()/inspect() BUILD THEIR OWN CLIENT from the link's
    # origin, so pointing the Sikkerfil instance at the discard port fixed only half
    # of it — a bare id or key falls back to the default market, which is
    # production. _client_for honours SIKKERFIL_BASE_URL above the link precisely so
    # this cannot happen, and its docstring says so; I had simply not set it.
    monkeypatch.setenv("SIKKERFIL_BASE_URL", "http://127.0.0.1:9")

    attempted: list[str] = []

    def refuse(request: Any, *args: Any, **kwargs: Any) -> Any:
        # THE BODY AND THE HEADERS TOO, not just the URL. Recording only full_url
        # meant a call that put the key in a JSON body counted as a safely-attempted
        # request: send(content_type=<key>) and send(name=<key>) serialise straight
        # into post_json, and the URLError that came back carried no key, so the case
        # PASSED. A server-bound disclosure was satisfying the sweep.
        attempted.append(getattr(request, "full_url", str(request)))
        body = getattr(request, "data", None)
        if body:
            if isinstance(body, bytes):
                attempted.append(body.decode("utf-8", "replace"))
            else:
                attempted.append(str(body))
        attempted.extend(f"{n}: {v}" for n, v in getattr(request, "header_items", list)())
        raise urllib.error.URLError("the sweep does not use the network")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    return attempted


@pytest.mark.parametrize("spelling", list(KEYS), ids=list(KEYS))
def test_no_public_entry_point_echoes_a_key_it_was_handed(
    spelling: str, _sealed_off: list[str]
) -> None:
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

                if _leaks_in(written, key):
                    leaked.append(f"{label}({parameter}=<{spelling}>)")

    # A sweep where nothing refused anything would pass while testing nothing.
    assert raised >= 40, f"only {raised} of {calls} calls raised — refusals are not reached"
    assert not unresolved, "annotations did not resolve, so these went unswept:\n  " + "\n  ".join(
        unresolved
    )

    # THE CLI TAKES argv, WHICH IS A SEQUENCE, so substituting a string into one
    # parameter cannot reach it and it was skipped wholesale — leaving every
    # argparse-owned message unchecked. argparse formats a bad choice as
    # "invalid choice: %(value)r", so `--market <key>` wrote the key to stderr and
    # never reached the sanitised base_url_for at all. Shaped argv, then.
    for argv in (
        ["--market", handed, "list"],
        ["receive", handed],
        ["inspect", handed],
        ["send", handed],
        ["revoke", handed, "--write-token", "wt_" + "y" * 43],
        ["audit", handed, "--write-token", "wt_" + "y" * 43],
        ["send", "rapport.pdf", "--expires", handed],
        ["send", "rapport.pdf", "--max-downloads", handed],
    ):
        out, err = io.StringIO(), io.StringIO()
        calls += 1
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                cli.main(argv)
        except KeyboardInterrupt:
            raise
        except BaseException as exc:
            raised += 1
            written = _chain(exc)
        else:
            written = ""
        written += "\n" + out.getvalue().lower() + err.getvalue().lower()
        if _leaks_in(written, key):
            leaked.append(f"cli.main({argv[0]} …)")
    reached.add("cli.main(argv)")

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
        "Sikkerfil(...).health(base_url)",
        "ReceivedFile.save(directory)",
        "cli.main(argv)",
    ):
        assert anchor in reached, f"the sweep no longer reaches {anchor}"

    assert not leaked, "these echoed the key they were handed:\n  " + "\n  ".join(
        sorted(set(leaked))
    )

    # Said out loud, because "it did not leak" is worth nothing if the call never
    # ran the code under test and merely failed to resolve a hostname.
    outside = [
        u for u in _sealed_off if u.startswith(("http://", "https://")) and "127.0.0.1:9" not in u
    ]
    assert not outside, "the sweep tried to leave the machine:\n  " + "\n  ".join(
        sorted(set(outside))
    )

    # AND NOTHING SERVER-BOUND CARRIED THE KEY. The URL, the headers and the body are
    # all recorded, because a disclosure to the service is not softened by the request
    # having failed — the bytes were assembled and handed over.
    bound = [u for u in _sealed_off if _leaks_in(u, key)]
    assert not bound, "these were about to send the key to a server:\n  " + "\n  ".join(
        sorted(set(bound))[:6]
    )
