"""
THE TEST THIS LIBRARY EXISTS TO PASS.

A file sent from Python must open in the web client, and a file sent from the
web client must open here. Everything else in this package is a convenience; an
envelope that only this library can read would be worse than no library at all,
because it would be discovered by a customer whose recipient could not open a
contract.

So the envelope is not asserted against a description of WebCrypto. It is
asserted against WebCrypto — the same ``crypto.subtle`` calls the browser makes,
run under Node, which implements the same Web Crypto API. Both directions:

    Python seals   -> WebCrypto opens
    WebCrypto seals -> Python opens

and the filename envelope as well, which uses the same construction and the same
key and is the part most likely to drift, because it is base64url text rather
than bytes.

Skipped when Node is absent, so the suite still runs on a machine that only has
Python. CI has Node and does not skip it — that is where this must not be
skippable, and ``.github/workflows/ci.yml`` asserts it ran.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

import pytest

from sikkerfil import crypto

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")

# The browser's own helpers, lifted from app/src/browser/app.ts so the two sides
# are compared against the SAME code rather than against two readings of it.
WEBCRYPTO_PRELUDE = """
const toBase64Url = (bytes) =>
  Buffer.from(bytes).toString("base64")
    .replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
const fromBase64Url = (text) => {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(padded + "=".repeat((4 - (padded.length % 4)) % 4), "base64"));
};
const KEY_ALGORITHM = { name: "AES-GCM", length: 256 };
const IV_BYTES = 12;
"""


def run_node(script: str) -> dict[str, Any]:
    assert NODE is not None
    result = subprocess.run(
        [NODE, "--input-type=module", "-e", WEBCRYPTO_PRELUDE + script],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"node failed:\n{result.stderr.decode()}")
    parsed: dict[str, Any] = json.loads(result.stdout.decode())
    return parsed


@needs_node
def test_webcrypto_opens_what_python_sealed() -> None:
    plaintext = b"Kvartalsrapport Q3. Omsetning 4,2 MNOK.\n\x00\xff binary too"
    sealed = crypto.seal(plaintext)

    out = run_node(
        f"""
        const blob = fromBase64Url({json.dumps(crypto.b64url_encode(sealed.blob))});
        const key = await crypto.subtle.importKey(
          "raw", fromBase64Url({json.dumps(sealed.key_text)}), KEY_ALGORITHM, false, ["decrypt"]);
        // EXACTLY what app.ts decrypt() does: the IV is the first 12 bytes and
        // everything after it — ciphertext AND tag — goes to decrypt() whole.
        const plain = await crypto.subtle.decrypt(
          {{ name: "AES-GCM", iv: blob.slice(0, IV_BYTES) }}, key, blob.slice(IV_BYTES));
        console.log(JSON.stringify({{ plain: Buffer.from(plain).toString("base64") }}));
        """
    )
    import base64

    assert base64.b64decode(out["plain"]) == plaintext


@needs_node
def test_python_opens_what_webcrypto_sealed() -> None:
    plaintext = b"En melding fra nettleseren, med \xc3\xa6\xc3\xb8\xc3\xa5"

    out = run_node(
        f"""
        const key = await crypto.subtle.generateKey(KEY_ALGORITHM, true, ["encrypt", "decrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
        const plaintext = Buffer.from({json.dumps(plaintext.decode("utf-8"))}, "utf8");
        const ciphertext = await crypto.subtle.encrypt({{ name: "AES-GCM", iv }}, key, plaintext);
        const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
        // The envelope exactly as encrypt() in app.ts assembles it.
        const blob = new Uint8Array([...iv, ...new Uint8Array(ciphertext)]);
        console.log(JSON.stringify({{ blob: toBase64Url(blob), key: toBase64Url(raw) }}));
        """
    )

    blob = crypto.b64url_decode(out["blob"])
    key = crypto.b64url_decode(out["key"])
    assert crypto.open_sealed(blob, key) == plaintext
    # And the shape is the one both sides document, not merely a shape that works.
    assert len(blob) == crypto.IV_BYTES + len(plaintext) + crypto.TAG_BYTES


@needs_node
def test_the_sealed_filename_crosses_too() -> None:
    # The filename is the part most likely to drift: it is base64url TEXT, so a
    # padding or alphabet disagreement produces a name that will not open while
    # the file itself is fine — and open_name swallows that by design.
    key = crypto.new_key()
    name = "oppsigelse-ansatt-4412.pdf"
    sealed_text = crypto.seal_name(name, key)

    out = run_node(
        f"""
        const key = await crypto.subtle.importKey(
          "raw", fromBase64Url({json.dumps(crypto.b64url_encode(key))}),
          KEY_ALGORITHM, false, ["decrypt"]);
        const sealed = fromBase64Url({json.dumps(sealed_text)});
        const plain = await crypto.subtle.decrypt(
          {{ name: "AES-GCM", iv: sealed.slice(0, IV_BYTES) }}, key, sealed.slice(IV_BYTES));
        console.log(JSON.stringify({{ name: new TextDecoder().decode(plain) }}));
        """
    )
    assert out["name"] == name


@needs_node
def test_the_key_in_the_link_is_the_key_the_browser_generates() -> None:
    # A base64url disagreement would show up as "wrong key" for every recipient
    # using the other client, which is the worst possible failure to debug.
    sealed = crypto.seal(b"x")
    out = run_node(
        f"""
        const raw = fromBase64Url({json.dumps(sealed.key_text)});
        console.log(JSON.stringify({{ len: raw.length, back: toBase64Url(raw) }}));
        """
    )
    assert out["len"] == crypto.KEY_BYTES
    assert out["back"] == sealed.key_text
    # Unpadded, because the key ends up in a URL fragment.
    assert "=" not in sealed.key_text


def test_node_is_present_in_ci() -> None:
    """The interop tests above are the point of this file; CI must not skip them.

    A skipped test is a green tick that proves nothing, and these are the ones
    that would let a broken envelope ship. Locally this is a no-op.
    """
    if os.environ.get("CI"):
        assert NODE is not None, "CI must have node so the WebCrypto interop tests run"
