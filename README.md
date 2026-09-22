# sikkerfil-py

Python client for [sikkerfil.no](https://sikkerfil.no) — encrypted file transfer
that stays inside Scandinavia.

Files are encrypted **in your process**, before anything leaves it. The key
travels in the URL fragment (`#k=...`), which browsers never send and logs never
record, so the service stores ciphertext it cannot open — in Stockholm
(`eu-north-1`), operated by a Norwegian company.

```bash
pip install git+https://github.com/motorvei/sikkerfil-py
# or: uv add git+https://github.com/motorvei/sikkerfil-py
```

> Not on PyPI yet, so the install is a git URL. `pip install sikkerfil` will
> work once the name is published; until then it fetches nothing.

## Send

Sending needs an API key. Mint one at [sikkerfil.no/konto](https://sikkerfil.no/konto) —
it needs a Business account.

```python
from sikkerfil import Sikkerfil

sf = Sikkerfil()                       # reads SIKKERFIL_API_KEY
sent = sf.send("kvartalsrapport.pdf", max_downloads=2, expires_in=86400)

print(sent.url)                        # give this to the recipient
print(sent.write_token)                # keep this — see below
```

`sent.url` contains the decryption key. **Treat it like the file**: anyone who
has the link can open the contents, and we have never seen the part after `#`.

`sent.write_token` is issued exactly once and cannot be recovered. Revoking the
share and reading its audit trail both require it — an API key will not do.

## Receive

Receiving needs nothing at all. A recipient holds a link, not an account.

```python
import sikkerfil

file = sikkerfil.receive("https://sikkerfil.no/s/ABCD1234#k=...")
file.save("~/Downloads")               # -> ~/Downloads/kvartalsrapport.pdf
```

The filename is sealed under the same key as the file, so it comes back
decrypted locally — the service never held it in the clear.

### The link is a convenience, not a requirement

A recipient has a link, so the link works. But if you sent the file and kept it,
you probably have the id and the key in two columns — `SentShare` hands them
over separately. Pass them that way:

```python
sikkerfil.receive(sent.id, key=sent.key)
```

That is also the way back from a shell that ate the fragment: an unquoted `#`
starts a comment, so the key is gone before the program starts.

**The domain in a link is not routing.** One distribution serves `sikkerfil.no`,
`sakerfil.se` and `sikkerfil.dk` from one table, and the Host header is not in
its cache key, so any market answers for any share. Which front door gets dialled
is a property of your client, not of the link:

```python
sikkerfil.receive("ABCD1234", key="...", market="dk")
Sikkerfil(market="dk").receive("ABCD1234", key="...")
```

Giving a key in both the fragment and `key=` is refused rather than resolved by
precedence — one of them opens the file and the other does not, and guessing
turns a typo into a decryption failure.

## List what you have sent

```python
from sikkerfil import Sikkerfil

sf = Sikkerfil()                       # reads SIKKERFIL_API_KEY

for share in sf.shares():
    left = "unlimited" if share.downloads_remaining is None else share.downloads_remaining
    print(f"{share.id}  {share.size_bytes} B  {left} left  expires {share.expires:%Y-%m-%d}")
```

```
TEST0001     37 B  3 left  expires 2026-09-23
TEST0002     36 B  1 left  expires 2026-09-23
TEST0003     33 B  5 left  expires 2026-09-29
```

**A listing cannot get your files back.** `Share` has no `key` attribute and
`encrypted_name` comes back sealed, because the service never held either — so
it has nothing to return. A share you kept no key for is permanently unopenable,
by you and by us. `write_token` is not in the listing either; it is issued once,
at creation.

So this answers *what is still live and how much is left on it*, not *give me my
files*. For the latter, keep `sent.id` and `sent.key` when you send, and use
`receive(id, key=...)`.

## Inspect one share

What the service knows about a share, without downloading or decrypting it.
Needs no account and **no key** — the id is enough.

```python
import sikkerfil

share = sikkerfil.inspect("ABCD1234")            # or the whole link, or a name

print(share.size_bytes)                          # ciphertext: 28 B over the original
print(share.downloads_remaining)                 # None means unlimited
print(share.password_required)                   # ask before you prompt
print(share.expires)                             # aware datetime, UTC
print(share.is_ready)                            # False if the upload never finished
```

Useful before pulling something large, and before prompting for a password.

The key is deliberately **not** a parameter: metadata is not encrypted, so it
unlocks nothing here. The one sealed field is the filename, and you open that
yourself:

```python
from sikkerfil import crypto

name = crypto.open_name(share.encrypted_name, crypto.b64url_decode(key))
```

`receive()` does that for you and puts the result on `ReceivedFile.filename`.

Note that `from sikkerfil import inspect` shadows the standard library's
`inspect` module. `import sikkerfil` and call `sikkerfil.inspect(...)`.

## Command line

```bash
sikkerfil send rapport.pdf --max-downloads 2 --expires 24h
sikkerfil receive 'https://sikkerfil.no/s/ABCD1234#k=...' -o ~/Downloads

sikkerfil list
sikkerfil inspect 'https://sikkerfil.no/s/ABCD1234#k=...'
sikkerfil audit ABCD1234 --write-token wt_... --csv
sikkerfil revoke ABCD1234 --write-token wt_...
```

**Quote the link.** An unquoted `#` starts a comment in every POSIX shell, which
silently truncates the link to the part before the key. The CLI notices and says
so, but the shell has already eaten the evidence.

`sikkerfil send` prints the link alone on stdout, so `$(sikkerfil send x.pdf)`
and `| pbcopy` both do the obvious thing. Everything else goes to stderr.

## Configuration

| Variable | Meaning |
| --- | --- |
| `SIKKERFIL_API_KEY` | the key used for sending and listing |
| `SIKKERFIL_MARKET` | `no`, `se` or `dk` — which front door to use |
| `SIKKERFIL_BASE_URL` | an explicit origin; overrides the market *and* a link's own origin |

```python
Sikkerfil(api_key="sikkerfil_sk_...", market="dk", timeout=60, retries=2)
```

One service, three front doors: `sikkerfil.no`, `sakerfil.se`, `sikkerfil.dk`.
The market decides which domain your recipients see. The bytes live in Stockholm
either way.

## What a key can and cannot do

| Endpoint | Credential |
| --- | --- |
| send a file | API key, or a browser session |
| list your shares | API key, or a browser session |
| revoke a share | the **write token**, or a session |
| read the audit trail | the **write token**, or a session |
| download a share | none — the link is the credential |
| mint, list or revoke API keys | a browser **session only** |

The last row is the security posture rather than an oversight: a leaked key can
do what the account can do with files, and cannot extend its own life, mint a
sibling, or hide itself from the list that would reveal it. Revoking it ends it.
That is also why this library has no key-management functions — they would be
functions that cannot work.

## Errors

Everything raised is a `SikkerfilError`. The interesting ones lead to genuinely
different handling:

```python
from sikkerfil import (
    PasswordRequiredError,    # 403 on a download — a wrong guess costs no download
    DownloadsExhaustedError,  # 410 — the sender's limit is spent
    ShareGoneError,           # expired, revoked, or never finished uploading
    BudgetError,              # 503 — daily egress budget; .retry_after seconds
    DecryptionError,          # wrong key, or bytes altered in transit
    TransportError,           # nothing answered; a retry is reasonable
)
```

## How it works

```
key        = AES-256-GCM, 256 bits, fresh per file
iv         = 12 random bytes, fresh per file
object     = iv || ciphertext || tag          # 12 | n | 16 bytes
fragment   = base64url(raw key)
```

The envelope is byte-identical to the one the web client produces, and that is
tested rather than asserted: `tests/test_interop.py` encrypts with the same
WebCrypto calls the browser makes and decrypts the result here, in both
directions. A file sent from Python opens in a browser and vice versa.

Two things about the wire are worth knowing if you ever bypass this library:

- **Every POST must carry `x-amz-content-sha256`**, the hex SHA-256 of the body.
  CloudFront signs each origin request with SigV4, which covers the body; without
  the digest the request is refused at the edge with
  `403 InvalidSignatureException` and never reaches the service.
- **Not `Authorization: Bearer`.** The same mechanism replaces that header in
  transit, so a credential sent that way arrives as nothing at all. Use
  `x-sikkerfil-key` and `x-sikkerfil-token`.

Full protocol documentation: [sikkerfil.no/utviklere](https://sikkerfil.no/utviklere)

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy
```

The interop tests need Node (for WebCrypto) and skip without it. CI has Node and
asserts they did not skip — they are the tests that would catch a broken
envelope before a customer's recipient does.

## Licence

MIT.
