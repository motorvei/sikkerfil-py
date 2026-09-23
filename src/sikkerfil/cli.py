"""
``sikkerfil`` on the command line.

THE POINT OF HAVING ONE. The published curl examples work, and they are four
commands plus a Node one-liner to decrypt — because ``openssl enc`` refuses AEAD
ciphers outright and there is no standard tool that will open an AES-GCM
envelope. That is a real obstacle for the person who just wants to hand a file
to a colleague from a terminal, or to pull one down inside a CI job.

    sikkerfil send rapport.pdf --max-downloads 2 --expires 24h
    sikkerfil receive 'https://sikkerfil.no/s/ABCD1234#k=...' -o ~/Downloads

QUOTE THE LINK. An unquoted ``#`` starts a comment in every POSIX shell, which
silently truncates the link to the part before the key — the part that cannot
decrypt anything. The error for that case says so by name rather than reporting
a missing key, because the shell has already eaten the evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence

from . import __version__
from .client import Sikkerfil, _client_for
from .errors import ConfigurationError, SikkerfilError
from .links import DEFAULT_MARKET, MARKETS, quoted

_DURATION = re.compile(r"^(\d+)\s*([smhdw]?)$", re.IGNORECASE)
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "": 1}


def count(text: str) -> int:
    """A positive integer, refused WITHOUT echoing what was given.

    argparse's own ``type=int`` formats a failure as "invalid int value: '<the value>'"
    and writes it to stderr itself — so ``--max-downloads <a key>`` printed the key
    before any of our code ran. Same mechanism as ``choices=``, which was removed from
    ``--market`` for the same reason, and which I fixed there without looking for
    other argparse-owned conversions.
    """
    try:
        value = int(text)
    except ValueError:
        value = -1
    if value < 0:
        raise argparse.ArgumentTypeError(
            f"{quoted(text)} is not a whole number. It is not repeated here if it "
            "might be a key: a decryption key is not a count."
        )
    return value


def duration(text: str) -> int:
    """``90``, ``30m``, ``24h``, ``7d`` — seconds either way."""
    match = _DURATION.match(text.strip())
    if not match:
        raise argparse.ArgumentTypeError(
            f"{quoted(text)} is not a duration; use 3600, 30m, 24h or 7d"
        )
    return int(match.group(1)) * _UNITS[match.group(2).lower()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sikkerfil",
        description="Encrypted file transfer that stays inside Scandinavia.",
        epilog="Protocol documentation: https://sikkerfil.no/utviklere",
    )
    parser.add_argument("--version", action="version", version=f"sikkerfil {__version__}")
    # NO choices= HERE, deliberately. argparse formats a rejected choice as
    # "invalid choice: %(value)r" and writes it to stderr itself, so `--market
    # <a key>` printed the key and never reached base_url_for, which exists to
    # refuse it without echoing. Validated below instead, by the one function that
    # already knows how — the help text still lists the markets, so nothing is lost
    # but the leak.
    parser.add_argument(
        "--market",
        default=None,
        metavar="{" + ",".join(sorted(MARKETS)) + "}",
        help=f"which front door to use (default: {DEFAULT_MARKET})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    send = sub.add_parser("send", help="encrypt a file and upload it")
    send.add_argument("file", help="the file to send, or - for stdin")
    send.add_argument("--name-as", metavar="NAME", help="seal this filename instead")
    send.add_argument("--expires", type=duration, metavar="DURATION", help="e.g. 24h, 7d")
    send.add_argument("--max-downloads", type=count, metavar="N")
    send.add_argument("--password", metavar="SECRET", help="an extra secret the recipient needs")
    send.add_argument("--link-name", metavar="NAME", help="claim sikkerfil.no/NAME")
    send.add_argument("--json", action="store_true", help="print the full result as JSON")

    recv = sub.add_parser("receive", help="download and decrypt a share")
    recv.add_argument("link", help="the share link, INCLUDING the #k=... fragment")
    recv.add_argument("-o", "--output", default=".", metavar="DIR_OR_FILE")
    recv.add_argument("--password", metavar="SECRET")

    info = sub.add_parser("inspect", help="what the service knows about a share")
    info.add_argument("link")
    info.add_argument("--json", action="store_true")

    listing = sub.add_parser("list", help="shares this account has sent")
    listing.add_argument("--json", action="store_true")

    revoke = sub.add_parser("revoke", help="delete a share now")
    revoke.add_argument("share_id")
    revoke.add_argument("--write-token", required=True, help="issued once, when the share was made")

    audit = sub.add_parser("audit", help="the transfer trail for a share")
    audit.add_argument("share_id")
    audit.add_argument("--write-token", required=True)
    audit.add_argument("--csv", action="store_true", help="the form a DPO files")

    args = parser.parse_args(argv)

    try:
        return _run(args)
    except SikkerfilError as exc:
        print(f"sikkerfil: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        return 130


def _run(args: argparse.Namespace) -> int:
    if args.command == "send":
        return _send(args)
    if args.command == "receive":
        return _receive(args)
    if args.command == "inspect":
        return _inspect(args)
    if args.command == "list":
        return _list(args)
    if args.command == "revoke":
        return _revoke(args)
    if args.command == "audit":
        return _audit(args)
    raise ConfigurationError(f"unknown command {args.command!r}")  # pragma: no cover


def _client(args: argparse.Namespace) -> Sikkerfil:
    return Sikkerfil(market=args.market)


def _send(args: argparse.Namespace) -> int:
    client = _client(args)
    if args.file == "-":
        data = sys.stdin.buffer.read()
        sent = client.send(
            data,
            filename=args.name_as or "",
            expires_in=args.expires,
            max_downloads=args.max_downloads,
            password=args.password,
            name=args.link_name,
        )
    else:
        sent = client.send(
            args.file,
            filename=args.name_as,
            expires_in=args.expires,
            max_downloads=args.max_downloads,
            password=args.password,
            name=args.link_name,
        )

    if args.json:
        print(
            json.dumps(
                {
                    "id": sent.id,
                    "url": sent.url,
                    "writeToken": sent.write_token,
                    "expiresAt": sent.expires_at,
                    "sizeBytes": sent.size_bytes,
                    "name": sent.name,
                },
                indent=2,
            )
        )
        return 0

    # THE LINK ON ITS OWN LINE, so `| pbcopy` and `$(...)` both do the obvious
    # thing. Everything else goes to stderr for the same reason.
    print(sent.url)
    print(f"write token: {sent.write_token}", file=sys.stderr)
    print(f"expires:     {sent.expires:%Y-%m-%d %H:%M UTC}", file=sys.stderr)
    print(
        "\nKeep the write token: revoking this share and reading its audit\n"
        "trail need it, it is issued once, and it cannot be recovered.\n"
        "The link contains the decryption key — treat it like the file.",
        file=sys.stderr,
    )
    return 0


def _receive(args: argparse.Namespace) -> int:
    _warn_if_shell_ate_the_fragment(args.link)
    client = _client_for(args.link, 60.0)
    got = client.receive(args.link, password=args.password)

    output = os.path.expanduser(args.output)
    target, chosen = os.path.split(output)
    if os.path.isdir(output):
        target, chosen = output, None
    path = got.save(target or ".", filename=chosen or None)
    print(path)
    print(f"{len(got)} bytes, decrypted locally", file=sys.stderr)
    return 0


def _inspect(args: argparse.Namespace) -> int:
    from .client import inspect as inspect_share

    share = inspect_share(args.link)
    if args.json:
        print(
            json.dumps(
                {
                    "id": share.id,
                    "state": share.state,
                    "sizeBytes": share.size_bytes,
                    "contentType": share.content_type,
                    "expiresAt": share.expires_at,
                    "downloadsRemaining": share.downloads_remaining,
                    "passwordRequired": share.password_required,
                    "name": share.name,
                },
                indent=2,
            )
        )
        return 0

    remaining = "unlimited" if share.downloads_remaining is None else share.downloads_remaining
    print(f"id                  {share.id}")
    print(f"state               {share.state}")
    print(f"size                {share.size_bytes} bytes (ciphertext)")
    print(f"expires             {share.expires:%Y-%m-%d %H:%M UTC}")
    print(f"downloads remaining {remaining}")
    print(f"password required   {'yes' if share.password_required else 'no'}")
    # Said plainly, because it is the product rather than a missing field.
    print("filename            sealed — only a holder of the key can read it")
    return 0


def _list(args: argparse.Namespace) -> int:
    shares = _client(args).shares()
    if args.json:
        print(json.dumps([s.__dict__ for s in shares], indent=2, default=str))
        return 0
    if not shares:
        print("no live shares")
        return 0
    for share in shares:
        remaining = "∞" if share.downloads_remaining is None else share.downloads_remaining
        print(
            f"{share.id:<10} {share.size_bytes:>12} B  "
            f"expires {share.expires:%Y-%m-%d %H:%M}  {remaining} left"
        )
    return 0


def _revoke(args: argparse.Namespace) -> int:
    _client(args).revoke(args.share_id, write_token=args.write_token)
    print(f"{args.share_id} revoked")
    return 0


def _audit(args: argparse.Namespace) -> int:
    client = _client(args)
    if args.csv:
        sys.stdout.write(client.audit_csv(args.share_id, write_token=args.write_token))
        return 0
    for event in client.audit(args.share_id, write_token=args.write_token):
        where = f" from {event.country}" if event.country else ""
        print(f"{event.when:%Y-%m-%d %H:%M:%S UTC}  {event.action}{where}")
    return 0


def _warn_if_shell_ate_the_fragment(link: str) -> None:
    """The unquoted-``#`` failure, named before it is reported as a missing key.

    ``sikkerfil receive https://sikkerfil.no/s/ABCD1234#k=...`` in any POSIX
    shell arrives here as ``https://sikkerfil.no/s/ABCD1234`` — the ``#`` began a
    comment and the key was discarded before this process started. The resulting
    "this link has no key" is true and completely unhelpful, so say what
    happened while the shape of it is still recognisable.
    """
    if "#" in link or "k=" in link:
        return
    print(
        "note: this link has no #k= fragment. If you pasted it into a shell "
        "without quotes,\n      the '#' started a comment and the key was "
        "dropped. Try:\n\n      sikkerfil receive '<the whole link>'\n",
        file=sys.stderr,
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
