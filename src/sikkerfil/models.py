"""
The shapes the service speaks, as Python objects.

Frozen dataclasses rather than dicts, for the ordinary reason — ``share.expires_at``
fails at the point of the typo, ``share["expiresAt"]`` fails somewhere else — and
one less ordinary one: the service is deliberately sparse about what it knows,
and a typed object makes that visible. There is no ``filename`` on
:class:`Share`, only ``encrypted_name``, because the service genuinely does not
have one. Reading that struct is reading the privacy claim.

Every field carries UTC seconds where the service sends epoch seconds. The
``*_at`` properties hand back aware ``datetime`` objects for the caller's
convenience; the raw numbers stay, because that is what round-trips.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .links import origin_of

#: ``repr=False`` on the classes below is a SAFETY BELT, not the mechanism. A
#: dataclass does not overwrite a ``__repr__`` defined in the class body, so the
#: explicit ones are what take effect either way. It matters if one of them is
#: ever deleted: with ``repr=False`` the class falls back to object's repr, which
#: shows no fields, instead of silently regaining a generated one that prints the
#: key. No test can tell the difference today, which is why it is written down.


def _utc(epoch: int) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


@dataclass(frozen=True)
class Share:
    """What the service will tell anyone holding a link, before they prove anything.

    NOTE WHAT IS NOT HERE: no filename, no owner, no hash of the contents, no
    key. :attr:`encrypted_name` is ciphertext under the file's own key, so it is
    only a name to someone who already has the link's ``#k=`` fragment.
    """

    id: str
    state: str
    size_bytes: int
    content_type: str
    expires_at: int
    #: ``None`` means unlimited within the share's lifetime.
    downloads_remaining: int | None
    password_required: bool
    encrypted_name: str | None = None
    #: Set only when the sender claimed a named link (``sikkerfil.no/kvartalsrapport``).
    name: str | None = None

    @property
    def expires(self) -> datetime:
        return _utc(self.expires_at)

    @property
    def is_ready(self) -> bool:
        """Whether the upload finished. A ``pending`` share has no bytes yet."""
        return self.state == "ready"

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Share:
        return cls(
            id=data["id"],
            state=data.get("state", "ready"),
            size_bytes=int(data.get("sizeBytes", 0)),
            content_type=data.get("contentType", "application/octet-stream"),
            expires_at=int(data.get("expiresAt", 0)),
            downloads_remaining=data.get("downloadsRemaining"),
            password_required=bool(data.get("passwordRequired", False)),
            encrypted_name=data.get("encryptedName"),
            name=data.get("name"),
        )


@dataclass(frozen=True, repr=False)
class SentShare:
    """The result of a send: a link to give somebody, and a token to keep.

    THE TWO HALVES MATTER DIFFERENTLY.

    :attr:`url` contains the decryption key after ``#k=``. Anyone who has it can
    open the file, so it is as sensitive as the file — and the service has never
    seen this string, only the part before the ``#``.

    :attr:`write_token` is issued exactly once, here, and is never recoverable.
    It is what revoking the share and reading its audit trail require. An API key
    will not do: those two endpoints take the write token or a browser session.
    Store it if you will ever want to pull a file back or evidence a transfer.
    """

    id: str
    url: str
    write_token: str
    key: str
    expires_at: int
    size_bytes: int
    name: str | None = None

    @property
    def expires(self) -> datetime:
        return _utc(self.expires_at)

    def __repr__(self) -> str:
        """Without the key, the link's fragment, or the write token.

        THE DEFAULT REPR PUT ALL THREE IN EVERY LOG THAT TOUCHED THIS OBJECT.
        ``logger.info("sent %s", sent)`` is an ordinary line to write, and it
        wrote the decryption key and the once-issued write token into whatever
        the application logs to. The caller chose to hold those; they did not
        choose to print them.

        What is left is what identifies the share — the id, the market, when it
        expires — which is what anyone reading a log actually wants.

        THE FIRST VERSION OF THIS LEAKED. It took everything before ``/s/`` as the
        origin, and ``partition`` returns the WHOLE string when the separator is
        absent — so a NAMED link, which has no ``/s/``, came back complete with its
        fragment. Hence origin_of, which is the one place that answers this.
        """
        return (
            f"SentShare(id={self.id!r}, origin={origin_of(self.url)!r}, "
            f"expires_at={self.expires_at}, size_bytes={self.size_bytes}, "
            f"name={self.name!r}, url=<carries the key>, "
            f"key=<hidden>, write_token=<hidden>)"
        )


@dataclass(frozen=True, repr=False)
class ReceivedFile:
    """A decrypted file, in memory.

    :attr:`filename` is ``None`` when the sender sealed no name, or when the
    sealed name would not open under this key — the download is not failed over
    a label. See ``crypto.open_name``.
    """

    data: bytes
    filename: str | None
    content_type: str
    share: Share

    def __len__(self) -> int:
        return len(self.data)

    def __repr__(self) -> str:
        """Without the plaintext, AND WITHOUT THE FILENAME.

        The file bytes are obviously the thing being protected. The name is less
        obvious and is the reason ``encryptedName`` exists at all: the service
        never learns it, because "oppsigelse-ansatt-4412.pdf" gives away the
        document without a byte of it. Decrypting it locally and then printing it
        into the application's logs hands back exactly what sealing it bought —
        which makes masking the bytes and not the name no protection at all.
        """
        named = "a sealed name" if self.filename else "no name"
        return (
            f"ReceivedFile({named}, content_type={self.content_type!r}, "
            f"data=<{len(self.data)} bytes>, share={self.share.id!r})"
        )

    def save(self, directory: str = ".", *, filename: str | None = None) -> str:
        """Write the bytes to disk and return the path written.

        THE FILENAME IS TREATED AS HOSTILE. It arrives from whoever sent the
        file, decrypted locally — which makes it attacker-controlled input
        reaching a path join. ``../../.ssh/authorized_keys`` is a sealed name
        like any other, so only the basename is ever used, and a leading dot is
        stripped so a sender cannot quietly drop a file somewhere it will not be
        noticed.

        THE DIRECTORY IS THE CALLER'S, so ``~`` is expanded. Not expanding it
        creates a directory literally named ``~`` in the working directory, or
        fails outright — and ``save("~/Downloads")`` is the obvious thing to
        write.
        """
        chosen = filename or self.filename or f"sikkerfil-{self.share.id}.bin"
        safe = os.path.basename(chosen.replace("\\", "/")).lstrip(".") or f"{self.share.id}.bin"
        path = os.path.join(os.path.expanduser(directory), safe)
        with open(path, "wb") as handle:
            handle.write(self.data)
        return path


@dataclass(frozen=True)
class AuditEvent:
    """One line of the trail a data protection officer reads.

    :attr:`country` comes from CloudFront's edge, not from the client, so it
    cannot be forged by a caller. It is coarse on purpose: the trail evidences
    that a transfer happened and roughly where from — it is not a location
    history of recipients.
    """

    share_id: str
    action: str
    at: int
    country: str | None = None

    @property
    def when(self) -> datetime:
        return _utc(self.at)

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> AuditEvent:
        return cls(
            share_id=data.get("shareId", ""),
            action=data.get("action", ""),
            at=int(data.get("at", 0)),
            country=data.get("country"),
        )
