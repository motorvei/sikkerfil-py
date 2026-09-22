"""
sikkerfil — encrypted file transfer that stays inside Scandinavia.

Files are encrypted in YOUR process before anything leaves it. The key travels
in a URL fragment the server never receives, so the service stores ciphertext it
cannot open, in Stockholm (eu-north-1), under a Norwegian company.

Send a file (needs an API key from https://sikkerfil.no/konto)::

    from sikkerfil import Sikkerfil

    sf = Sikkerfil()                            # reads SIKKERFIL_API_KEY
    sent = sf.send("kvartalsrapport.pdf", max_downloads=2, expires_in=86400)
    print(sent.url)                             # give this to the recipient
    print(sent.write_token)                     # keep this: revoke and audit need it

Receive one (needs nothing at all — the link is the credential)::

    import sikkerfil

    file = sikkerfil.receive("https://sikkerfil.no/s/ABCD1234#k=...")
    file.save("~/Downloads")

Full protocol documentation: https://sikkerfil.no/utviklere
"""

from __future__ import annotations

from .client import Sikkerfil, inspect, receive
from .crypto import open_sealed, seal
from .errors import (
    ApiError,
    AuthenticationError,
    BudgetError,
    ConfigurationError,
    DecryptionError,
    DownloadsExhaustedError,
    NotFoundError,
    PasswordRequiredError,
    ShareGoneError,
    SignatureError,
    SikkerfilError,
    TransportError,
)
from .links import MARKETS, build_link, parse_link
from .models import AuditEvent, ReceivedFile, SentShare, Share

__version__ = "0.3.3"

__all__ = [
    "MARKETS",
    "ApiError",
    "AuditEvent",
    "AuthenticationError",
    "BudgetError",
    "ConfigurationError",
    "DecryptionError",
    "DownloadsExhaustedError",
    "NotFoundError",
    "PasswordRequiredError",
    "ReceivedFile",
    "SentShare",
    "Share",
    "ShareGoneError",
    "SignatureError",
    "Sikkerfil",
    "SikkerfilError",
    "TransportError",
    "__version__",
    "build_link",
    "inspect",
    "open_sealed",
    "parse_link",
    "receive",
    "seal",
]
