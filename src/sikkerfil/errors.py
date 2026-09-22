"""
What can go wrong, named.

THE RULE THIS FILE FOLLOWS: an exception says what happened, whether retrying
could help, and what the caller should do. A library that raises
``HTTPError: 410`` has moved the work of understanding the service onto every
person who integrates with it.

The hierarchy is shallow on purpose. Everything is a :class:`SikkerfilError`, so
``except SikkerfilError`` is a correct catch-all, and the interesting cases —
gone, exhausted, wrong password, out of budget — are separate classes because
they lead to genuinely different handling.
"""

from __future__ import annotations


class SikkerfilError(Exception):
    """Base class. Every error this library raises is one of these."""


class ConfigurationError(SikkerfilError):
    """The client was built wrong — no key, an unknown market, a bad base URL.

    Raised before anything is sent, so it never costs an upload.
    """


class DecryptionError(SikkerfilError):
    """The bytes did not open.

    The wrong key, a truncated download, or altered ciphertext. GCM refuses all
    three identically and that is the point of using it.
    """


class TransportError(SikkerfilError):
    """The request never got an answer: DNS, TLS, a timeout, a reset socket.

    Distinct from every error below, all of which mean the service DID answer.
    This one is the class where a retry is usually reasonable.
    """


class ApiError(SikkerfilError):
    """The service answered, and the answer was a refusal.

    Carries the HTTP status and, when the body had one, the service's own error
    code — the short string in ``{"error": "..."}`` — so callers can branch on a
    stable identifier instead of matching on prose.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int,
        code: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        #: CloudFront's ``x-amz-cf-id``, when present. This is the one value
        #: support can use to find a single request in the logs, so it is kept
        #: on the exception rather than discarded with the response.
        self.request_id = request_id


class AuthenticationError(ApiError):
    """401/403: the credential is missing, wrong, revoked, or not allowed here.

    Worth knowing which: API keys work on ``POST /api/v1/shares`` and
    ``GET /api/v1/account/shares``. Revoking a share and reading its audit trail
    take the WRITE TOKEN issued when the share was created, or a browser
    session — not a key. And minting keys takes a session, never a key.
    """


class SignatureError(AuthenticationError):
    """The CDN rejected the request before it reached the service.

    THIS IS A BUG IN THIS LIBRARY IF YOU EVER SEE IT, and the message says so,
    because the alternative is a customer debugging our signing for us.

    CloudFront reaches the origin through an origin access control that signs
    every request with SigV4, and SigV4 covers the body. The caller has to
    supply the body's SHA-256 in ``x-amz-content-sha256`` or the signature is
    not computable and the request is refused at the edge — no route runs, no
    log line is written. ``transport.py`` sets that header on every POST from one
    place, which is why this should be unreachable.
    """


class NotFoundError(ApiError):
    """404: no such share — or one you hold no credential for.

    THE AMBIGUITY IS DELIBERATE, on the service's side. A wrong write token gets
    a 404 rather than a 403, because answering 403 would confirm to someone who
    cannot act on a share that the share exists.
    """


class ShareGoneError(ApiError):
    """The share is past its expiry, was revoked, or never finished uploading.

    Not retryable. Shares are deleted, not archived — that is the product.
    """


class DownloadsExhaustedError(ApiError):
    """410: the download limit for this share has been spent.

    The sender sets the limit at creation and it is clamped to the plan's cap,
    so a link that worked yesterday can legitimately be spent today.
    """


class PasswordRequiredError(ApiError):
    """403 on a download: the share is password-protected, or the guess is wrong.

    A WRONG GUESS DOES NOT COST A DOWNLOAD. The service checks the password
    before it claims one, so retrying with the right password works — otherwise
    anybody holding the link could exhaust a share they cannot open.
    """


class BudgetError(ApiError):
    """503: the service's daily egress budget is spent. Try later.

    A cost control, not a fault, and the only error here that clears on its own.
    :attr:`retry_after` carries the service's own advice in seconds.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int,
        code: str | None = None,
        request_id: str | None = None,
        retry_after: int = 3600,
    ) -> None:
        super().__init__(message, status=status, code=code, request_id=request_id)
        self.retry_after = retry_after
