"""
A stub of the service, over real HTTP.

WHY A REAL SOCKET AND NOT A MOCK. The failures this library has to survive are
failures of what goes ON THE WIRE — a header that was set on the wrong object, a
body serialised twice, a Content-Length that disagrees with the bytes. A mocked
transport asserts that we called ourselves the way we expected to call ourselves,
which is exactly the class of bug it cannot see. This runs a real HTTP server on
a real loopback port and records what actually arrived.

WHAT IT CANNOT PROVE, and the reason ``test_transport.py`` is structural as well:
there is no CloudFront here. This stub accepts a POST with no
``x-amz-content-sha256`` because nothing is signing anything. Production would
refuse it at the edge. No functional test in this repository can close that gap.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest


@dataclass
class Recorded:
    """One request, exactly as it arrived."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class Scripted:
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


class StubService:
    """Enough of sikkerfil to drive the whole send-and-receive flow."""

    def __init__(self) -> None:
        self.requests: list[Recorded] = []
        self.objects: dict[str, bytes] = {}
        self.shares: dict[str, dict[str, Any]] = {}
        self._scripted: Scripted | None = None
        self._server: HTTPServer | None = None
        self.base_url = ""

    def respond(self, *, status: int, body: bytes, headers: dict[str, str]) -> None:
        """Force the next response, whatever was asked for."""
        self._scripted = Scripted(status=status, body=body, headers=headers)

    # --- The routes ----------------------------------------------------------

    def handle(self, request: Recorded) -> Scripted:
        self.requests.append(request)
        if self._scripted is not None:
            scripted, self._scripted = self._scripted, None
            return scripted

        method, path = request.method, request.path

        if method == "GET" and path == "/api/health":
            return _json(200, {"ok": True})

        if method == "POST" and path == "/api/shares":
            return self._create(request)

        if method == "PUT" and path.startswith("/upload/"):
            share_id = path.split("/")[2]
            # S3 PINS THE CONTENT LENGTH INTO THE PRESIGNED SIGNATURE, so a body
            # of a different size is refused. Reproduced here because getting it
            # wrong means every upload fails in production and none fails in a
            # test that ignores it.
            expected = self.shares[share_id]["sizeBytes"]
            if len(request.body) != expected:
                return _json(403, {"error": "SignatureDoesNotMatch"})
            self.objects[share_id] = request.body
            return Scripted(status=200, body=b"", headers={})

        if method == "POST" and path.endswith("/complete"):
            share_id = path.split("/")[3]
            share = self.shares.get(share_id)
            if not share or request.headers.get("x-sikkerfil-token") != share["writeToken"]:
                return _json(409, {"error": "not_pending_or_bad_token"})
            share["state"] = "ready"
            return _json(200, _public(share))

        if method == "POST" and path.endswith("/download"):
            share_id = path.split("/")[3]
            share = self.shares.get(share_id)
            if not share or share["state"] != "ready":
                return _json(404, {"error": "gone"})
            asked = json.loads(request.body or b"{}").get("password")
            if share.get("password") and asked != share["password"]:
                return _json(403, {"error": "forbidden"})
            if share["downloadsRemaining"] is not None:
                if share["downloadsRemaining"] <= 0:
                    return _json(410, {"error": "exhausted"})
                share["downloadsRemaining"] -= 1
            return _json(200, {"url": f"{self.base_url}/object/{share_id}"})

        if method == "GET" and path.startswith("/object/"):
            return Scripted(status=200, body=self.objects[path.split("/")[2]], headers={})

        if method == "GET" and path.startswith("/api/navn/"):
            wanted = path.split("/")[3]
            for share in self.shares.values():
                if share.get("name") == wanted and share["state"] == "ready":
                    return _json(200, _public(share))
            return _json(404, {"error": "not_found"})

        if method == "GET" and path.endswith("/audit"):
            share_id = path.split("/")[3]
            return _json(200, {"id": share_id, "events": [
                {"shareId": share_id, "action": "created", "at": 1_700_000_000},
                {"shareId": share_id, "action": "downloaded", "at": 1_700_000_100, "country": "NO"},
            ]})

        if method == "GET" and path.endswith("/audit.csv"):
            return Scripted(
                status=200,
                body=b"share,action,at,country\nABCD1234,created,1700000000,\n",
                headers={"content-type": "text/csv; charset=utf-8"},
            )

        if method == "GET" and path == "/api/account/shares":
            if not request.headers.get("x-sikkerfil-key"):
                return _json(401, {"error": "unauthorized"})
            return _json(200, {"shares": [_public(s) for s in self.shares.values()]})

        if method == "DELETE" and path.startswith("/api/shares/"):
            share_id = path.split("/")[3]
            share = self.shares.get(share_id)
            if not share or request.headers.get("x-sikkerfil-token") != share["writeToken"]:
                return _json(404, {"error": "not_found"})
            del self.shares[share_id]
            return Scripted(status=204, body=b"", headers={})

        if method == "GET" and path.startswith("/api/shares/"):
            share = self.shares.get(path.split("/")[3])
            if not share or share["state"] != "ready":
                return _json(404, {"error": "gone"})
            return _json(200, _public(share))

        return _json(404, {"error": "not_found"})

    def _create(self, request: Recorded) -> Scripted:
        if not request.headers.get("x-sikkerfil-key"):
            return _json(401, {"error": "unauthorized"})
        body = json.loads(request.body)
        share_id = f"TEST{len(self.shares) + 1:04d}"
        share = {
            "id": share_id,
            "state": "pending",
            "writeToken": f"wt-{share_id}",
            "sizeBytes": body["sizeBytes"],
            "contentType": body.get("contentType", "application/octet-stream"),
            "encryptedName": body.get("encryptedName"),
            "expiresAt": 1_700_086_400,
            # Clamped exactly as the service clamps it, so a test that asks for
            # 500 sees the 5 a caller would really get.
            "downloadsRemaining": min(body.get("maxDownloads", 5), 5),
            "password": body.get("password"),
            "name": body.get("name"),
        }
        self.shares[share_id] = share
        return _json(201, {
            "id": share_id,
            "writeToken": share["writeToken"],
            "uploadUrl": f"{self.base_url}/upload/{share_id}",
            "expiresAt": share["expiresAt"],
            **({"name": share["name"]} if share["name"] else {}),
        })


def _public(share: dict[str, Any]) -> dict[str, Any]:
    out = {
        "id": share["id"],
        "state": share["state"],
        "sizeBytes": share["sizeBytes"],
        "contentType": share["contentType"],
        "expiresAt": share["expiresAt"],
        "downloadsRemaining": share["downloadsRemaining"],
        "passwordRequired": bool(share.get("password")),
    }
    if share.get("encryptedName"):
        out["encryptedName"] = share["encryptedName"]
    if share.get("name"):
        out["name"] = share["name"]
    return out


def _json(status: int, payload: dict[str, Any]) -> Scripted:
    return Scripted(
        status=status,
        body=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
    )


class _Handler(BaseHTTPRequestHandler):
    service: StubService

    def _dispatch(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        recorded = Recorded(
            method=self.command,
            path=self.path,
            headers={k.lower(): v for k, v in self.headers.items()},
            body=self.rfile.read(length) if length else b"",
        )
        result = self.service.handle(recorded)
        self.send_response(result.status)
        for name, value in result.headers.items():
            self.send_header(name, value)
        self.send_header("content-length", str(len(result.body)))
        self.end_headers()
        if result.body:
            self.wfile.write(result.body)

    do_GET = do_POST = do_PUT = do_DELETE = _dispatch

    def log_message(self, *args: object) -> None:  # keep the test output readable
        pass


@pytest.fixture
def stub() -> Iterator[StubService]:
    service = StubService()
    handler = type("Handler", (_Handler,), {"service": service})
    server = HTTPServer(("127.0.0.1", 0), handler)
    service.base_url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield service
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
