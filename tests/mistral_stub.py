"""
A stub Mistral account speaking the wire shapes of the recorded reference.

``/v1/files`` (multipart upload, paged listing, delete), ``/v1/ocr`` and
``/v1/models``, answering per API key so a rotation can be told apart from
the recorded version. Every behaviour a D-43 test needs is a switch: the
answer to an upload (dropped, a different ``visibility``, no
``expires_at``), the answer to a delete (proof, ``404``, ``401``, ``500``,
``deleted: false``), listings that omit a stored file for the first N calls,
and files the gateway does not own.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from provider_stubs import Received, Reply

_FIELD = re.compile(rb'name="([^"]+)"\r\n\r\n([^\r]*)\r\n')
_FILE = re.compile(
    rb'name="file"; filename="([^"]+)"\r\nContent-Type: ([^\r]+)\r\n\r\n'
)


def page(index: int, markdown: str = "text") -> dict[str, Any]:
    """One OCR answer page in the reference's shape."""
    return {
        "index": index,
        "markdown": f"{markdown} {index}",
        "images": [
            {
                "id": f"img-{index}.jpeg",
                "top_left_x": 10,
                "top_left_y": 20,
                "bottom_right_x": 110,
                "bottom_right_y": 220,
                "image_base64": None,
            }
        ],
        "dimensions": {"dpi": 200, "height": 2200, "width": 1700},
    }


@dataclass
class StoredFile:
    """A file the stub account holds."""

    remote_id: str
    file_name: str
    key: str
    body: bytes
    created_at: int
    purpose: str = "ocr"


@dataclass
class MistralStub:
    """One stub account; ``__call__`` is a :class:`StubServer` reply function."""

    visibility: str = "user"
    expires: bool = True
    expires_in: int = 3600
    drop_upload: bool = False
    #: ``proof`` | ``404`` | ``401`` | ``429`` | ``500`` | ``false`` | ``wrong-id``.
    delete_mode: str = "proof"
    #: Keys whose delete answers ``401`` (a revoked recorded version).
    revoked: set[str] = field(default_factory=set)
    #: Keys whose account holds none of the files (``404`` to every delete).
    elsewhere: set[str] = field(default_factory=set)
    list_status: int = 200
    #: Listing calls that omit the gateway's stored files.
    hide_listings: int = 0
    pages: Callable[[list[int]], list[dict[str, Any]]] = field(
        default=lambda wanted: [page(i) for i in wanted]
    )
    ocr_status: int = 200
    on_ocr: Callable[[], None] | None = None
    files: dict[str, StoredFile] = field(default_factory=dict)
    log: list[tuple[str, str, str]] = field(default_factory=list)
    ocr_bodies: list[dict[str, Any]] = field(default_factory=list)
    uploads: list[dict[str, Any]] = field(default_factory=list)
    _next: int = 0

    # --- the account's contents ---------------------------------------------------

    def add(
        self, file_name: str, *, key: str = "", age: int = 0, purpose: str = "ocr"
    ) -> str:
        """Store a file the gateway did not upload; its id."""
        self._next += 1
        remote_id = f"file-{self._next:04d}"
        self.files[remote_id] = StoredFile(
            remote_id, file_name, key, b"", int(time.time()) - age, purpose
        )
        return remote_id

    def held(self) -> list[str]:
        """The names of every stored file."""
        return sorted(f.file_name for f in self.files.values())

    def requests(self, method: str, prefix: str = "") -> list[tuple[str, str, str]]:
        """``(method, path, key)`` of the requests to paths under ``prefix``."""
        return [r for r in self.log if r[0] == method and r[1].startswith(prefix)]

    # --- the API --------------------------------------------------------------------

    def __call__(self, received: Received) -> Reply:
        method, target, _ = received.request_line.split(" ")
        url = urlsplit(target)
        key = (received.header("authorization") or "").removeprefix("Bearer ")
        self.log.append((method, url.path, key))
        if method == "POST" and url.path == "/v1/files":
            return self._upload(received, key)
        if method == "GET" and url.path == "/v1/files":
            return self._list(parse_qs(url.query), key)
        if method == "DELETE" and url.path.startswith("/v1/files/"):
            return self._delete(url.path.removeprefix("/v1/files/"), key)
        if method == "POST" and url.path == "/v1/ocr":
            return self._ocr(received)
        if method == "GET" and url.path == "/v1/models":
            return _json({"object": "list", "data": []})
        return _json({"detail": "not found"}, 404)

    def _upload(self, received: Received, key: str) -> Reply:
        fields = {k.decode(): v.decode() for k, v in _FIELD.findall(received.body)}
        match = _FILE.search(received.body)
        assert match is not None, "the upload carried no file part"
        file_name, media_type = match.group(1).decode(), match.group(2).decode()
        content = received.body[match.end() :].rsplit(b"\r\n--", 1)[0]
        self.uploads.append(
            {
                **fields,
                "filename": file_name,
                "content_type": media_type,
                "size": len(content),
            }
        )
        self._next += 1
        remote_id = f"file-{self._next:04d}"
        now = int(time.time())
        self.files[remote_id] = StoredFile(remote_id, file_name, key, content, now)
        if self.drop_upload:
            return Reply(drop=True)
        answer: dict[str, Any] = {
            "id": remote_id,
            "object": "file",
            "bytes": len(content),
            "created_at": now,
            "filename": file_name,
            "purpose": fields.get("purpose"),
            "sample_type": "ocr_input",
            "source": "upload",
            "visibility": self.visibility,
        }
        if self.expires:
            answer["expires_at"] = now + self.expires_in
        return _json(answer)

    def _list(self, query: dict[str, list[str]], key: str) -> Reply:
        if self.list_status != 200:
            return _json({"detail": "listing failed"}, self.list_status)
        hide = self.hide_listings > 0
        self.hide_listings -= 1 if hide else 0
        number = int(query.get("page", ["0"])[0])
        size = int(query.get("page_size", ["100"])[0])
        purpose = query.get("purpose", [None])[0]
        visible = [
            f
            for f in self.files.values()
            if (purpose is None or f.purpose == purpose)
            and not (hide and f.file_name.startswith("m8ai-") and f.key == key)
        ]
        chunk = visible[number * size : (number + 1) * size]
        data = [
            {
                "id": f.remote_id,
                "object": "file",
                "bytes": len(f.body),
                "created_at": f.created_at,
                "filename": f.file_name,
                "purpose": f.purpose,
            }
            for f in chunk
        ]
        return _json({"object": "list", "data": data, "total": len(visible)})

    def _delete(self, remote_id: str, key: str) -> Reply:
        if key in self.revoked or self.delete_mode == "401":
            return _json({"detail": "unauthorized"}, 401)
        if self.delete_mode == "500":
            return _json({"detail": "boom"}, 500)
        if self.delete_mode == "429":
            reply = _json({"detail": "slow down"}, 429)
            reply.headers.append(("Retry-After", "900"))
            return reply
        stored = self.files.get(remote_id)
        if stored is None or self.delete_mode == "404" or key in self.elsewhere:
            return _json({"detail": "not found"}, 404)
        if self.delete_mode == "false":
            return _json({"id": remote_id, "object": "file", "deleted": False})
        del self.files[remote_id]
        answered = "file-9999" if self.delete_mode == "wrong-id" else remote_id
        return _json({"id": answered, "object": "file", "deleted": True})

    def _ocr(self, received: Received) -> Reply:
        body = json.loads(received.body)
        self.ocr_bodies.append(body)
        if self.on_ocr is not None:
            self.on_ocr()
        if self.ocr_status != 200:
            return _json({"detail": "ocr failed"}, self.ocr_status)
        pages = self.pages(list(body["pages"]))
        return _json(
            {
                "pages": pages,
                "model": body["model"],
                "document_annotation": None,
                "usage_info": {"pages_processed": len(pages), "doc_size_bytes": 10},
            }
        )


def _json(body: Any, status: int = 200) -> Reply:
    return Reply(
        status=status,
        headers=[("Content-Type", "application/json")],
        chunks=[json.dumps(body).encode()],
    )


__all__ = ["MistralStub", "StoredFile", "page"]
