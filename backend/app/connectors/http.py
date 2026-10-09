from __future__ import annotations

import ssl
from typing import Any

import httpx


def make_client(verify: bool = True, timeout: float = 60.0, headers: dict[str, str] | None = None, auth: Any = None) -> httpx.AsyncClient:
    verify_arg: bool | ssl.SSLContext = verify
    return httpx.AsyncClient(verify=verify_arg, timeout=httpx.Timeout(timeout), headers=headers or {}, auth=auth, follow_redirects=True)


def error_text(resp: httpx.Response) -> str:
    body = resp.text[:300].replace("\n", " ")
    return f"HTTP {resp.status_code} from {resp.request.method} {resp.request.url.path}: {body}"
