"""Generic MCP (Model Context Protocol) connector.

Connects to any MCP server over Streamable HTTP (JSON-RPC 2.0) - for example a vendor's
SIEM MCP server - and calls two tools: one that returns the ingested log sources and one
that returns detection rules. Tool results are expected to be JSON (a list, or an object
with `items`/`results`/`data`). Field names are matched flexibly.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .base import BaseConnector, ConnectorError, FetchResult, FieldSpec, LogSourceRecord, RuleRecord, TestResult, extract_techniques
from .http import error_text, make_client

PROTOCOL_VERSION = "2025-06-18"


class MCPClient:
    def __init__(self, url: str, headers: dict[str, str], verify: bool = True):
        self.url = url
        self.headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json", **headers}
        self.verify = verify
        self.session_id: str | None = None
        self._id = 0

    def _next(self) -> int:
        self._id += 1
        return self._id

    @staticmethod
    def _parse_sse(text: str) -> dict:
        last: dict | None = None
        for block in text.split("\n\n"):
            data_lines = [ln[5:].strip() for ln in block.splitlines() if ln.startswith("data:")]
            if not data_lines:
                continue
            try:
                msg = json.loads("\n".join(data_lines))
            except ValueError:
                continue
            if isinstance(msg, dict) and ("result" in msg or "error" in msg):
                last = msg
        if last is None:
            raise ConnectorError("No JSON-RPC response found in SSE stream")
        return last

    async def call(self, client, method: str, params: dict | None = None, notify: bool = False) -> Any:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            payload["id"] = self._next()
        headers = dict(self.headers)
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        resp = await client.post(self.url, json=payload, headers=headers)
        if resp.status_code >= 400:
            raise ConnectorError(error_text(resp))
        if sid := resp.headers.get("Mcp-Session-Id"):
            self.session_id = sid
        if notify or resp.status_code == 202 or not resp.content:
            return None
        ctype = resp.headers.get("content-type", "")
        msg = self._parse_sse(resp.text) if "text/event-stream" in ctype else resp.json()
        if "error" in msg:
            raise ConnectorError(f"MCP error: {msg['error'].get('message', msg['error'])}")
        return msg.get("result")

    async def initialize(self, client) -> dict:
        result = await self.call(
            client,
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "attack-logging-coverage", "version": "0.1.0"},
            },
        )
        await self.call(client, "notifications/initialized", notify=True)
        return result or {}

    async def list_tools(self, client) -> list[dict]:
        result = await self.call(client, "tools/list")
        return (result or {}).get("tools", [])

    async def call_tool(self, client, name: str, arguments: dict) -> Any:
        result = await self.call(client, "tools/call", {"name": name, "arguments": arguments}) or {}
        if result.get("isError"):
            raise ConnectorError(f"Tool {name} returned an error: {json.dumps(result.get('content'))[:300]}")
        if "structuredContent" in result and result["structuredContent"] is not None:
            return result["structuredContent"]
        texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
        joined = "\n".join(texts).strip()
        try:
            return json.loads(joined)
        except ValueError:
            return joined


def _as_items(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [x if isinstance(x, dict) else {"name": str(x)} for x in data]
    if isinstance(data, dict):
        for key in ("items", "results", "data", "log_sources", "sources", "rules", "resources", "entry"):
            if isinstance(data.get(key), list):
                return _as_items(data[key])
        return [data]
    if isinstance(data, str):
        return [{"name": ln.strip()} for ln in data.splitlines() if ln.strip()]
    return []


def _pick(item: dict, *keys: str, default: Any = "") -> Any:
    lower = {k.lower(): v for k, v in item.items()}
    for k in keys:
        if k.lower() in lower and lower[k.lower()] not in (None, ""):
            return lower[k.lower()]
    return default


class MCPConnector(BaseConnector):
    type = "mcp"
    label = "MCP server (generic)"
    description = "Call any MCP server (Streamable HTTP) that exposes tools returning log sources and detection rules - e.g. a vendor SIEM MCP server."
    docs_url = "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports"
    fields = [
        FieldSpec("url", "MCP endpoint URL", type="url", required=True, placeholder="https://mcp.example.com/mcp"),
        FieldSpec("auth_header", "Authorization header value", type="password", secret=True, help="e.g. `Bearer <token>`. Leave empty for unauthenticated servers."),
        FieldSpec("extra_headers", "Extra headers (JSON)", type="textarea", placeholder='{"X-Org": "acme"}'),
        FieldSpec("log_sources_tool", "Log sources tool", type="text", required=True, placeholder="list_sourcetypes", help="Tool returning the ingested log sources."),
        FieldSpec("log_sources_args", "Log sources tool arguments (JSON)", type="textarea", default="{}"),
        FieldSpec("rules_tool", "Rules tool", type="text", placeholder="list_detection_rules", help="Optional tool returning detection rules."),
        FieldSpec("rules_args", "Rules tool arguments (JSON)", type="textarea", default="{}"),
        FieldSpec("verify_ssl", "Verify TLS certificate", type="bool", default=True),
    ]

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.sec("auth_header"):
            headers["Authorization"] = self.sec("auth_header")
        extra = self.cfg("extra_headers")
        if extra:
            try:
                headers.update({str(k): str(v) for k, v in json.loads(extra).items()})
            except ValueError as exc:
                raise ConnectorError(f"Extra headers is not valid JSON: {exc}") from exc
        return headers

    def _args(self, key: str) -> dict:
        raw = self.cfg(key, "{}") or "{}"
        try:
            v = json.loads(raw)
        except ValueError as exc:
            raise ConnectorError(f"{key} is not valid JSON: {exc}") from exc
        return v if isinstance(v, dict) else {}

    async def test(self) -> TestResult:
        try:
            mcp = MCPClient(self.cfg("url", ""), self._headers(), bool(self.cfg("verify_ssl", True)))
            async with make_client(verify=bool(self.cfg("verify_ssl", True))) as client:
                info = await mcp.initialize(client)
                tools = await mcp.list_tools(client)
                names = [t.get("name") for t in tools]
                missing = [t for t in (self.cfg("log_sources_tool"), self.cfg("rules_tool")) if t and t not in names]
                server = (info.get("serverInfo") or {}).get("name", "MCP server")
                msg = f"Connected to {server}; {len(tools)} tools available."
                if missing:
                    msg += f" Configured tools not found: {', '.join(missing)}."
                return TestResult(not missing, msg, {"tools": names})
        except ConnectorError as exc:
            return TestResult(False, str(exc))
        except Exception as exc:  # noqa: BLE001
            return TestResult(False, f"Connection failed: {exc}")

    async def fetch(self) -> FetchResult:
        out = FetchResult()
        mcp = MCPClient(self.cfg("url", ""), self._headers(), bool(self.cfg("verify_ssl", True)))
        async with make_client(verify=bool(self.cfg("verify_ssl", True)), timeout=300.0) as client:
            await mcp.initialize(client)
            data = await mcp.call_tool(client, self.cfg("log_sources_tool", ""), self._args("log_sources_args"))
            for i, item in enumerate(_as_items(data)):
                name = str(_pick(item, "name", "sourcetype", "source", "log_source", "dataset", "id", "title", default=f"source-{i}"))
                mitre = _pick(item, "mitre_log_sources", "attack_log_sources", default=[])
                if isinstance(mitre, str):
                    mitre = [m.strip() for m in re.split(r"[;,]", mitre) if m.strip()]
                out.log_sources.append(
                    LogSourceRecord(
                        external_id=str(_pick(item, "id", "external_id", default=name)),
                        name=name,
                        kind=str(_pick(item, "kind", "type", default="sourcetype")),
                        vendor=str(_pick(item, "vendor", "Vendor")),
                        product=str(_pick(item, "product", "Product")),
                        event_count=int(float(_pick(item, "event_count", "count", "events", "total", default=0) or 0)),
                        attributes={k: v for k, v in item.items() if isinstance(v, (str, int, float, bool))},
                        explicit_log_sources=list(mitre or []),
                    )
                )
            if self.cfg("rules_tool"):
                data = await mcp.call_tool(client, self.cfg("rules_tool", ""), self._args("rules_args"))
                for i, item in enumerate(_as_items(data)):
                    name = str(_pick(item, "name", "title", "rule_name", "id", default=f"rule-{i}"))
                    tech_raw = _pick(item, "techniques", "technique", "mitre_attack", "mitre_techniques", "attack", "tags", default=[])
                    tech_text = " ".join(map(str, tech_raw)) if isinstance(tech_raw, list) else str(tech_raw)
                    techniques = extract_techniques(tech_text) or extract_techniques(name, str(_pick(item, "description")))
                    enabled_raw = _pick(item, "enabled", "status", "disabled", default=True)
                    if isinstance(enabled_raw, str):
                        enabled = enabled_raw.lower() in ("true", "1", "enabled", "active", "on", "")
                    elif "disabled" in {k.lower() for k in item}:
                        enabled = not bool(enabled_raw)
                    else:
                        enabled = bool(enabled_raw)
                    out.rules.append(
                        RuleRecord(
                            external_id=str(_pick(item, "id", "external_id", default=name)),
                            name=name,
                            description=str(_pick(item, "description")),
                            enabled=enabled,
                            severity=str(_pick(item, "severity", "level", "risk")),
                            query=str(_pick(item, "query", "search", "filter"))[:2000],
                            url=str(_pick(item, "url", "link")),
                            techniques=techniques,
                            attributes={k: v for k, v in item.items() if isinstance(v, (str, int, float, bool))},
                        )
                    )
        return out
