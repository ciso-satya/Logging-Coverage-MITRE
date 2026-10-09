import asyncio
import json

from app.connectors.base import extract_techniques
from app.connectors.file_import import parse_log_sources, parse_rules
from app.connectors.mcp import MCPClient, _as_items


def test_extract_techniques():
    assert extract_techniques("Detects T1059.001 and t1003 and T1059") == ["T1003", "T1059", "T1059.001"]
    assert extract_techniques(None, "") == []


def test_parse_log_sources_csv_and_json():
    rows = parse_log_sources("# comment\nname,vendor,product,event_count\nwineventlog:security,Microsoft,Windows,42\nsyslog\n")
    assert [(r.name, r.vendor, r.event_count) for r in rows] == [("wineventlog:security", "Microsoft", 42), ("syslog", "", 0)]
    rows = parse_log_sources(json.dumps([{"name": "custom", "mitre_log_sources": ["dns:query"], "count": 5}, "plain"]))
    assert rows[0].explicit_log_sources == ["dns:query"] and rows[0].event_count == 5 and rows[1].name == "plain"


def test_parse_rules_sigma():
    sigma = """title: Encoded PowerShell
id: abc-123
status: experimental
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: ' -enc '
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
---
title: Old rule
status: deprecated
logsource:
  product: linux
detection:
  condition: x
tags: [attack.t1053]
"""
    rules = parse_rules(sigma)
    assert rules[0].techniques == ["T1059.001"] and rules[0].tactics == ["execution"] and rules[0].severity == "high"
    assert rules[0].log_sources == ["windows process_creation"]
    assert rules[1].enabled is False


def test_parse_rules_csv():
    rules = parse_rules("name,techniques,enabled\nMimikatz,T1003.001 T1003,true\nOld rule,T1053,false\n")
    assert rules[0].techniques == ["T1003", "T1003.001"] and rules[1].enabled is False


def test_mcp_items_and_sse_parsing():
    assert _as_items({"items": [{"name": "a"}]}) == [{"name": "a"}]
    assert _as_items(["x"]) == [{"name": "x"}]
    assert _as_items("a\nb") == [{"name": "a"}, {"name": "b"}]
    sse = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n\n'
    assert MCPClient._parse_sse(sse)["result"] == {"tools": []}


def test_mcp_client_against_fake_server():
    """Drive the MCP client against an in-process fake Streamable-HTTP server using httpx's ASGI transport."""
    import httpx
    from fastapi import FastAPI, Request

    from app.connectors.mcp import MCPConnector

    fake = FastAPI()

    @fake.post("/mcp")
    async def mcp(req: Request):
        body = await req.json()
        if body["method"] == "initialize":
            return {"jsonrpc": "2.0", "id": body["id"], "result": {"serverInfo": {"name": "fake-siem"}}}
        if body["method"] == "notifications/initialized":
            return {}
        if body["method"] == "tools/list":
            return {"jsonrpc": "2.0", "id": body["id"], "result": {"tools": [{"name": "list_sourcetypes"}, {"name": "list_rules"}]}}
        if body["method"] == "tools/call":
            name = body["params"]["name"]
            if name == "list_sourcetypes":
                payload = [{"sourcetype": "wineventlog:security", "count": 12}]
            else:
                payload = {"results": [{"title": "Rule A", "mitre_attack": "T1059.001", "status": "enabled"}, {"title": "Rule B T1003", "disabled": True}]}
            return {"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": json.dumps(payload)}]}}
        return {"jsonrpc": "2.0", "id": body.get("id"), "error": {"message": "unknown"}}

    transport = httpx.ASGITransport(app=fake)
    import app.connectors.mcp as mcp_mod

    orig = mcp_mod.make_client
    mcp_mod.make_client = lambda **kw: httpx.AsyncClient(transport=transport, base_url="http://fake")  # noqa: E731
    try:
        c = MCPConnector({"url": "http://fake/mcp", "log_sources_tool": "list_sourcetypes", "rules_tool": "list_rules"}, {"auth_header": "Bearer x"})
        t = asyncio.run(c.test())
        assert t.ok and "fake-siem" in t.message
        res = asyncio.run(c.fetch())
        assert res.log_sources[0].name == "wineventlog:security" and res.log_sources[0].event_count == 12
        assert res.rules[0].techniques == ["T1059.001"] and res.rules[0].enabled
        assert res.rules[1].techniques == ["T1003"] and res.rules[1].enabled is False
    finally:
        mcp_mod.make_client = orig
