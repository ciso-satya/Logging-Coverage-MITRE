"""Splunk Enterprise / Splunk Cloud connector (REST API on port 8089).

Log sources: `| tstats count where index=* by index, sourcetype` over a lookback window.
Rules:       saved searches (`/services/saved/searches`), optionally only Enterprise Security
             correlation searches. ATT&CK techniques are read from the ES annotations
             (`action.correlationsearch.annotations` -> mitre_attack) and from T#### ids in
             the name/description/search.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .base import BaseConnector, ConnectorError, FetchResult, FieldSpec, LogSourceRecord, RuleRecord, TestResult, extract_techniques
from .http import error_text, make_client


class SplunkConnector(BaseConnector):
    type = "splunk"
    label = "Splunk (Enterprise / Cloud)"
    description = "Reads ingested sourcetypes via tstats and saved/correlation searches via the REST API (port 8089)."
    docs_url = "https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch"
    fields = [
        FieldSpec("base_url", "Management URL", type="url", required=True, placeholder="https://splunk.example.com:8089", help="Splunk management port (8089), not the web UI."),
        FieldSpec("auth_mode", "Authentication", type="select", options=["token", "basic"], default="token"),
        FieldSpec("token", "Bearer token", type="password", secret=True, help="Splunk authentication token (Settings > Tokens)."),
        FieldSpec("username", "Username", type="text"),
        FieldSpec("password", "Password", type="password", secret=True),
        FieldSpec("verify_ssl", "Verify TLS certificate", type="bool", default=True),
        FieldSpec("lookback", "Lookback for ingested data", type="text", default="-7d", help="Splunk time modifier used to decide which sourcetypes are 'live'."),
        FieldSpec("index_filter", "Index filter", type="text", default="*", help="tstats `index=` filter, e.g. `*` or `main OR security`."),
        FieldSpec("rules_scope", "Rules to import", type="select", options=["correlation", "alerts", "all"], default="correlation", help="correlation = Enterprise Security correlation searches; alerts = saved searches with alert actions; all = every enabled saved search."),
        FieldSpec("app", "App namespace", type="text", default="-", help="Restrict saved searches to one app (use `-` for all)."),
    ]

    def _client(self):
        headers = {}
        auth = None
        if self.cfg("auth_mode", "token") == "token":
            token = self.sec("token")
            if not token:
                raise ConnectorError("A bearer token is required (or switch to basic auth).")
            headers["Authorization"] = f"Bearer {token}"
        else:
            auth = (self.cfg("username", ""), self.sec("password", ""))
            if not auth[0]:
                raise ConnectorError("Username and password are required for basic auth.")
        return make_client(verify=bool(self.cfg("verify_ssl", True)), headers=headers, auth=auth)

    def _url(self, path: str) -> str:
        return self.cfg("base_url", "").rstrip("/") + path

    async def test(self) -> TestResult:
        try:
            async with self._client() as client:
                resp = await client.get(self._url("/services/server/info"), params={"output_mode": "json"})
                if resp.status_code != 200:
                    return TestResult(False, error_text(resp))
                content = resp.json()["entry"][0]["content"]
                return TestResult(True, f"Connected to {content.get('serverName')} (Splunk {content.get('version')})", {"version": content.get("version"), "server": content.get("serverName")})
        except ConnectorError as exc:
            return TestResult(False, str(exc))
        except Exception as exc:  # noqa: BLE001
            return TestResult(False, f"Connection failed: {exc}")

    async def _oneshot(self, client, spl: str, earliest: str = "-7d") -> list[dict]:
        resp = await client.post(
            self._url("/services/search/jobs"),
            data={"search": spl, "exec_mode": "oneshot", "output_mode": "json", "earliest_time": earliest, "latest_time": "now", "count": 0},
            timeout=300.0,
        )
        if resp.status_code != 200:
            raise ConnectorError(error_text(resp))
        return resp.json().get("results", [])

    async def fetch(self) -> FetchResult:
        out = FetchResult()
        lookback = self.cfg("lookback", "-7d")
        index_filter = self.cfg("index_filter", "*")
        async with self._client() as client:
            spl = f"| tstats count latest(_time) as last_seen where index={index_filter} by index, sourcetype"
            for row in await self._oneshot(client, spl, lookback):
                st = row.get("sourcetype", "")
                idx = row.get("index", "")
                if not st:
                    continue
                last_seen = None
                try:
                    last_seen = datetime.fromtimestamp(float(row.get("last_seen", 0)), tz=timezone.utc).isoformat()
                except (TypeError, ValueError):
                    pass
                out.log_sources.append(
                    LogSourceRecord(
                        external_id=f"{idx}/{st}",
                        name=st,
                        kind="sourcetype",
                        event_count=int(float(row.get("count", 0) or 0)),
                        last_seen=last_seen,
                        attributes={"index": idx},
                    )
                )

            scope = self.cfg("rules_scope", "correlation")
            app = self.cfg("app", "-") or "-"
            params = {"output_mode": "json", "count": 0}
            if scope == "correlation":
                params["search"] = 'action.correlationsearch.enabled=1'
            elif scope == "alerts":
                params["search"] = "alert_type!=always OR actions=*"
            resp = await client.get(self._url(f"/servicesNS/-/{app}/saved/searches"), params=params, timeout=300.0)
            if resp.status_code != 200:
                raise ConnectorError(error_text(resp))
            base_ui = re.sub(r":8089(/)?$", "", self.cfg("base_url", "").rstrip("/"))
            for entry in resp.json().get("entry", []):
                c = entry.get("content", {})
                name = entry.get("name", "")
                techniques: set[str] = set()
                tactics: list[str] = []
                ann_raw = c.get("action.correlationsearch.annotations")
                if ann_raw:
                    try:
                        ann = json.loads(ann_raw) if isinstance(ann_raw, str) else ann_raw
                        for t in ann.get("mitre_attack", []) or []:
                            techniques.update(extract_techniques(t))
                    except (ValueError, AttributeError):
                        pass
                techniques.update(extract_techniques(name, c.get("description"), c.get("action.correlationsearch.label")))
                enabled = not (str(c.get("disabled", "0")).lower() in ("1", "true"))
                is_corr = str(c.get("action.correlationsearch.enabled", "0")).lower() in ("1", "true")
                out.rules.append(
                    RuleRecord(
                        external_id=name,
                        name=c.get("action.correlationsearch.label") or name,
                        description=c.get("description", "") or "",
                        enabled=enabled,
                        severity=str(c.get("action.notable.param.severity") or c.get("alert.severity") or ""),
                        query=(c.get("search") or "")[:2000],
                        url=f"{base_ui}/app/{entry.get('acl', {}).get('app', 'search')}/saved/searches" if base_ui else "",
                        techniques=sorted(techniques),
                        tactics=tactics,
                        log_sources=sorted(set(re.findall(r"sourcetype\s*=\s*\"?([\w:\-./]+)", c.get("search") or ""))),
                        attributes={"app": entry.get("acl", {}).get("app"), "correlation_search": is_corr, "cron": c.get("cron_schedule")},
                    )
                )
        return out
