"""CrowdStrike Falcon Next-Gen SIEM connector.

Log sources: a LogScale query (`groupBy([#repo, Vendor, Product, #event.module, #event.dataset, #event_simpleName])`)
             run through the NG-SIEM query-jobs API over a lookback window.
Rules:       Correlation rules (`/correlation-rules/combined/rules/v1`). Techniques are taken from the
             rule's tactic/technique fields and from T#### ids in name, description and search.
Auth:        OAuth2 client credentials (API client with "Correlation Rules: Read" and
             "NGSIEM: Read" scopes).
"""
from __future__ import annotations

import asyncio
import json

from .base import BaseConnector, ConnectorError, FetchResult, FieldSpec, LogSourceRecord, RuleRecord, TestResult, extract_techniques
from .http import error_text, make_client

DEFAULT_QUERY = (
    "groupBy([#repo, Vendor, Product, #event.module, #event.dataset, #event_simpleName], "
    "function=[count(as=count), max(@timestamp, as=last_seen)], limit=20000)"
)


class CrowdStrikeConnector(BaseConnector):
    type = "crowdstrike"
    label = "CrowdStrike Falcon Next-Gen SIEM"
    description = "Reads ingested data sources from NG-SIEM (LogScale query) and Falcon correlation rules via the Falcon API."
    docs_url = "https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis"
    fields = [
        FieldSpec("base_url", "Falcon API base URL", type="select", required=True, default="https://api.crowdstrike.com", options=["https://api.crowdstrike.com", "https://api.us-2.crowdstrike.com", "https://api.eu-1.crowdstrike.com", "https://api.laggar.gcw.crowdstrike.com"]),
        FieldSpec("client_id", "API client ID", type="text", required=True),
        FieldSpec("client_secret", "API client secret", type="password", secret=True, required=True),
        FieldSpec("member_cid", "Member CID (Flight Control)", type="text", help="Optional. Child CID when using a parent API client."),
        FieldSpec("repository", "NG-SIEM repository", type="text", default="search-all", help="Repository (or view) to query, e.g. `search-all` or your `*_ngsiem` repo."),
        FieldSpec("lookback", "Lookback", type="text", default="7d", help="LogScale relative time, e.g. 24h, 7d."),
        FieldSpec("log_source_query", "Log source query", type="textarea", default=DEFAULT_QUERY, help="LogScale query returning one row per data source. Fields recognised: Vendor, Product, #event.module, #event.dataset, #event_simpleName, #repo, count, last_seen."),
        FieldSpec("include_disabled_rules", "Include disabled correlation rules", type="bool", default=False),
    ]

    async def _token(self, client) -> str:
        data = {"client_id": self.cfg("client_id", ""), "client_secret": self.sec("client_secret", "")}
        if self.cfg("member_cid"):
            data["member_cid"] = self.cfg("member_cid")
        resp = await client.post(self._url("/oauth2/token"), data=data)
        if resp.status_code not in (200, 201):
            raise ConnectorError(f"OAuth2 token request failed: {error_text(resp)}")
        return resp.json()["access_token"]

    def _url(self, path: str) -> str:
        return self.cfg("base_url", "https://api.crowdstrike.com").rstrip("/") + path

    async def test(self) -> TestResult:
        try:
            async with make_client() as client:
                token = await self._token(client)
                client.headers["Authorization"] = f"Bearer {token}"
                resp = await client.get(self._url("/correlation-rules/queries/rules/v1"), params={"limit": 1})
                rules_ok = resp.status_code == 200
                return TestResult(True, "Authenticated with Falcon API." + ("" if rules_ok else f" Correlation rules scope check: {error_text(resp)}"), {"correlation_rules_scope": rules_ok})
        except ConnectorError as exc:
            return TestResult(False, str(exc))
        except Exception as exc:  # noqa: BLE001
            return TestResult(False, f"Connection failed: {exc}")

    async def _query(self, client, repo: str, query: str, start: str) -> list[dict]:
        resp = await client.post(
            self._url(f"/humio/api/v1/repositories/{repo}/queryjobs"),
            json={"queryString": query, "start": start, "end": "now", "isLive": False},
        )
        if resp.status_code not in (200, 201):
            raise ConnectorError(f"NG-SIEM query failed: {error_text(resp)}")
        job_id = resp.json()["id"]
        for _ in range(600):
            poll = await client.get(self._url(f"/humio/api/v1/repositories/{repo}/queryjobs/{job_id}"))
            if poll.status_code != 200:
                raise ConnectorError(f"NG-SIEM query poll failed: {error_text(poll)}")
            body = poll.json()
            if body.get("done"):
                return body.get("events", [])
            await asyncio.sleep(1)
        raise ConnectorError("NG-SIEM query timed out")

    async def fetch(self) -> FetchResult:
        out = FetchResult()
        async with make_client(timeout=120.0) as client:
            token = await self._token(client)
            client.headers["Authorization"] = f"Bearer {token}"

            repo = self.cfg("repository", "search-all")
            rows = await self._query(client, repo, self.cfg("log_source_query", DEFAULT_QUERY), self.cfg("lookback", "7d"))
            for row in rows:
                vendor = row.get("Vendor") or row.get("#Vendor") or ""
                product = row.get("Product") or ""
                module = row.get("#event.module") or row.get("event.module") or ""
                dataset = row.get("#event.dataset") or row.get("event.dataset") or ""
                simple = row.get("#event_simpleName") or row.get("event_simpleName") or ""
                parts = [p for p in (vendor, product, module, dataset, simple) if p]
                if not parts:
                    continue
                name = " / ".join(dict.fromkeys(parts))
                if simple and not vendor:
                    vendor, product = "CrowdStrike", "Falcon"
                out.log_sources.append(
                    LogSourceRecord(
                        external_id=f"{row.get('#repo', repo)}/{name}",
                        name=name,
                        kind="data source",
                        vendor=str(vendor),
                        product=str(product),
                        event_count=int(float(row.get("count", 0) or 0)),
                        attributes={"repository": row.get("#repo", repo), "event_module": module, "dataset": dataset, "event_simpleName": simple},
                    )
                )

            # Correlation rules
            ids: list[str] = []
            offset = 0
            while True:
                resp = await client.get(self._url("/correlation-rules/queries/rules/v1"), params={"limit": 500, "offset": offset})
                if resp.status_code == 403:
                    out.warnings.append("API client lacks 'Correlation Rules: Read' scope; rules skipped.")
                    break
                if resp.status_code != 200:
                    raise ConnectorError(error_text(resp))
                body = resp.json()
                batch = body.get("resources", []) or []
                ids.extend(batch)
                total = body.get("meta", {}).get("pagination", {}).get("total", len(ids))
                offset += len(batch)
                if not batch or offset >= total:
                    break
            for i in range(0, len(ids), 100):
                chunk = ids[i : i + 100]
                resp = await client.get(self._url("/correlation-rules/entities/rules/v1"), params=[("ids", x) for x in chunk])
                if resp.status_code != 200:
                    raise ConnectorError(error_text(resp))
                for r in resp.json().get("resources", []) or []:
                    status = str(r.get("status", "")).lower()
                    enabled = status in ("active", "enabled", "")
                    if not enabled and not self.cfg("include_disabled_rules", False):
                        continue
                    search = r.get("search") or {}
                    filt = search.get("filter", "") if isinstance(search, dict) else str(search)
                    tech_fields = " ".join(
                        str(r.get(k, "")) for k in ("technique", "techniques", "mitre_attack", "mitre_technique", "tags")
                    )
                    techniques = extract_techniques(tech_fields, r.get("name"), r.get("description"), filt, json.dumps(r.get("mitre", "")))
                    out.rules.append(
                        RuleRecord(
                            external_id=str(r.get("id")),
                            name=r.get("name", ""),
                            description=r.get("description", "") or "",
                            enabled=enabled,
                            severity=str(r.get("severity", "")),
                            query=str(filt)[:2000],
                            techniques=techniques,
                            tactics=[str(r.get("tactic"))] if r.get("tactic") else [],
                            attributes={"status": status, "customer_id": r.get("customer_id"), "trigger_mode": r.get("trigger_mode")},
                        )
                    )
        return out
