"""Cribl Stream connector (self-managed leader or Cribl.Cloud).

Cribl is a telemetry pipeline, so it tells us which feeds are flowing (sources / inputs
and the sourcetypes referenced by routes) - it has no detection rules.
"""
from __future__ import annotations

import re

from .base import BaseConnector, ConnectorError, FetchResult, FieldSpec, LogSourceRecord, TestResult
from .http import error_text, make_client

CLOUD_TOKEN_URL = "https://login.cribl.cloud/oauth/token"


class CriblConnector(BaseConnector):
    type = "cribl"
    label = "Cribl Stream"
    description = "Lists configured sources (inputs) and the sourcetypes referenced by routes in a worker group. Provides log sources only."
    docs_url = "https://docs.cribl.io/api/"
    provides_rules = False
    fields = [
        FieldSpec("base_url", "Leader / Cribl.Cloud URL", type="url", required=True, placeholder="https://main-myorg.cribl.cloud or https://leader:9000"),
        FieldSpec("auth_mode", "Authentication", type="select", options=["bearer", "cloud_oauth", "basic"], default="bearer", help="bearer = API token; cloud_oauth = Cribl.Cloud client credentials; basic = local username/password (self-managed)."),
        FieldSpec("token", "Bearer token", type="password", secret=True),
        FieldSpec("client_id", "Cloud client ID", type="text"),
        FieldSpec("client_secret", "Cloud client secret", type="password", secret=True),
        FieldSpec("username", "Username", type="text"),
        FieldSpec("password", "Password", type="password", secret=True),
        FieldSpec("worker_group", "Worker group / fleet", type="text", default="default"),
        FieldSpec("verify_ssl", "Verify TLS certificate", type="bool", default=True),
        FieldSpec("include_disabled", "Include disabled sources", type="bool", default=False),
    ]

    def _url(self, path: str) -> str:
        return self.cfg("base_url", "").rstrip("/") + path

    async def _auth(self, client) -> None:
        mode = self.cfg("auth_mode", "bearer")
        if mode == "bearer":
            token = self.sec("token")
            if not token:
                raise ConnectorError("Bearer token required.")
        elif mode == "cloud_oauth":
            resp = await client.post(
                CLOUD_TOKEN_URL,
                json={"grant_type": "client_credentials", "client_id": self.cfg("client_id", ""), "client_secret": self.sec("client_secret", ""), "audience": "https://api.cribl.cloud"},
            )
            if resp.status_code != 200:
                raise ConnectorError(f"Cribl.Cloud OAuth failed: {error_text(resp)}")
            token = resp.json()["access_token"]
        else:
            resp = await client.post(self._url("/api/v1/auth/login"), json={"username": self.cfg("username", ""), "password": self.sec("password", "")})
            if resp.status_code != 200:
                raise ConnectorError(f"Cribl login failed: {error_text(resp)}")
            token = resp.json()["token"]
        client.headers["Authorization"] = f"Bearer {token}"

    async def test(self) -> TestResult:
        try:
            async with make_client(verify=bool(self.cfg("verify_ssl", True))) as client:
                await self._auth(client)
                resp = await client.get(self._url("/api/v1/system/info"))
                if resp.status_code != 200:
                    resp = await client.get(self._url("/api/v1/master/groups"))
                if resp.status_code != 200:
                    return TestResult(False, error_text(resp))
                return TestResult(True, "Authenticated with Cribl API.")
        except ConnectorError as exc:
            return TestResult(False, str(exc))
        except Exception as exc:  # noqa: BLE001
            return TestResult(False, f"Connection failed: {exc}")

    async def fetch(self) -> FetchResult:
        out = FetchResult()
        group = self.cfg("worker_group", "default")
        async with make_client(verify=bool(self.cfg("verify_ssl", True))) as client:
            await self._auth(client)
            prefix = f"/api/v1/m/{group}" if group else "/api/v1"
            resp = await client.get(self._url(f"{prefix}/system/inputs"))
            if resp.status_code == 404 and group:
                prefix = "/api/v1"
                resp = await client.get(self._url(f"{prefix}/system/inputs"))
            if resp.status_code != 200:
                raise ConnectorError(error_text(resp))
            for item in resp.json().get("items", []):
                if item.get("disabled") and not self.cfg("include_disabled", False):
                    continue
                itype = item.get("type", "")
                meta = {m.get("name"): m.get("value") for m in item.get("metadata", []) or [] if isinstance(m, dict)}
                name = item.get("id", "")
                sourcetype = str(meta.get("sourcetype", "")).strip("'\"")
                out.log_sources.append(
                    LogSourceRecord(
                        external_id=f"input/{name}",
                        name=f"{name} ({itype})" + (f" sourcetype={sourcetype}" if sourcetype else ""),
                        kind=f"cribl input:{itype}",
                        vendor=str(meta.get("vendor", "")).strip("'\""),
                        product=str(meta.get("product", "")).strip("'\""),
                        attributes={"type": itype, "description": item.get("description", ""), "metadata": meta, "worker_group": group},
                    )
                )
            # Sourcetypes referenced by route filters
            resp = await client.get(self._url(f"{prefix}/routes"))
            if resp.status_code == 200:
                seen: set[str] = set()
                for table in resp.json().get("items", []):
                    for route in table.get("routes", []) or []:
                        if route.get("disabled"):
                            continue
                        filt = route.get("filter", "") or ""
                        for st in re.findall(r"sourcetype\s*[=!]=+\s*['\"]([^'\"]+)['\"]", filt):
                            if st in seen:
                                continue
                            seen.add(st)
                            out.log_sources.append(
                                LogSourceRecord(
                                    external_id=f"route-sourcetype/{st}",
                                    name=st,
                                    kind="sourcetype (route filter)",
                                    attributes={"route": route.get("name"), "filter": filt, "pipeline": route.get("pipeline"), "output": route.get("output")},
                                )
                            )
            else:
                out.warnings.append(f"Routes not readable: {error_text(resp)}")
        return out
