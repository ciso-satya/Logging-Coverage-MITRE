"""Import an inventory from pasted/uploaded text: JSON, CSV or Sigma rules.

Log sources - one per line  `name[,vendor,product,event_count]`, or a JSON array of objects
              {"name": ..., "vendor": ..., "product": ..., "kind": ..., "mitre_log_sources": [...]}.
Rules       - JSON array of {"name", "techniques": [...], "enabled", "severity", "description"},
              CSV `name,techniques (space or ; separated),enabled`, or Sigma YAML documents
              separated by `---` (techniques read from `tags: attack.t1059.001`).
"""
from __future__ import annotations

import csv
import io
import json

import yaml

from .base import BaseConnector, FetchResult, FieldSpec, LogSourceRecord, RuleRecord, TestResult, extract_techniques


def parse_log_sources(text: str) -> list[LogSourceRecord]:
    text = (text or "").strip()
    if not text:
        return []
    if text.startswith("["):
        items = json.loads(text)
        out = []
        for i, it in enumerate(items):
            if isinstance(it, str):
                out.append(LogSourceRecord(external_id=it, name=it))
                continue
            name = it.get("name") or it.get("sourcetype") or it.get("id") or f"source-{i}"
            out.append(
                LogSourceRecord(
                    external_id=str(it.get("id") or name),
                    name=str(name),
                    kind=str(it.get("kind") or it.get("type") or "sourcetype"),
                    vendor=str(it.get("vendor") or ""),
                    product=str(it.get("product") or ""),
                    event_count=int(it.get("event_count") or it.get("count") or 0),
                    attributes={k: v for k, v in it.items() if k not in ("name", "id", "kind", "type", "vendor", "product", "event_count", "count", "mitre_log_sources")},
                    explicit_log_sources=list(it.get("mitre_log_sources") or []),
                )
            )
        return out
    out = []
    for row in csv.reader(io.StringIO(text)):
        if not row or not row[0].strip() or row[0].strip().startswith("#"):
            continue
        if row[0].strip().lower() == "name":
            continue
        name = row[0].strip()
        vendor = row[1].strip() if len(row) > 1 else ""
        product = row[2].strip() if len(row) > 2 else ""
        try:
            count = int(row[3]) if len(row) > 3 and row[3].strip() else 0
        except ValueError:
            count = 0
        out.append(LogSourceRecord(external_id=name, name=name, vendor=vendor, product=product, event_count=count))
    return out


def parse_sigma(text: str) -> list[RuleRecord]:
    out = []
    for i, doc in enumerate(yaml.safe_load_all(text)):
        if not isinstance(doc, dict) or "title" not in doc:
            continue
        tags = [str(t) for t in doc.get("tags", []) or []]
        techniques = sorted({t.split(".", 1)[1].upper() for t in tags if t.lower().startswith("attack.t")})
        tactics = sorted({t.split(".", 1)[1] for t in tags if t.lower().startswith("attack.") and not t.lower().startswith("attack.t") and not t.lower().startswith("attack.g") and not t.lower().startswith("attack.s")})
        ls = doc.get("logsource", {}) or {}
        ls_name = " ".join(str(v) for v in (ls.get("product"), ls.get("service"), ls.get("category")) if v)
        out.append(
            RuleRecord(
                external_id=str(doc.get("id") or f"sigma-{i}"),
                name=str(doc["title"]),
                description=str(doc.get("description", "")),
                enabled=str(doc.get("status", "")).lower() not in ("deprecated", "unsupported"),
                severity=str(doc.get("level", "")),
                query=json.dumps(doc.get("detection", {}))[:2000],
                techniques=techniques,
                tactics=tactics,
                log_sources=[ls_name] if ls_name else [],
                attributes={"format": "sigma", "tags": tags, "logsource": ls},
            )
        )
    return out


def parse_rules(text: str) -> list[RuleRecord]:
    text = (text or "").strip()
    if not text:
        return []
    if text.startswith("["):
        out = []
        for i, it in enumerate(json.loads(text)):
            name = it.get("name") or it.get("title") or f"rule-{i}"
            techniques = it.get("techniques") or it.get("mitre_attack") or it.get("attack") or []
            if isinstance(techniques, str):
                techniques = extract_techniques(techniques)
            techniques = extract_techniques(" ".join(map(str, techniques))) or extract_techniques(name, it.get("description"), " ".join(map(str, it.get("tags", []) or [])))
            out.append(
                RuleRecord(
                    external_id=str(it.get("id") or name),
                    name=str(name),
                    description=str(it.get("description", "")),
                    enabled=bool(it.get("enabled", True)),
                    severity=str(it.get("severity") or it.get("level") or ""),
                    query=str(it.get("query") or it.get("search") or "")[:2000],
                    url=str(it.get("url", "")),
                    techniques=techniques,
                    tactics=[str(t) for t in it.get("tactics", []) or []],
                    log_sources=[str(s) for s in it.get("log_sources", []) or []],
                    attributes={"format": "json"},
                )
            )
        return out
    if "title:" in text and ("detection:" in text or "logsource:" in text):
        return parse_sigma(text)
    out = []
    for row in csv.reader(io.StringIO(text)):
        if not row or not row[0].strip() or row[0].strip().startswith("#") or row[0].strip().lower() == "name":
            continue
        name = row[0].strip()
        techniques = extract_techniques(row[1] if len(row) > 1 else "", name)
        enabled = (row[2].strip().lower() not in ("false", "0", "no", "disabled")) if len(row) > 2 else True
        out.append(RuleRecord(external_id=name, name=name, enabled=enabled, techniques=techniques, attributes={"format": "csv"}))
    return out


class FileImportConnector(BaseConnector):
    type = "file"
    label = "File / manual import"
    description = "Paste or upload a list of log sources and rules (JSON, CSV or Sigma YAML). Useful for SIEMs without an API, or for what-if planning."
    provides_rules = True
    fields = [
        FieldSpec("log_sources_text", "Log sources", type="textarea", help="One per line: name,vendor,product,event_count - or a JSON array.", placeholder="XmlWinEventLog:Security,Microsoft,Windows\naws:cloudtrail,AWS,CloudTrail"),
        FieldSpec("rules_text", "Rules", type="textarea", help="JSON array, CSV (name,techniques,enabled) or Sigma YAML documents separated by ---.", placeholder='[{"name": "Encoded PowerShell", "techniques": ["T1059.001"]}]'),
    ]

    async def test(self) -> TestResult:
        try:
            ls = parse_log_sources(self.cfg("log_sources_text", ""))
            rules = parse_rules(self.cfg("rules_text", ""))
        except Exception as exc:  # noqa: BLE001
            return TestResult(False, f"Could not parse input: {exc}")
        return TestResult(True, f"Parsed {len(ls)} log sources and {len(rules)} rules.", {"log_sources": len(ls), "rules": len(rules)})

    async def fetch(self) -> FetchResult:
        return FetchResult(
            log_sources=parse_log_sources(self.cfg("log_sources_text", "")),
            rules=parse_rules(self.cfg("rules_text", "")),
        )
