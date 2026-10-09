"""Connector framework. A connector pulls two inventories from a product:

* log sources  - what telemetry is actually being ingested (sourcetypes, repositories, inputs ...)
* rules        - which detections are enabled and which ATT&CK techniques they map to
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
TACTIC_RE = re.compile(r"\bTA\d{4}\b", re.IGNORECASE)


@dataclass
class FieldSpec:
    name: str
    label: str
    type: str = "text"  # text|password|number|bool|select|textarea|url
    required: bool = False
    secret: bool = False
    default: Any = None
    help: str = ""
    options: list[str] = field(default_factory=list)
    placeholder: str = ""


@dataclass
class LogSourceRecord:
    external_id: str
    name: str
    kind: str = "sourcetype"
    vendor: str = ""
    product: str = ""
    event_count: int = 0
    last_seen: str | None = None
    attributes: dict = field(default_factory=dict)
    explicit_log_sources: list[str] = field(default_factory=list)


@dataclass
class RuleRecord:
    external_id: str
    name: str
    description: str = ""
    enabled: bool = True
    severity: str = ""
    query: str = ""
    url: str = ""
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    log_sources: list[str] = field(default_factory=list)
    attributes: dict = field(default_factory=dict)


@dataclass
class FetchResult:
    log_sources: list[LogSourceRecord] = field(default_factory=list)
    rules: list[RuleRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class TestResult:
    ok: bool
    message: str
    details: dict = field(default_factory=dict)


class ConnectorError(Exception):
    pass


def extract_techniques(*texts: str | None) -> list[str]:
    found: set[str] = set()
    for t in texts:
        if not t:
            continue
        for m in TECHNIQUE_RE.findall(str(t)):
            found.add(m.upper())
    return sorted(found)


def extract_tactics(*texts: str | None) -> list[str]:
    found: set[str] = set()
    for t in texts:
        if not t:
            continue
        for m in TACTIC_RE.findall(str(t)):
            found.add(m.upper())
    return sorted(found)


class BaseConnector:
    type: ClassVar[str] = "base"
    label: ClassVar[str] = "Base"
    description: ClassVar[str] = ""
    docs_url: ClassVar[str] = ""
    provides_rules: ClassVar[bool] = True
    fields: ClassVar[list[FieldSpec]] = []

    def __init__(self, config: dict[str, Any], secrets: dict[str, Any]):
        self.config = {**{f.name: f.default for f in self.fields if not f.secret}, **(config or {})}
        self.secrets = secrets or {}

    @classmethod
    def schema(cls) -> dict:
        return {
            "type": cls.type,
            "label": cls.label,
            "description": cls.description,
            "docs_url": cls.docs_url,
            "provides_rules": cls.provides_rules,
            "fields": [asdict(f) for f in cls.fields],
        }

    def cfg(self, name: str, default: Any = None) -> Any:
        v = self.config.get(name)
        return default if v in (None, "") else v

    def sec(self, name: str, default: Any = None) -> Any:
        v = self.secrets.get(name)
        return default if v in (None, "") else v

    async def test(self) -> TestResult:  # pragma: no cover - abstract
        raise NotImplementedError

    async def fetch(self) -> FetchResult:  # pragma: no cover - abstract
        raise NotImplementedError
