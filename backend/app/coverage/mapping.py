"""Map SIEM / pipeline log sources to MITRE ATT&CK canonical log source names."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ..attack.parser import normalize_log_source_name
from ..models import LogSource, MappingOverride

CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "log_source_catalog.json"


@dataclass(frozen=True)
class MappingRule:
    pattern: re.Pattern
    field: str  # any|name|vendor|product|kind
    mitre_log_sources: tuple[str, ...]
    note: str
    source: str  # builtin|override
    id: int | None = None


@lru_cache(maxsize=1)
def builtin_rules() -> tuple[MappingRule, ...]:
    with CATALOG_PATH.open() as fh:
        catalog = json.load(fh)
    rules: list[MappingRule] = []
    for entry in catalog["entries"]:
        rules.append(
            MappingRule(
                pattern=re.compile(entry["pattern"], re.IGNORECASE),
                field=entry.get("field", "any"),
                mitre_log_sources=tuple(normalize_log_source_name(n) for n in entry["mitre_log_sources"]),
                note=entry.get("note", ""),
                source="builtin",
            )
        )
    return tuple(rules)


def override_rules(overrides: list[MappingOverride]) -> list[MappingRule]:
    rules: list[MappingRule] = []
    for o in overrides:
        if not o.enabled:
            continue
        try:
            pat = re.compile(o.pattern, re.IGNORECASE)
        except re.error:
            continue
        rules.append(
            MappingRule(
                pattern=pat,
                field=o.field or "any",
                mitre_log_sources=tuple(normalize_log_source_name(n) for n in (o.mitre_log_sources or [])),
                note=o.note or "",
                source="override",
                id=o.id,
            )
        )
    return rules


def _haystacks(ls: LogSource) -> dict[str, list[str]]:
    """Candidate strings per field. Each is matched independently so anchors (^ $) work."""
    attrs = ls.attributes or {}
    extra = [str(v) for k, v in attrs.items() if k in ("source", "index", "repository", "event_module", "dataset", "type", "category", "description", "event_simpleName") and v]
    name = [ls.name] + ([ls.external_id] if ls.external_id and ls.external_id != ls.name else [])
    vendor = [ls.vendor] if ls.vendor else []
    product = [ls.product] if ls.product else []
    kind = [ls.kind] if ls.kind else []
    return {
        "name": name,
        "vendor": vendor,
        "product": product,
        "kind": kind,
        "any": name + vendor + product + kind + extra,
    }


def map_log_source(ls: LogSource, rules: list[MappingRule] | tuple[MappingRule, ...]) -> tuple[set[str], list[str]]:
    """Return (set of MITRE log source names, list of matched rule notes)."""
    names: set[str] = set()
    notes: list[str] = []
    if ls.explicit_log_sources:
        names.update(normalize_log_source_name(n) for n in ls.explicit_log_sources)
        notes.append("explicit")
    hay = _haystacks(ls)
    for rule in rules:
        candidates = hay.get(rule.field, hay["any"])
        if any(rule.pattern.search(text) for text in candidates):
            names.update(rule.mitre_log_sources)
            notes.append(rule.note or rule.pattern.pattern)
    return names, notes


def all_rules(overrides: list[MappingOverride]) -> list[MappingRule]:
    # Overrides first so their notes appear first; both contribute (union semantics).
    return override_rules(overrides) + list(builtin_rules())
