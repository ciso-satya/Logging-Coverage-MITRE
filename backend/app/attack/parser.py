"""Parse a MITRE ATT&CK STIX 2.1 bundle into plain dictionaries.

Supports ATT&CK v18+ (detection strategies / analytics / canonical log sources) and
degrades gracefully for older bundles where data components detect techniques directly.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _ext_id(obj: dict, prefix: str = "") -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            ext = ref["external_id"]
            if not prefix or ext.startswith(prefix):
                return ext
    return ""


def _ext_url(obj: dict) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return ""


def _inactive(obj: dict) -> bool:
    return bool(obj.get("x_mitre_deprecated")) or bool(obj.get("revoked"))


def normalize_log_source_name(name: str) -> str:
    """Normalise MITRE canonical log source names (fix case and known typos)."""
    n = (name or "").strip()
    fixes = {
        "nsm:flow": "NSM:Flow",
        "nsm:firewall": "NSM:Firewall",
        "linus:syslog": "linux:syslog",
        "linuxsyslog": "linux:syslog",
        "esxis:vmkernel": "esxi:vmkernel",
        "macos:unifiedlog": "macos:unifiedlog",
        "containerd:events": "containerd:events",
        "networkconfig": "networkdevice:config",
        "firmware:integrity": "firmware:integrity",
    }
    return fixes.get(n.lower(), n)


@dataclass
class ParsedAttack:
    version: str = ""
    domain: str = "enterprise-attack"
    tactics: list[dict] = field(default_factory=list)
    techniques: list[dict] = field(default_factory=list)
    data_components: list[dict] = field(default_factory=list)
    detection_strategies: list[dict] = field(default_factory=list)
    analytics: list[dict] = field(default_factory=list)
    log_source_names: set[str] = field(default_factory=set)


def parse_bundle(bundle: dict[str, Any]) -> ParsedAttack:
    objs = bundle.get("objects", [])
    by_id: dict[str, dict] = {o["id"]: o for o in objs if "id" in o}
    out = ParsedAttack()

    collection = next((o for o in objs if o.get("type") == "x-mitre-collection"), None)
    if collection:
        out.version = str(collection.get("x_mitre_version", ""))
        out.domain = (collection.get("x_mitre_domains") or ["enterprise-attack"])[0]

    # ---- tactics, ordered as in the matrix ----
    matrix = next((o for o in objs if o.get("type") == "x-mitre-matrix" and not _inactive(o)), None)
    tactic_objs = [o for o in objs if o.get("type") == "x-mitre-tactic" and not _inactive(o)]
    order: dict[str, int] = {}
    if matrix:
        for i, ref in enumerate(matrix.get("tactic_refs", [])):
            order[ref] = i
    tactic_objs.sort(key=lambda o: order.get(o["id"], 999))
    for i, t in enumerate(tactic_objs):
        out.tactics.append(
            {
                "stix_id": t["id"],
                "attack_id": _ext_id(t, "TA"),
                "name": t.get("name", ""),
                "shortname": t.get("x_mitre_shortname", ""),
                "description": t.get("description", ""),
                "url": _ext_url(t),
                "order": i,
            }
        )

    # ---- data components ----
    dc_name: dict[str, str] = {}
    for dc in objs:
        if dc.get("type") != "x-mitre-data-component":
            continue
        ds_name = ""
        ds_ref = dc.get("x_mitre_data_source_ref")
        if ds_ref and ds_ref in by_id:
            ds_name = by_id[ds_ref].get("name", "")
        log_sources = [
            {"name": normalize_log_source_name(ls.get("name", "")), "channel": ls.get("channel", "")}
            for ls in dc.get("x_mitre_log_sources", []) or []
            if ls.get("name")
        ]
        dc_name[dc["id"]] = dc.get("name", "")
        out.data_components.append(
            {
                "stix_id": dc["id"],
                "attack_id": _ext_id(dc, "DC"),
                "name": dc.get("name", ""),
                "description": dc.get("description", ""),
                "url": _ext_url(dc),
                "log_sources": log_sources,
                "data_source_name": ds_name,
                "deprecated": _inactive(dc),
            }
        )

    # ---- relationships ----
    detects: dict[str, set[str]] = defaultdict(set)  # target technique stix -> source stix ids
    for rel in objs:
        if rel.get("type") != "relationship" or _inactive(rel):
            continue
        if rel.get("relationship_type") == "detects":
            detects[rel["target_ref"]].add(rel["source_ref"])

    # ---- analytics ----
    analytic_by_id: dict[str, dict] = {}
    for an in objs:
        if an.get("type") != "x-mitre-analytic":
            continue
        refs = []
        for r in an.get("x_mitre_log_source_references", []) or []:
            name = normalize_log_source_name(r.get("name", ""))
            if not name:
                continue
            refs.append(
                {
                    "data_component": r.get("x_mitre_data_component_ref", ""),
                    "data_component_name": dc_name.get(r.get("x_mitre_data_component_ref", ""), ""),
                    "name": name,
                    "channel": r.get("channel", "") or "",
                }
            )
            out.log_source_names.add(name)
        rec = {
            "stix_id": an["id"],
            "attack_id": _ext_id(an, "AN"),
            "name": an.get("name", ""),
            "description": an.get("description", ""),
            "url": _ext_url(an),
            "strategy_stix_id": None,
            "platforms": an.get("x_mitre_platforms", []) or [],
            "log_source_refs": refs,
            "mutable_elements": an.get("x_mitre_mutable_elements", []) or [],
            "deprecated": _inactive(an),
        }
        analytic_by_id[an["id"]] = rec
        out.analytics.append(rec)

    # ---- detection strategies ----
    strategies_for_technique: dict[str, list[dict]] = defaultdict(list)
    for ds in objs:
        if ds.get("type") != "x-mitre-detection-strategy":
            continue
        rec = {
            "stix_id": ds["id"],
            "attack_id": _ext_id(ds, "DET"),
            "name": ds.get("name", ""),
            "description": ds.get("description", ""),
            "url": _ext_url(ds),
            "techniques": [],
            "analytics": [a for a in ds.get("x_mitre_analytic_refs", []) or [] if a in analytic_by_id],
            "deprecated": _inactive(ds),
        }
        for a in rec["analytics"]:
            analytic_by_id[a]["strategy_stix_id"] = ds["id"]
        out.detection_strategies.append(rec)
    strategy_by_id = {s["stix_id"]: s for s in out.detection_strategies}

    # ---- techniques ----
    tech_objs = [o for o in objs if o.get("type") == "attack-pattern"]
    for t in tech_objs:
        attack_id = _ext_id(t, "T")
        if not attack_id:
            continue
        parent = attack_id.split(".")[0] if "." in attack_id else None
        tactics = [
            p.get("phase_name")
            for p in t.get("kill_chain_phases", []) or []
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        strategy_ids: list[str] = []
        component_names: set[str] = set()
        log_names: set[str] = set()
        for src in sorted(detects.get(t["id"], ())):
            src_obj = by_id.get(src)
            if not src_obj:
                continue
            if src_obj.get("type") == "x-mitre-detection-strategy" and src in strategy_by_id:
                strat = strategy_by_id[src]
                if strat["deprecated"]:
                    continue
                strat["techniques"].append(attack_id)
                strategy_ids.append(strat["attack_id"])
                for aid in strat["analytics"]:
                    an = analytic_by_id[aid]
                    if an["deprecated"]:
                        continue
                    for ref in an["log_source_refs"]:
                        if ref["data_component_name"]:
                            component_names.add(ref["data_component_name"])
                        log_names.add(ref["name"])
            elif src_obj.get("type") == "x-mitre-data-component":
                # Pre-v18 bundles: data component -> technique
                component_names.add(src_obj.get("name", ""))
                for ls in src_obj.get("x_mitre_log_sources", []) or []:
                    if ls.get("name"):
                        log_names.add(normalize_log_source_name(ls["name"]))
        out.techniques.append(
            {
                "stix_id": t["id"],
                "attack_id": attack_id,
                "name": t.get("name", ""),
                "description": t.get("description", ""),
                "detection": t.get("x_mitre_detection", "") or "",
                "url": _ext_url(t),
                "is_subtechnique": bool(t.get("x_mitre_is_subtechnique")),
                "parent_attack_id": parent,
                "platforms": t.get("x_mitre_platforms", []) or [],
                "tactics": tactics,
                "data_components": sorted(c for c in component_names if c),
                "detection_strategies": strategy_ids,
                "log_source_names": sorted(log_names),
                "deprecated": bool(t.get("x_mitre_deprecated")),
                "revoked": bool(t.get("revoked")),
                "version": str(t.get("x_mitre_version", "")),
            }
        )
    out.techniques.sort(key=lambda x: x["attack_id"])
    for s in out.detection_strategies:
        s["techniques"] = sorted(set(s["techniques"]))
    return out
