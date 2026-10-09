"""Coverage engine: joins ATT&CK analytics with the log sources and rules pulled from SIEMs.

Status per technique
--------------------
covered          logs available AND at least one enabled detection rule          (green)
logs_no_rules    logs available but no rule maps to the technique                 (yellow)
rules_no_logs    a rule exists but none of the logs it would need are collected   (orange)
missing_logs     no logs and no rules                                             (red)
no_detection_data ATT&CK lists no analytics for this technique                    (grey)
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import (
    Analytic,
    AppSetting,
    AttackMeta,
    Connection,
    DetectionStrategy,
    LogSource,
    MappingOverride,
    Rule,
    Tactic,
    Technique,
)
from .mapping import all_rules, map_log_source

STATUSES = ("covered", "logs_no_rules", "rules_no_logs", "missing_logs", "no_detection_data")
STATUS_LABELS = {
    "covered": "Logs + rules",
    "logs_no_rules": "Logs, no rules",
    "rules_no_logs": "Rules, no logs",
    "missing_logs": "Missing logs",
    "no_detection_data": "No ATT&CK analytics",
}

ALL_PLATFORMS = [
    "Windows",
    "Linux",
    "macOS",
    "ESXi",
    "IaaS",
    "SaaS",
    "Office Suite",
    "Identity Provider",
    "Network Devices",
    "Containers",
    "PRE",
]


def get_setting(db: Session, key: str, default: Any = None) -> Any:
    row = db.get(AppSetting, key)
    return row.value if row and row.value is not None else default


def set_setting(db: Session, key: str, value: Any) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value
    db.commit()


@dataclass
class AvailableLogs:
    """MITRE log source name -> list of {connection, log_source} providing it."""

    providers: dict[str, list[dict]] = field(default_factory=dict)
    mapped_sources: list[dict] = field(default_factory=list)
    unmapped_sources: list[dict] = field(default_factory=list)

    @property
    def names(self) -> set[str]:
        return set(self.providers)


def compute_available_logs(db: Session, connections: list[Connection] | None = None) -> AvailableLogs:
    if connections is None:
        connections = list(db.scalars(select(Connection).where(Connection.enabled.is_(True))))
    conn_ids = [c.id for c in connections]
    conn_by_id = {c.id: c for c in connections}
    overrides = list(db.scalars(select(MappingOverride)))
    rules = all_rules(overrides)
    out = AvailableLogs()
    if not conn_ids:
        return out
    sources = db.scalars(
        select(LogSource).where(LogSource.connection_id.in_(conn_ids), LogSource.active.is_(True))
    ).all()
    for ls in sources:
        names, notes = map_log_source(ls, rules)
        entry = {
            "id": ls.id,
            "connection_id": ls.connection_id,
            "connection": conn_by_id[ls.connection_id].name,
            "connection_type": conn_by_id[ls.connection_id].type,
            "name": ls.name,
            "kind": ls.kind,
            "vendor": ls.vendor,
            "product": ls.product,
            "event_count": ls.event_count,
            "mitre_log_sources": sorted(names),
            "matched_rules": notes,
        }
        if names:
            out.mapped_sources.append(entry)
            for n in names:
                out.providers.setdefault(n, []).append(
                    {"connection": entry["connection"], "log_source": ls.name, "log_source_id": ls.id}
                )
        else:
            out.unmapped_sources.append(entry)
    return out


def _rule_index(db: Session, conn_ids: list[int]) -> dict[str, list[Rule]]:
    idx: dict[str, list[Rule]] = defaultdict(list)
    if not conn_ids:
        return idx
    for r in db.scalars(select(Rule).where(Rule.connection_id.in_(conn_ids), Rule.enabled.is_(True))):
        for t in r.techniques or []:
            idx[t.upper()].append(r)
    return idx


def _rules_for(technique: Technique, idx: dict[str, list[Rule]], children: dict[str, list[str]]) -> dict:
    direct = idx.get(technique.attack_id, [])
    related: list[Rule] = []
    relation = ""
    if technique.is_subtechnique and technique.parent_attack_id:
        related = idx.get(technique.parent_attack_id, [])
        relation = "parent"
    elif not technique.is_subtechnique:
        seen = {r.id for r in direct}
        for child in children.get(technique.attack_id, []):
            for r in idx.get(child, []):
                if r.id not in seen:
                    related.append(r)
                    seen.add(r.id)
        relation = "sub-technique"
    return {
        "count": len(direct) + len(related),
        "direct": len(direct),
        "related": len(related),
        "related_via": relation if related else "",
        "ids": [r.id for r in direct] + [r.id for r in related],
    }


def _analytics_by_technique(db: Session) -> dict[str, list[Analytic]]:
    strategies = {s.stix_id: s for s in db.scalars(select(DetectionStrategy).where(DetectionStrategy.deprecated.is_(False)))}
    analytics = {a.stix_id: a for a in db.scalars(select(Analytic).where(Analytic.deprecated.is_(False)))}
    out: dict[str, list[Analytic]] = defaultdict(list)
    for s in strategies.values():
        for aid in s.analytics:
            a = analytics.get(aid)
            if a is None:
                continue
            for t in s.techniques:
                out[t].append(a)
    return out


def evaluate_logs(analytics: list[Analytic], available: set[str], platforms: set[str] | None) -> dict:
    """Evaluate ATT&CK analytics for one technique against the available MITRE log source names."""
    considered = []
    for a in analytics:
        if platforms and a.platforms and not (set(a.platforms) & platforms):
            continue
        considered.append(a)
    if not considered:
        return {"state": "none", "score": 0.0, "analytics": 0, "satisfied": 0, "matched": [], "missing": [], "no_analytics": True}
    best = 0.0
    satisfied = 0
    matched: set[str] = set()
    missing: set[str] = set()
    for a in considered:
        required = {r["name"] for r in a.log_source_refs if r.get("name")}
        if not required:
            continue
        hit = required & available
        score = len(hit) / len(required)
        best = max(best, score)
        if hit == required:
            satisfied += 1
        matched |= hit
        missing |= required - hit
    state = "full" if satisfied else ("partial" if matched else "none")
    return {
        "state": state,
        "score": round(best, 3),
        "analytics": len(considered),
        "satisfied": satisfied,
        "matched": sorted(matched),
        "missing": sorted(missing - matched),
        "no_analytics": False,
    }


def status_for(logs: dict, rules: dict) -> str:
    if logs.get("no_analytics"):
        return "no_detection_data"
    has_logs = logs["state"] in ("full", "partial")
    has_rules = rules["count"] > 0
    if has_logs and has_rules:
        return "covered"
    if has_logs:
        return "logs_no_rules"
    if has_rules:
        return "rules_no_logs"
    return "missing_logs"


def compute_matrix(db: Session, platforms: list[str] | None = None, include_subtechniques: bool = True) -> dict:
    meta = db.scalars(select(AttackMeta).order_by(AttackMeta.imported_at.desc())).first()
    if meta is None:
        return {"attack": None, "tactics": [], "techniques": {}, "summary": {}, "connections": []}

    scope = platforms if platforms is not None else get_setting(db, "platforms", None)
    scope_set = set(scope) if scope else None

    connections = list(db.scalars(select(Connection).where(Connection.enabled.is_(True))))
    conn_ids = [c.id for c in connections]
    available = compute_available_logs(db, connections)
    rule_idx = _rule_index(db, conn_ids)
    analytics_idx = _analytics_by_technique(db)

    techniques = db.scalars(
        select(Technique).where(Technique.deprecated.is_(False), Technique.revoked.is_(False))
    ).all()
    children: dict[str, list[str]] = defaultdict(list)
    for t in techniques:
        if t.is_subtechnique and t.parent_attack_id:
            children[t.parent_attack_id].append(t.attack_id)

    tech_out: dict[str, dict] = {}
    for t in techniques:
        if scope_set and t.platforms and not (set(t.platforms) & scope_set):
            continue
        if not include_subtechniques and t.is_subtechnique:
            continue
        logs = evaluate_logs(analytics_idx.get(t.attack_id, []), available.names, scope_set)
        rules = _rules_for(t, rule_idx, children)
        tech_out[t.attack_id] = {
            "attack_id": t.attack_id,
            "name": t.name,
            "url": t.url,
            "is_subtechnique": t.is_subtechnique,
            "parent": t.parent_attack_id,
            "platforms": t.platforms,
            "tactics": t.tactics,
            "status": status_for(logs, rules),
            "logs": logs,
            "rules": rules,
        }

    tactics_out = []
    for tac in db.scalars(select(Tactic).order_by(Tactic.order)):
        ids = [t["attack_id"] for t in tech_out.values() if tac.shortname in t["tactics"] and not t["is_subtechnique"]]
        ids.sort(key=lambda i: tech_out[i]["name"].lower())
        counts = {s: 0 for s in STATUSES}
        for i in ids:
            counts[tech_out[i]["status"]] += 1
            for c in children.get(i, []):
                if c in tech_out:
                    counts[tech_out[c]["status"]] += 1
        tactics_out.append(
            {
                "attack_id": tac.attack_id,
                "name": tac.name,
                "shortname": tac.shortname,
                "url": tac.url,
                "techniques": ids,
                "counts": counts,
            }
        )

    summary = summarize(tech_out)
    summary["log_sources_total"] = len(available.mapped_sources) + len(available.unmapped_sources)
    summary["log_sources_mapped"] = len(available.mapped_sources)
    summary["log_sources_unmapped"] = len(available.unmapped_sources)
    summary["mitre_log_sources_available"] = len(available.names)
    summary["rules_mapped"] = len({r.id for rs in rule_idx.values() for r in rs})
    summary["rules_total"] = (
        db.scalar(select(func.count()).select_from(Rule).where(Rule.connection_id.in_(conn_ids), Rule.enabled.is_(True))) if conn_ids else 0
    )

    return {
        "attack": {
            "version": meta.version,
            "domain": meta.domain,
            "imported_at": meta.imported_at.isoformat() if meta.imported_at else None,
            "technique_count": meta.technique_count,
            "subtechnique_count": meta.subtechnique_count,
            "analytic_count": meta.analytic_count,
        },
        "platforms": sorted(scope_set) if scope_set else ALL_PLATFORMS,
        "all_platforms": ALL_PLATFORMS,
        "tactics": tactics_out,
        "techniques": tech_out,
        "children": {k: sorted(v) for k, v in children.items() if k in tech_out},
        "summary": summary,
        "connections": [
            {
                "id": c.id,
                "name": c.name,
                "type": c.type,
                "last_sync_at": c.last_sync_at.isoformat() if c.last_sync_at else None,
                "last_sync_status": c.last_sync_status,
            }
            for c in connections
        ],
        "status_labels": STATUS_LABELS,
    }


def summarize(tech_out: dict[str, dict]) -> dict:
    counts = {s: 0 for s in STATUSES}
    parent_counts = {s: 0 for s in STATUSES}
    for t in tech_out.values():
        counts[t["status"]] += 1
        if not t["is_subtechnique"]:
            parent_counts[t["status"]] += 1
    total = len(tech_out) or 1
    return {
        "techniques_total": len(tech_out),
        "techniques_parent": sum(parent_counts.values()),
        "counts": counts,
        "parent_counts": parent_counts,
        "percent": {s: round(100 * counts[s] / total, 1) for s in STATUSES},
    }


@dataclass
class _Context:
    scope_set: set[str] | None
    connections: list[Connection]
    conn_by_id: dict[int, Connection]
    available: AvailableLogs
    rule_idx: dict[str, list[Rule]]
    analytics_idx: dict[str, list[Analytic]]
    children: dict[str, list[str]]
    strategies: dict[str, DetectionStrategy]
    rules_by_id: dict[int, Rule]


def _build_context(db: Session, platforms: list[str] | None) -> _Context:
    scope = platforms if platforms is not None else get_setting(db, "platforms", None)
    scope_set = set(scope) if scope else None
    connections = list(db.scalars(select(Connection).where(Connection.enabled.is_(True))))
    conn_ids = [c.id for c in connections]
    children: dict[str, list[str]] = defaultdict(list)
    for t in db.scalars(select(Technique).where(Technique.is_subtechnique.is_(True), Technique.deprecated.is_(False), Technique.revoked.is_(False))):
        if t.parent_attack_id:
            children[t.parent_attack_id].append(t.attack_id)
    rules_by_id = {r.id: r for r in db.scalars(select(Rule).where(Rule.connection_id.in_(conn_ids)))} if conn_ids else {}
    return _Context(
        scope_set=scope_set,
        connections=connections,
        conn_by_id={c.id: c for c in connections},
        available=compute_available_logs(db, connections),
        rule_idx=_rule_index(db, conn_ids),
        analytics_idx=_analytics_by_technique(db),
        children=children,
        strategies={s.attack_id: s for s in db.scalars(select(DetectionStrategy).where(DetectionStrategy.deprecated.is_(False)))},
        rules_by_id=rules_by_id,
    )


def _detail(ctx: _Context, t: Technique) -> dict:
    analytics = ctx.analytics_idx.get(t.attack_id, [])
    logs = evaluate_logs(analytics, ctx.available.names, ctx.scope_set)
    rules = _rules_for(t, ctx.rule_idx, ctx.children)
    rule_rows = []
    for rid in rules["ids"]:
        r = ctx.rules_by_id.get(rid)
        if r is None:
            continue
        rule_rows.append(
            {
                "id": r.id,
                "name": r.name,
                "connection": ctx.conn_by_id[r.connection_id].name if r.connection_id in ctx.conn_by_id else "",
                "severity": r.severity,
                "techniques": r.techniques,
                "url": r.url,
                "description": (r.description or "")[:400],
                "relation": "direct" if t.attack_id.upper() in [x.upper() for x in r.techniques] else rules["related_via"],
            }
        )
    analytic_rows = []
    for a in analytics:
        in_scope = not (ctx.scope_set and a.platforms and not (set(a.platforms) & ctx.scope_set))
        refs = []
        for ref in a.log_source_refs:
            refs.append(
                {
                    **ref,
                    "available": ref["name"] in ctx.available.names,
                    "providers": ctx.available.providers.get(ref["name"], []),
                }
            )
        required = {r["name"] for r in a.log_source_refs}
        analytic_rows.append(
            {
                "attack_id": a.attack_id,
                "name": a.name,
                "description": a.description,
                "url": a.url,
                "platforms": a.platforms,
                "in_scope": in_scope,
                "satisfied": bool(required) and required <= ctx.available.names,
                "log_sources": refs,
                "mutable_elements": a.mutable_elements,
            }
        )
    strategies = [ctx.strategies[sid] for sid in (t.detection_strategies or []) if sid in ctx.strategies]
    return {
        "attack_id": t.attack_id,
        "name": t.name,
        "description": t.description,
        "detection": t.detection,
        "url": t.url,
        "is_subtechnique": t.is_subtechnique,
        "parent": t.parent_attack_id,
        "children": sorted(ctx.children.get(t.attack_id, [])),
        "platforms": t.platforms,
        "tactics": t.tactics,
        "data_components": t.data_components,
        "status": status_for(logs, rules),
        "logs": logs,
        "rules": {**rules, "items": rule_rows},
        "strategies": [
            {"attack_id": s.attack_id, "name": s.name, "description": s.description, "url": s.url} for s in strategies
        ],
        "analytics": analytic_rows,
    }


def technique_detail(db: Session, attack_id: str, platforms: list[str] | None = None) -> dict | None:
    t = db.scalars(select(Technique).where(Technique.attack_id == attack_id)).first()
    if t is None:
        return None
    return _detail(_build_context(db, platforms), t)


def all_technique_details(db: Session, platforms: list[str] | None = None, max_description: int | None = None) -> dict[str, dict]:
    """Details for every active technique (used by the static HTML snapshot)."""
    ctx = _build_context(db, platforms)
    out: dict[str, dict] = {}
    for t in db.scalars(select(Technique).where(Technique.deprecated.is_(False), Technique.revoked.is_(False))):
        if ctx.scope_set and t.platforms and not (set(t.platforms) & ctx.scope_set):
            continue
        d = _detail(ctx, t)
        if max_description and len(d["description"]) > max_description:
            d["description"] = d["description"][:max_description] + " …"
        out[t.attack_id] = d
    return out


def gaps(db: Session, platforms: list[str] | None = None) -> dict:
    m = compute_matrix(db, platforms)
    techs = list(m["techniques"].values())
    by_status: dict[str, list[dict]] = {s: [] for s in STATUSES}
    for t in sorted(techs, key=lambda x: x["attack_id"]):
        by_status[t["status"]].append(t)
    # Which missing MITRE log sources would unlock the most techniques?
    impact: dict[str, dict] = {}
    for t in techs:
        if t["status"] in ("missing_logs", "rules_no_logs"):
            for n in t["logs"]["missing"]:
                rec = impact.setdefault(n, {"log_source": n, "techniques": 0, "with_rules": 0, "technique_ids": []})
                rec["techniques"] += 1
                rec["technique_ids"].append(t["attack_id"])
                if t["status"] == "rules_no_logs":
                    rec["with_rules"] += 1
    ranked = sorted(impact.values(), key=lambda r: (-r["techniques"], r["log_source"]))
    return {
        "summary": m["summary"],
        "status_labels": STATUS_LABELS,
        "missing_logs": by_status["missing_logs"] + by_status["rules_no_logs"],
        "logs_no_rules": by_status["logs_no_rules"],
        "covered": by_status["covered"],
        "no_detection_data": by_status["no_detection_data"],
        "log_source_impact": ranked[:50],
    }


def navigator_layer(db: Session, platforms: list[str] | None = None) -> dict:
    """Export an ATT&CK Navigator layer so the result can also be viewed in MITRE's own tool."""
    m = compute_matrix(db, platforms)
    colors = {
        "covered": "#0ca30c",
        "logs_no_rules": "#fab219",
        "rules_no_logs": "#ec835a",
        "missing_logs": "#d03b3b",
        "no_detection_data": "#bfbfbf",
    }
    scores = {"covered": 3, "logs_no_rules": 2, "rules_no_logs": 1, "missing_logs": 0, "no_detection_data": 0}
    techniques = []
    for t in m["techniques"].values():
        for tac in t["tactics"]:
            techniques.append(
                {
                    "techniqueID": t["attack_id"],
                    "tactic": tac,
                    "color": colors[t["status"]],
                    "score": scores[t["status"]],
                    "comment": f"{STATUS_LABELS[t['status']]}; rules={t['rules']['count']}; "
                    f"logs={t['logs']['state']} ({t['logs']['score']})",
                    "enabled": True,
                    "showSubtechniques": False,
                }
            )
    version = (m["attack"] or {}).get("version", "")
    return {
        "name": "Logging coverage",
        "versions": {"attack": version, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated by ATT&CK Logging Coverage Heatmap",
        "techniques": techniques,
        "legendItems": [{"label": STATUS_LABELS[s], "color": c} for s, c in colors.items()],
        "gradient": {"colors": ["#d03b3b", "#fab219", "#0ca30c"], "minValue": 0, "maxValue": 3},
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": True,
    }
