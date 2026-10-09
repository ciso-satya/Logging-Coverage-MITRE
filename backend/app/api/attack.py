from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..attack.importer import import_attack
from ..db import get_db
from ..models import Analytic, AttackMeta, DataComponent, Tactic, Technique

router = APIRouter(prefix="/api/attack", tags=["attack"])


@router.get("/status")
def status(db: Session = Depends(get_db)):
    meta = db.scalars(select(AttackMeta).order_by(AttackMeta.imported_at.desc())).first()
    if meta is None:
        return {"imported": False}
    return {
        "imported": True,
        "domain": meta.domain,
        "version": meta.version,
        "source_url": meta.source_url,
        "imported_at": meta.imported_at.isoformat() if meta.imported_at else None,
        "tactics": meta.tactic_count,
        "techniques": meta.technique_count,
        "subtechniques": meta.subtechnique_count,
        "data_components": meta.data_component_count,
        "detection_strategies": meta.detection_strategy_count,
        "analytics": meta.analytic_count,
        "log_source_names": meta.log_source_name_count,
    }


@router.post("/import")
async def do_import(force: bool = Query(False, description="Re-download the bundle from MITRE"), db: Session = Depends(get_db)):
    try:
        meta = await import_attack(db, force_download=force)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"ATT&CK import failed: {exc}") from exc
    return {"ok": True, "version": meta.version, "techniques": meta.technique_count, "subtechniques": meta.subtechnique_count}


@router.get("/tactics")
def tactics(db: Session = Depends(get_db)):
    return [
        {"attack_id": t.attack_id, "name": t.name, "shortname": t.shortname, "description": t.description, "url": t.url}
        for t in db.scalars(select(Tactic).order_by(Tactic.order))
    ]


@router.get("/techniques")
def techniques(q: str = "", db: Session = Depends(get_db)):
    stmt = select(Technique).where(Technique.deprecated.is_(False), Technique.revoked.is_(False))
    if q:
        like = f"%{q}%"
        stmt = stmt.where((Technique.name.ilike(like)) | (Technique.attack_id.ilike(like)))
    return [
        {"attack_id": t.attack_id, "name": t.name, "is_subtechnique": t.is_subtechnique, "tactics": t.tactics, "platforms": t.platforms}
        for t in db.scalars(stmt.order_by(Technique.attack_id))
    ]


@router.get("/techniques/{attack_id}")
def technique(attack_id: str, db: Session = Depends(get_db)):
    t = db.scalars(select(Technique).where(Technique.attack_id == attack_id.upper())).first()
    if t is None:
        raise HTTPException(404, "Technique not found")
    return {c.name: getattr(t, c.name) for c in Technique.__table__.columns}


@router.get("/log-sources")
def log_source_names(db: Session = Depends(get_db)):
    """All canonical MITRE log source names referenced by analytics, with how many techniques use each."""
    counts: dict[str, set[str]] = {}
    channels: dict[str, set[str]] = {}
    components: dict[str, set[str]] = {}
    for a in db.scalars(select(Analytic).where(Analytic.deprecated.is_(False))):
        for ref in a.log_source_refs:
            counts.setdefault(ref["name"], set()).add(a.strategy_stix_id or a.stix_id)
            if ref.get("channel"):
                channels.setdefault(ref["name"], set()).add(ref["channel"])
            if ref.get("data_component_name"):
                components.setdefault(ref["name"], set()).add(ref["data_component_name"])
    return sorted(
        (
            {
                "name": n,
                "strategies": len(s),
                "data_components": sorted(components.get(n, [])),
                "example_channels": sorted(channels.get(n, []))[:8],
            }
            for n, s in counts.items()
        ),
        key=lambda x: (-x["strategies"], x["name"]),
    )


@router.get("/data-components")
def data_components(db: Session = Depends(get_db)):
    return [
        {"attack_id": d.attack_id, "name": d.name, "description": d.description, "url": d.url, "log_sources": d.log_sources}
        for d in db.scalars(select(DataComponent).where(DataComponent.deprecated.is_(False)).order_by(DataComponent.name))
    ]


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    return {
        "techniques": db.scalar(select(func.count()).select_from(Technique).where(Technique.deprecated.is_(False), Technique.revoked.is_(False))),
        "analytics": db.scalar(select(func.count()).select_from(Analytic)),
    }
