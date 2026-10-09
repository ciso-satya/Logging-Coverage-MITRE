from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..coverage.engine import compute_available_logs, compute_matrix, gaps, navigator_layer, technique_detail
from ..db import get_db
from ..models import Connection, Rule

router = APIRouter(prefix="/api/coverage", tags=["coverage"])


def _platforms(platforms: str | None) -> list[str] | None:
    if platforms is None or platforms == "":
        return None
    return [p.strip() for p in platforms.split(",") if p.strip()]


@router.get("/matrix")
def matrix(platforms: str | None = Query(None, description="Comma-separated platform filter"), db: Session = Depends(get_db)):
    return compute_matrix(db, _platforms(platforms))


@router.get("/summary")
def summary(platforms: str | None = None, db: Session = Depends(get_db)):
    m = compute_matrix(db, _platforms(platforms))
    return {"attack": m["attack"], "summary": m["summary"], "connections": m["connections"]}


@router.get("/techniques/{attack_id}")
def technique(attack_id: str, platforms: str | None = None, db: Session = Depends(get_db)):
    d = technique_detail(db, attack_id.upper(), _platforms(platforms))
    if d is None:
        raise HTTPException(404, "Technique not found")
    return d


@router.get("/gaps")
def gap_report(platforms: str | None = None, db: Session = Depends(get_db)):
    return gaps(db, _platforms(platforms))


@router.get("/log-sources")
def log_sources(db: Session = Depends(get_db)):
    """Every ingested log source across enabled connections, with its MITRE mapping."""
    avail = compute_available_logs(db)
    return {
        "mapped": sorted(avail.mapped_sources, key=lambda x: -x["event_count"]),
        "unmapped": sorted(avail.unmapped_sources, key=lambda x: -x["event_count"]),
        "mitre_log_sources": {k: v for k, v in sorted(avail.providers.items())},
    }


@router.get("/rules")
def rules(db: Session = Depends(get_db)):
    conns = {c.id: c for c in db.scalars(select(Connection))}
    out = []
    for r in db.scalars(select(Rule).order_by(Rule.name)):
        c = conns.get(r.connection_id)
        out.append(
            {
                "id": r.id,
                "name": r.name,
                "connection": c.name if c else "",
                "connection_enabled": bool(c and c.enabled),
                "enabled": r.enabled,
                "severity": r.severity,
                "techniques": r.techniques,
                "tactics": r.tactics,
                "url": r.url,
                "unmapped": not r.techniques,
            }
        )
    return out


@router.get("/navigator-layer")
def layer(platforms: str | None = None, db: Session = Depends(get_db)):
    data = navigator_layer(db, _platforms(platforms))
    return JSONResponse(data, headers={"Content-Disposition": 'attachment; filename="logging-coverage-layer.json"'})
