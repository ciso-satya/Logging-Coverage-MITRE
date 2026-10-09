from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..coverage.engine import ALL_PLATFORMS, get_setting, set_setting
from ..coverage.mapping import builtin_rules
from ..db import get_db
from ..models import MappingOverride

router = APIRouter(prefix="/api", tags=["mappings"])


class OverrideIn(BaseModel):
    pattern: str = Field(min_length=1, max_length=512)
    field: str = "any"
    mitre_log_sources: list[str] = Field(default_factory=list)
    note: str = ""
    enabled: bool = True


def _ser(o: MappingOverride) -> dict:
    return {"id": o.id, "pattern": o.pattern, "field": o.field, "mitre_log_sources": o.mitre_log_sources, "note": o.note, "enabled": o.enabled}


@router.get("/mappings")
def list_overrides(db: Session = Depends(get_db)):
    return [_ser(o) for o in db.scalars(select(MappingOverride).order_by(MappingOverride.id))]


@router.get("/mappings/builtin")
def list_builtin():
    return [{"pattern": r.pattern.pattern, "field": r.field, "mitre_log_sources": list(r.mitre_log_sources), "note": r.note} for r in builtin_rules()]


@router.post("/mappings", status_code=201)
def create_override(body: OverrideIn, db: Session = Depends(get_db)):
    try:
        re.compile(body.pattern, re.IGNORECASE)
    except re.error as exc:
        raise HTTPException(400, f"Invalid regular expression: {exc}") from exc
    o = MappingOverride(**body.model_dump())
    db.add(o)
    db.commit()
    return _ser(o)


@router.put("/mappings/{oid}")
def update_override(oid: int, body: OverrideIn, db: Session = Depends(get_db)):
    o = db.get(MappingOverride, oid)
    if o is None:
        raise HTTPException(404, "Not found")
    try:
        re.compile(body.pattern, re.IGNORECASE)
    except re.error as exc:
        raise HTTPException(400, f"Invalid regular expression: {exc}") from exc
    for k, v in body.model_dump().items():
        setattr(o, k, v)
    db.commit()
    return _ser(o)


@router.delete("/mappings/{oid}", status_code=204)
def delete_override(oid: int, db: Session = Depends(get_db)):
    o = db.get(MappingOverride, oid)
    if o is None:
        raise HTTPException(404, "Not found")
    db.delete(o)
    db.commit()
    return None


class SettingsIn(BaseModel):
    platforms: list[str] | None = None


@router.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    return {"platforms": get_setting(db, "platforms", None), "all_platforms": ALL_PLATFORMS}


@router.put("/settings")
def put_settings(body: SettingsIn, db: Session = Depends(get_db)):
    platforms = [p for p in (body.platforms or []) if p in ALL_PLATFORMS] or None
    set_setting(db, "platforms", platforms)
    return {"platforms": platforms, "all_platforms": ALL_PLATFORMS}
