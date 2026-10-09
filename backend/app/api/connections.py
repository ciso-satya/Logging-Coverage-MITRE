from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.base import ConnectorError
from ..connectors.registry import CONNECTORS, build_connector, schemas
from ..db import get_db
from ..models import Connection, LogSource, Rule
from ..sync import load_secrets, store_secrets, sync_all, sync_connection

router = APIRouter(prefix="/api/connections", tags=["connections"])


class ConnectionIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    type: str
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, Any] = Field(default_factory=dict)


def _split(conn_type: str, config: dict, secrets: dict) -> tuple[dict, dict]:
    """Move any secret fields that arrived in `config` into `secrets`."""
    cls = CONNECTORS.get(conn_type)
    if cls is None:
        raise HTTPException(400, f"Unknown connector type '{conn_type}'")
    secret_names = {f.name for f in cls.fields if f.secret}
    cfg = {k: v for k, v in config.items() if k not in secret_names}
    sec = {**{k: v for k, v in config.items() if k in secret_names}, **secrets}
    return cfg, {k: v for k, v in sec.items() if v not in (None, "")}


def _serialize(conn: Connection, db: Session | None = None) -> dict:
    cls = CONNECTORS.get(conn.type)
    secret_names = {f.name for f in cls.fields if f.secret} if cls else set()
    stored = load_secrets(conn)
    out = {
        "id": conn.id,
        "name": conn.name,
        "type": conn.type,
        "type_label": cls.label if cls else conn.type,
        "enabled": conn.enabled,
        "config": conn.config,
        "secrets_set": sorted(k for k in stored if k in secret_names and stored[k]),
        "created_at": conn.created_at.isoformat() if conn.created_at else None,
        "last_sync_at": conn.last_sync_at.isoformat() if conn.last_sync_at else None,
        "last_sync_status": conn.last_sync_status,
        "last_sync_message": conn.last_sync_message,
    }
    if db is not None:
        out["log_source_count"] = db.scalar(select(LogSource.id).where(LogSource.connection_id == conn.id).limit(1)) and len(db.scalars(select(LogSource.id).where(LogSource.connection_id == conn.id)).all()) or 0
        out["rule_count"] = len(db.scalars(select(Rule.id).where(Rule.connection_id == conn.id)).all())
    return out


@router.get("/types")
def connector_types():
    return schemas()


@router.get("")
def list_connections(db: Session = Depends(get_db)):
    return [_serialize(c, db) for c in db.scalars(select(Connection).order_by(Connection.id))]


@router.post("", status_code=201)
def create_connection(body: ConnectionIn, db: Session = Depends(get_db)):
    cfg, sec = _split(body.type, body.config, body.secrets)
    conn = Connection(name=body.name, type=body.type, enabled=body.enabled, config=cfg)
    store_secrets(conn, sec)
    db.add(conn)
    db.commit()
    return _serialize(conn, db)


@router.get("/{conn_id}")
def get_connection(conn_id: int, db: Session = Depends(get_db)):
    conn = db.get(Connection, conn_id)
    if conn is None:
        raise HTTPException(404, "Connection not found")
    return _serialize(conn, db)


@router.put("/{conn_id}")
def update_connection(conn_id: int, body: ConnectionIn, db: Session = Depends(get_db)):
    conn = db.get(Connection, conn_id)
    if conn is None:
        raise HTTPException(404, "Connection not found")
    cfg, sec = _split(body.type, body.config, body.secrets)
    conn.name = body.name
    conn.type = body.type
    conn.enabled = body.enabled
    conn.config = cfg
    # Keep existing secrets unless a new (non-empty) value was provided.
    merged = {**load_secrets(conn), **sec}
    store_secrets(conn, merged)
    db.commit()
    return _serialize(conn, db)


@router.delete("/{conn_id}", status_code=204)
def delete_connection(conn_id: int, db: Session = Depends(get_db)):
    conn = db.get(Connection, conn_id)
    if conn is None:
        raise HTTPException(404, "Connection not found")
    db.delete(conn)
    db.commit()
    return None


@router.post("/test")
async def test_unsaved(body: ConnectionIn):
    cfg, sec = _split(body.type, body.config, body.secrets)
    try:
        result = await build_connector(body.type, cfg, sec).test()
    except ConnectorError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": result.ok, "message": result.message, "details": result.details}


@router.post("/{conn_id}/test")
async def test_connection(conn_id: int, db: Session = Depends(get_db)):
    conn = db.get(Connection, conn_id)
    if conn is None:
        raise HTTPException(404, "Connection not found")
    try:
        result = await build_connector(conn.type, conn.config, load_secrets(conn)).test()
    except ConnectorError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": result.ok, "message": result.message, "details": result.details}


@router.post("/{conn_id}/sync")
async def sync_one(conn_id: int, db: Session = Depends(get_db)):
    if db.get(Connection, conn_id) is None:
        raise HTTPException(404, "Connection not found")
    return await sync_connection(conn_id)


@router.post("/sync-all")
async def sync_everything():
    return await sync_all()


@router.post("/{conn_id}/upload")
async def upload_file(conn_id: int, kind: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Attach an uploaded file's text to a file-import connection (kind = log_sources | rules)."""
    conn = db.get(Connection, conn_id)
    if conn is None:
        raise HTTPException(404, "Connection not found")
    if conn.type != "file":
        raise HTTPException(400, "Uploads are only supported for file-import connections")
    if kind not in ("log_sources", "rules"):
        raise HTTPException(400, "kind must be log_sources or rules")
    text = (await file.read()).decode("utf-8", errors="replace")
    conn.config = {**conn.config, f"{kind}_text": text}
    db.commit()
    return {"ok": True, "bytes": len(text)}


@router.get("/{conn_id}/log-sources")
def connection_log_sources(conn_id: int, db: Session = Depends(get_db)):
    return [
        {"id": ls.id, "name": ls.name, "kind": ls.kind, "vendor": ls.vendor, "product": ls.product, "event_count": ls.event_count, "last_seen": ls.last_seen.isoformat() if ls.last_seen else None, "attributes": ls.attributes}
        for ls in db.scalars(select(LogSource).where(LogSource.connection_id == conn_id).order_by(LogSource.event_count.desc()))
    ]


@router.get("/{conn_id}/rules")
def connection_rules(conn_id: int, db: Session = Depends(get_db)):
    return [
        {"id": r.id, "name": r.name, "enabled": r.enabled, "severity": r.severity, "techniques": r.techniques, "description": r.description[:300], "url": r.url, "attributes": r.attributes}
        for r in db.scalars(select(Rule).where(Rule.connection_id == conn_id).order_by(Rule.name))
    ]
