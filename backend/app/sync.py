"""Pull inventories from connectors and persist them."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .connectors.base import ConnectorError, FetchResult
from .connectors.registry import build_connector
from .crypto import decrypt, encrypt
from .db import SessionLocal
from .models import Connection, LogSource, Rule

log = logging.getLogger(__name__)
_locks: dict[int, asyncio.Lock] = {}


def load_secrets(conn: Connection) -> dict:
    if not conn.secrets_enc:
        return {}
    try:
        return json.loads(decrypt(conn.secrets_enc))
    except ValueError:
        log.warning("Cannot decrypt secrets for connection %s", conn.id)
        return {}


def store_secrets(conn: Connection, secrets: dict) -> None:
    conn.secrets_enc = encrypt(json.dumps(secrets)) if secrets else ""


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def apply_result(db: Session, conn: Connection, result: FetchResult) -> dict:
    db.execute(delete(LogSource).where(LogSource.connection_id == conn.id))
    db.execute(delete(Rule).where(Rule.connection_id == conn.id))
    seen: set[str] = set()
    for ls in result.log_sources:
        if ls.external_id in seen:
            continue
        seen.add(ls.external_id)
        db.add(
            LogSource(
                connection_id=conn.id,
                external_id=ls.external_id[:512],
                name=ls.name[:512],
                kind=ls.kind[:64],
                vendor=ls.vendor[:128],
                product=ls.product[:128],
                event_count=ls.event_count,
                last_seen=_parse_dt(ls.last_seen),
                attributes=ls.attributes,
                explicit_log_sources=ls.explicit_log_sources,
            )
        )
    seen = set()
    for r in result.rules:
        if r.external_id in seen:
            continue
        seen.add(r.external_id)
        db.add(
            Rule(
                connection_id=conn.id,
                external_id=r.external_id[:512],
                name=r.name[:512],
                description=r.description,
                enabled=r.enabled,
                severity=r.severity[:32],
                query=r.query,
                url=r.url,
                techniques=r.techniques,
                tactics=r.tactics,
                log_sources=r.log_sources,
                attributes=r.attributes,
            )
        )
    conn.last_sync_at = datetime.now(timezone.utc)
    conn.last_sync_status = "ok"
    msg = f"{len(result.log_sources)} log sources, {len(result.rules)} rules"
    if result.warnings:
        msg += "; warnings: " + " | ".join(result.warnings)
    conn.last_sync_message = msg
    db.commit()
    return {"log_sources": len(result.log_sources), "rules": len(result.rules), "warnings": result.warnings}


async def sync_connection(connection_id: int) -> dict:
    lock = _locks.setdefault(connection_id, asyncio.Lock())
    async with lock:
        db = SessionLocal()
        try:
            conn = db.get(Connection, connection_id)
            if conn is None:
                raise ValueError("Connection not found")
            conn.last_sync_status = "running"
            db.commit()
            try:
                connector = build_connector(conn.type, conn.config, load_secrets(conn))
                result = await connector.fetch()
            except (ConnectorError, ValueError) as exc:
                conn.last_sync_status = "error"
                conn.last_sync_message = str(exc)
                db.commit()
                return {"ok": False, "error": str(exc)}
            except Exception as exc:  # noqa: BLE001
                log.exception("Sync failed for connection %s", connection_id)
                conn.last_sync_status = "error"
                conn.last_sync_message = f"{type(exc).__name__}: {exc}"
                db.commit()
                return {"ok": False, "error": conn.last_sync_message}
            stats = apply_result(db, conn, result)
            return {"ok": True, **stats}
        finally:
            db.close()


async def sync_all() -> list[dict]:
    db = SessionLocal()
    try:
        ids = [c.id for c in db.scalars(select(Connection).where(Connection.enabled.is_(True)))]
    finally:
        db.close()
    results = []
    for cid in ids:
        res = await sync_connection(cid)
        results.append({"connection_id": cid, **res})
    return results
