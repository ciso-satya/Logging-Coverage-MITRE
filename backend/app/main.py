from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from .api import attack, connections, coverage, mappings
from .api.export import router as export_router
from .attack.importer import import_attack
from .config import settings
from .db import SessionLocal, init_db
from .models import AttackMeta, Connection
from .sync import sync_all, sync_connection

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")


async def _bootstrap() -> None:
    db = SessionLocal()
    try:
        if db.scalars(select(AttackMeta)).first() is None:
            try:
                await import_attack(db)
            except Exception as exc:  # noqa: BLE001
                log.error("Initial ATT&CK import failed (use POST /api/attack/import to retry): %s", exc)
        if settings.seed_demo and db.scalars(select(Connection)).first() is None:
            demo = Connection(name="Demo SIEM (sample data)", type="demo", enabled=True, config={})
            db.add(demo)
            db.commit()
            await sync_connection(demo.id)
    finally:
        db.close()


async def _scheduler() -> None:
    interval = settings.sync_interval_minutes
    if interval <= 0:
        return
    while True:
        await asyncio.sleep(interval * 60)
        try:
            await sync_all()
        except Exception:  # noqa: BLE001
            log.exception("Scheduled sync failed")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    await _bootstrap()
    task = asyncio.create_task(_scheduler())
    yield
    task.cancel()


app = FastAPI(title="ATT&CK Logging Coverage Heatmap", version="0.1.0", lifespan=lifespan)
app.include_router(attack.router)
app.include_router(connections.router)
app.include_router(coverage.router)
app.include_router(mappings.router)
app.include_router(export_router)


@app.get("/api/health")
def health():
    return {"ok": True}


def _dist() -> Path | None:
    candidates = [settings.frontend_dist] if settings.frontend_dist else []
    candidates += [Path(__file__).resolve().parent.parent.parent / "frontend" / "dist", Path("/app/frontend/dist")]
    for c in candidates:
        if c and (c / "index.html").exists():
            return c
    return None


DIST = _dist()
if DIST:
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        target = DIST / full_path
        if full_path and target.is_file():
            return FileResponse(target)
        return FileResponse(DIST / "index.html")
else:

    @app.get("/", include_in_schema=False)
    def no_frontend():
        return {"message": "Frontend not built. Run `npm run build` in frontend/ or use the Docker image.", "api_docs": "/docs"}
