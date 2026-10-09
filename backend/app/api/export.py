"""Export a self-contained HTML snapshot of the heatmap (works offline, can be shared)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..coverage.engine import all_technique_details, compute_matrix, gaps
from ..db import get_db

router = APIRouter(prefix="/api/export", tags=["export"])


def _dist() -> Path | None:
    from ..main import DIST  # late import to avoid cycle

    return DIST


@router.get("/snapshot.html")
def snapshot(platforms: str | None = None, db: Session = Depends(get_db)):
    dist = _dist()
    if dist is None:
        raise HTTPException(503, "Frontend build not found; cannot render a snapshot")
    plats = [p.strip() for p in platforms.split(",")] if platforms else None
    matrix = compute_matrix(db, plats)
    gap_report = gaps(db, plats)
    html = (dist / "index.html").read_text()

    # Inline built assets so the file stands alone.
    def inline_script(m: re.Match) -> str:
        src = m.group(1).lstrip("/")
        return "<script type=\"module\">" + (dist / src).read_text().replace("</script>", "<\\/script>") + "</script>"

    def inline_css(m: re.Match) -> str:
        href = m.group(1).lstrip("/")
        return "<style>" + (dist / href).read_text() + "</style>"

    html = re.sub(r'<script type="module" crossorigin src="([^"]+)"></script>', inline_script, html)
    html = re.sub(r'<link rel="stylesheet" crossorigin href="([^"]+)">', inline_css, html)
    snap = {"matrix": matrix, "gaps": gap_report, "details": all_technique_details(db, plats, max_description=1500)}
    payload = json.dumps(snap).replace("</", "<\\/")
    # Classic scripts run before deferred module scripts regardless of position, so the data
    # goes at the end of the body (keeps <title> near the top of the file).
    html = html.replace("</body>", f"<script>window.__LCM_SNAPSHOT__={payload};</script></body>", 1)
    return HTMLResponse(html, headers={"Content-Disposition": 'attachment; filename="attack-logging-coverage.html"'})
