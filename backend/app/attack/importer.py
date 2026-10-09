"""Download the official ATT&CK STIX bundle from MITRE and load it into the database."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Analytic, AttackMeta, DataComponent, DetectionStrategy, Tactic, Technique
from .parser import parse_bundle

log = logging.getLogger(__name__)


async def download_bundle(url: str | None = None, force: bool = False) -> dict:
    """Fetch the STIX bundle (cached on disk)."""
    url = url or settings.attack_stix_url
    cache = settings.attack_cache_path
    if cache.exists() and not force:
        with cache.open() as fh:
            return json.load(fh)
    log.info("Downloading ATT&CK bundle from %s", url)
    async with httpx.AsyncClient(timeout=httpx.Timeout(300.0), follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
    cache.parent.mkdir(parents=True, exist_ok=True)
    with cache.open("w") as fh:
        json.dump(data, fh)
    return data


def load_bundle_into_db(db: Session, bundle: dict, source_url: str = "") -> AttackMeta:
    parsed = parse_bundle(bundle)

    for table in (Analytic, DetectionStrategy, DataComponent, Technique, Tactic, AttackMeta):
        db.execute(delete(table))

    db.flush()
    db.add_all(Tactic(**t) for t in parsed.tactics)
    db.add_all(Technique(**t) for t in parsed.techniques)
    db.add_all(DataComponent(**d) for d in parsed.data_components)
    db.flush()
    db.add_all(DetectionStrategy(**s) for s in parsed.detection_strategies)
    db.flush()
    db.add_all(Analytic(**a) for a in parsed.analytics)
    db.flush()

    active = [t for t in parsed.techniques if not t["deprecated"] and not t["revoked"]]
    meta = AttackMeta(
        domain=parsed.domain,
        version=parsed.version,
        source_url=source_url or settings.attack_stix_url,
        imported_at=datetime.now(timezone.utc),
        tactic_count=len(parsed.tactics),
        technique_count=sum(1 for t in active if not t["is_subtechnique"]),
        subtechnique_count=sum(1 for t in active if t["is_subtechnique"]),
        data_component_count=sum(1 for d in parsed.data_components if not d["deprecated"]),
        detection_strategy_count=sum(1 for s in parsed.detection_strategies if not s["deprecated"]),
        analytic_count=sum(1 for a in parsed.analytics if not a["deprecated"]),
        log_source_name_count=len(parsed.log_source_names),
    )
    db.add(meta)
    db.commit()
    log.info(
        "Imported ATT&CK %s: %d tactics, %d techniques, %d sub-techniques, %d analytics",
        meta.version,
        meta.tactic_count,
        meta.technique_count,
        meta.subtechnique_count,
        meta.analytic_count,
    )
    return meta


async def import_attack(db: Session, force_download: bool = False, url: str | None = None) -> AttackMeta:
    bundle = await download_bundle(url=url, force=force_download)
    return load_bundle_into_db(db, bundle, source_url=url or settings.attack_stix_url)
