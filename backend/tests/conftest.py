import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Point the app at an isolated data directory BEFORE any app module is imported
# (app.config instantiates Settings at import time).
_TMP = Path(tempfile.mkdtemp(prefix="lcm-test-"))
os.environ["LCM_DATA_DIR"] = str(_TMP)
os.environ["LCM_SEED_DEMO"] = "false"
os.environ["LCM_SECRET_KEY"] = "9h7p2nqgC8iVtZ5nbVUV5pZb9tCqq0gJ1oG3t3h5rXk="
os.environ["LCM_SYNC_INTERVAL_MINUTES"] = "0"

DATA_DIR = Path(os.environ.get("LCM_TEST_DATA_DIR", str(ROOT.parent / "data")))


@pytest.fixture(scope="session")
def tmp_env():
    return _TMP


@pytest.fixture(scope="session")
def mini_bundle() -> dict:
    """A tiny synthetic ATT&CK bundle in the v18+ shape (detection strategies + analytics)."""
    return {
        "type": "bundle",
        "objects": [
            {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "99.0", "x_mitre_domains": ["enterprise-attack"]},
            {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "tactic_refs": ["x-mitre-tactic--exec", "x-mitre-tactic--persist"]},
            {"type": "x-mitre-tactic", "id": "x-mitre-tactic--persist", "name": "Persistence", "x_mitre_shortname": "persistence", "external_references": [{"source_name": "mitre-attack", "external_id": "TA0003", "url": "u"}]},
            {"type": "x-mitre-tactic", "id": "x-mitre-tactic--exec", "name": "Execution", "x_mitre_shortname": "execution", "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002", "url": "u"}]},
            {"type": "x-mitre-data-component", "id": "x-mitre-data-component--pc", "name": "Process Creation", "external_references": [{"source_name": "mitre-attack", "external_id": "DC0032"}], "x_mitre_log_sources": [{"name": "WinEventLog:Sysmon", "channel": "EventCode=1"}]},
            {"type": "attack-pattern", "id": "attack-pattern--t1", "name": "Command and Scripting Interpreter", "x_mitre_platforms": ["Windows", "Linux"], "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}], "external_references": [{"source_name": "mitre-attack", "external_id": "T1059", "url": "https://attack.mitre.org/techniques/T1059"}]},
            {"type": "attack-pattern", "id": "attack-pattern--t1s", "name": "PowerShell", "x_mitre_is_subtechnique": True, "x_mitre_platforms": ["Windows"], "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}], "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001", "url": "u"}]},
            {"type": "attack-pattern", "id": "attack-pattern--t2", "name": "Scheduled Task", "x_mitre_platforms": ["Windows"], "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}, {"kill_chain_name": "mitre-attack", "phase_name": "execution"}], "external_references": [{"source_name": "mitre-attack", "external_id": "T1053", "url": "u"}]},
            {"type": "attack-pattern", "id": "attack-pattern--t3", "name": "Launch Agent (macOS only)", "x_mitre_platforms": ["macOS"], "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}], "external_references": [{"source_name": "mitre-attack", "external_id": "T1543", "url": "u"}]},
            {"type": "attack-pattern", "id": "attack-pattern--old", "name": "Deprecated", "x_mitre_deprecated": True, "kill_chain_phases": [], "external_references": [{"source_name": "mitre-attack", "external_id": "T9999", "url": "u"}]},
            {"type": "x-mitre-analytic", "id": "x-mitre-analytic--a1", "name": "Analytic 1", "x_mitre_platforms": ["Windows"], "external_references": [{"source_name": "mitre-attack", "external_id": "AN0001"}], "x_mitre_log_source_references": [{"x_mitre_data_component_ref": "x-mitre-data-component--pc", "name": "WinEventLog:Sysmon", "channel": "EventCode=1"}, {"x_mitre_data_component_ref": "x-mitre-data-component--pc", "name": "WinEventLog:PowerShell", "channel": "EventCode=4104"}]},
            {"type": "x-mitre-analytic", "id": "x-mitre-analytic--a2", "name": "Analytic 2", "x_mitre_platforms": ["Linux"], "external_references": [{"source_name": "mitre-attack", "external_id": "AN0002"}], "x_mitre_log_source_references": [{"x_mitre_data_component_ref": "x-mitre-data-component--pc", "name": "auditd:SYSCALL", "channel": "execve"}]},
            {"type": "x-mitre-analytic", "id": "x-mitre-analytic--a3", "name": "Analytic 3", "x_mitre_platforms": ["Windows"], "external_references": [{"source_name": "mitre-attack", "external_id": "AN0003"}], "x_mitre_log_source_references": [{"x_mitre_data_component_ref": "x-mitre-data-component--pc", "name": "WinEventLog:TaskScheduler", "channel": "EventCode=106"}]},
            {"type": "x-mitre-analytic", "id": "x-mitre-analytic--a4", "name": "Analytic 4", "x_mitre_platforms": ["macOS"], "external_references": [{"source_name": "mitre-attack", "external_id": "AN0004"}], "x_mitre_log_source_references": [{"x_mitre_data_component_ref": "x-mitre-data-component--pc", "name": "macos:unifiedlog", "channel": "launchctl"}]},
            {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--d1", "name": "Strategy 1", "external_references": [{"source_name": "mitre-attack", "external_id": "DET0001"}], "x_mitre_analytic_refs": ["x-mitre-analytic--a1", "x-mitre-analytic--a2"]},
            {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--d2", "name": "Strategy 2", "external_references": [{"source_name": "mitre-attack", "external_id": "DET0002"}], "x_mitre_analytic_refs": ["x-mitre-analytic--a3"]},
            {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--d3", "name": "Strategy 3", "external_references": [{"source_name": "mitre-attack", "external_id": "DET0003"}], "x_mitre_analytic_refs": ["x-mitre-analytic--a4"]},
            {"type": "relationship", "id": "relationship--1", "relationship_type": "detects", "source_ref": "x-mitre-detection-strategy--d1", "target_ref": "attack-pattern--t1"},
            {"type": "relationship", "id": "relationship--1b", "relationship_type": "detects", "source_ref": "x-mitre-detection-strategy--d1", "target_ref": "attack-pattern--t1s"},
            {"type": "relationship", "id": "relationship--2", "relationship_type": "detects", "source_ref": "x-mitre-detection-strategy--d2", "target_ref": "attack-pattern--t2"},
            {"type": "relationship", "id": "relationship--3", "relationship_type": "detects", "source_ref": "x-mitre-detection-strategy--d3", "target_ref": "attack-pattern--t3"},
            {"type": "relationship", "id": "relationship--4", "relationship_type": "subtechnique-of", "source_ref": "attack-pattern--t1s", "target_ref": "attack-pattern--t1"},
        ],
    }


@pytest.fixture(scope="session")
def client(tmp_env, mini_bundle):
    """FastAPI test client with the mini bundle loaded and the demo connection replaced by a file import."""
    from fastapi.testclient import TestClient

    from app.main import app
    from app.db import SessionLocal, init_db
    from app.attack.importer import load_bundle_into_db

    init_db()
    db = SessionLocal()
    load_bundle_into_db(db, mini_bundle, source_url="test")
    db.close()
    with TestClient(app) as c:
        yield c


def real_bundle_available() -> bool:
    return (DATA_DIR / "enterprise-attack.json").exists()


def load_real_bundle() -> dict:
    with (DATA_DIR / "enterprise-attack.json").open() as fh:
        return json.load(fh)
