import pytest

from app.attack.parser import normalize_log_source_name, parse_bundle
from tests.conftest import load_real_bundle, real_bundle_available


def test_parse_mini_bundle(mini_bundle):
    p = parse_bundle(mini_bundle)
    assert p.version == "99.0"
    assert [t["shortname"] for t in p.tactics] == ["execution", "persistence"]  # matrix order wins
    by_id = {t["attack_id"]: t for t in p.techniques}
    assert by_id["T1059"]["log_source_names"] == ["WinEventLog:PowerShell", "WinEventLog:Sysmon", "auditd:SYSCALL"]
    assert by_id["T1059"]["detection_strategies"] == ["DET0001"]
    assert by_id["T1059"]["data_components"] == ["Process Creation"]
    assert by_id["T1059.001"]["is_subtechnique"] and by_id["T1059.001"]["parent_attack_id"] == "T1059"
    assert by_id["T1053"]["tactics"] == ["persistence", "execution"]
    assert by_id["T9999"]["deprecated"] is True
    strat = {s["attack_id"]: s for s in p.detection_strategies}
    assert strat["DET0001"]["techniques"] == ["T1059", "T1059.001"]
    an = {a["attack_id"]: a for a in p.analytics}
    assert an["AN0001"]["strategy_stix_id"] == "x-mitre-detection-strategy--d1"
    assert an["AN0001"]["log_source_refs"][0]["data_component_name"] == "Process Creation"


def test_normalize_names():
    assert normalize_log_source_name("NSM:FLow") == "NSM:Flow"
    assert normalize_log_source_name("linus:syslog") == "linux:syslog"
    assert normalize_log_source_name("WinEventLog:Security") == "WinEventLog:Security"


@pytest.mark.skipif(not real_bundle_available(), reason="cached MITRE bundle not present")
def test_parse_real_bundle():
    p = parse_bundle(load_real_bundle())
    assert len(p.tactics) >= 14
    active = [t for t in p.techniques if not t["deprecated"] and not t["revoked"]]
    assert len(active) > 600
    # Every active technique should have at least one detection strategy in v18+ bundles.
    with_det = [t for t in active if t["detection_strategies"]]
    assert len(with_det) / len(active) > 0.95
    assert "WinEventLog:Security" in p.log_source_names
