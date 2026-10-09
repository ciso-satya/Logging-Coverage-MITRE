import json

LOG_SOURCES = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational,Microsoft,Sysmon,100\nXmlWinEventLog:Microsoft-Windows-PowerShell/Operational,Microsoft,PowerShell,50\n"
RULES = json.dumps(
    [
        {"name": "Encoded PowerShell", "techniques": ["T1059.001"], "severity": "high"},
        {"name": "Schtasks persistence", "techniques": ["T1053"], "enabled": True},
        {"name": "Disabled rule for macOS", "techniques": ["T1543"], "enabled": False},
        {"name": "No technique at all"},
    ]
)


def _make_file_connection(client, enabled=True, rules=RULES, logs=LOG_SOURCES):
    r = client.post("/api/connections", json={"name": "File import", "type": "file", "enabled": enabled, "config": {"log_sources_text": logs, "rules_text": rules}, "secrets": {}})
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    r = client.post(f"/api/connections/{cid}/sync")
    assert r.status_code == 200 and r.json()["ok"], r.text
    return cid


def test_attack_status(client):
    s = client.get("/api/attack/status").json()
    assert s["imported"] and s["version"] == "99.0"
    assert s["techniques"] == 3 and s["subtechniques"] == 1


def test_connector_types_listed(client):
    types = {t["type"] for t in client.get("/api/connections/types").json()}
    assert {"splunk", "crowdstrike", "cribl", "mcp", "file", "demo"} <= types


def test_matrix_statuses_end_to_end(client):
    # No connections -> everything is missing logs
    m = client.get("/api/coverage/matrix").json()
    assert m["summary"]["counts"]["missing_logs"] == 4

    cid = _make_file_connection(client)
    m = client.get("/api/coverage/matrix").json()
    T = m["techniques"]
    # Sysmon + PowerShell collected -> AN0001 fully satisfied; rule maps to the sub-technique directly,
    # and the parent inherits it ("via sub-technique").
    assert T["T1059.001"]["status"] == "covered" and T["T1059.001"]["logs"]["state"] == "full"
    assert T["T1059"]["status"] == "covered" and T["T1059"]["rules"]["related_via"] == "sub-technique"
    # Scheduled Task: rule exists but TaskScheduler log is not collected
    assert T["T1053"]["status"] == "rules_no_logs"
    assert T["T1053"]["logs"]["missing"] == ["WinEventLog:TaskScheduler"]
    # macOS technique: no logs and its only rule is disabled
    assert T["T1543"]["status"] == "missing_logs"
    assert m["summary"]["rules_mapped"] == 2
    assert m["summary"]["log_sources_mapped"] == 2

    # Tactic ordering and counts
    assert [t["shortname"] for t in m["tactics"]] == ["execution", "persistence"]
    assert "T1053" in m["tactics"][0]["techniques"] and "T1053" in m["tactics"][1]["techniques"]

    # Platform scope: exclude macOS -> T1543 disappears from the matrix
    m2 = client.get("/api/coverage/matrix?platforms=Windows,Linux").json()
    assert "T1543" not in m2["techniques"]

    # Technique detail
    d = client.get("/api/coverage/techniques/T1059").json()
    assert d["status"] == "covered"
    assert {a["attack_id"]: a["satisfied"] for a in d["analytics"]} == {"AN0001": True, "AN0002": False}
    assert d["rules"]["items"][0]["name"] == "Encoded PowerShell"

    # Gap report
    g = client.get("/api/coverage/gaps").json()
    assert {t["attack_id"] for t in g["missing_logs"]} == {"T1053", "T1543"}
    impact = {r["log_source"]: r for r in g["log_source_impact"]}
    assert impact["WinEventLog:TaskScheduler"]["with_rules"] == 1

    # Navigator layer export
    layer = client.get("/api/coverage/navigator-layer").json()
    assert layer["domain"] == "enterprise-attack" and any(t["techniqueID"] == "T1059" for t in layer["techniques"])

    # Rules endpoint flags unmapped rules
    rules = client.get("/api/coverage/rules").json()
    assert any(r["unmapped"] for r in rules if r["name"] == "No technique at all")

    # Disabling the connection removes its contribution
    client.put(f"/api/connections/{cid}", json={"name": "File import", "type": "file", "enabled": False, "config": {}, "secrets": {}})
    m3 = client.get("/api/coverage/matrix").json()
    assert m3["summary"]["counts"]["missing_logs"] == 4
    client.delete(f"/api/connections/{cid}")


def test_mapping_override_changes_coverage(client):
    cid = _make_file_connection(client, logs="acme:tasks_audit,Acme,Tasks,10\n", rules="[]")
    assert client.get("/api/coverage/matrix").json()["techniques"]["T1053"]["status"] == "missing_logs"
    r = client.post("/api/mappings", json={"pattern": "^acme:tasks_audit$", "field": "name", "mitre_log_sources": ["WinEventLog:TaskScheduler"], "note": "t"})
    assert r.status_code == 201
    assert client.get("/api/coverage/matrix").json()["techniques"]["T1053"]["status"] == "logs_no_rules"
    assert client.post("/api/mappings", json={"pattern": "([", "mitre_log_sources": ["x"]}).status_code == 400
    client.delete(f"/api/mappings/{r.json()['id']}")
    client.delete(f"/api/connections/{cid}")


def test_secrets_are_encrypted_and_not_returned(client):
    r = client.post("/api/connections", json={"name": "Splunk", "type": "splunk", "config": {"base_url": "https://splunk:8089", "token": "SECRET-TOKEN"}, "secrets": {}})
    assert r.status_code == 201
    body = r.json()
    assert "token" not in body["config"] and body["secrets_set"] == ["token"]
    from app.db import SessionLocal
    from app.models import Connection

    db = SessionLocal()
    row = db.get(Connection, body["id"])
    assert "SECRET-TOKEN" not in row.secrets_enc
    db.close()
    # Updating without providing the secret keeps it
    r = client.put(f"/api/connections/{body['id']}", json={"name": "Splunk", "type": "splunk", "config": {"base_url": "https://splunk:8089"}, "secrets": {}})
    assert r.json()["secrets_set"] == ["token"]
    client.delete(f"/api/connections/{body['id']}")


def test_settings_platform_scope(client):
    r = client.put("/api/settings", json={"platforms": ["Windows", "Bogus"]})
    assert r.json()["platforms"] == ["Windows"]
    assert "T1543" not in client.get("/api/coverage/matrix").json()["techniques"]
    client.put("/api/settings", json={"platforms": None})
