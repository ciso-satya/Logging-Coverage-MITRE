from app.coverage.mapping import builtin_rules, map_log_source
from app.models import LogSource


def ls(name, vendor="", product="", kind="sourcetype", explicit=None, attrs=None):
    return LogSource(connection_id=1, external_id=name, name=name, vendor=vendor, product=product, kind=kind, explicit_log_sources=explicit or [], attributes=attrs or {})


def names(src):
    return map_log_source(src, builtin_rules())[0]


def test_windows_security():
    assert "WinEventLog:Security" in names(ls("XmlWinEventLog:Security"))
    assert "WinEventLog:Security" in names(ls("WinEventLog:Security"))
    assert "WinEventLog:Sysmon" in names(ls("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"))
    assert "WinEventLog:System" in names(ls("XmlWinEventLog:System"))
    assert "WinEventLog:Sysmon" not in names(ls("XmlWinEventLog:System"))


def test_cloud_and_identity():
    assert "AWS:CloudTrail" in names(ls("aws:cloudtrail"))
    assert "saas:okta" in names(ls("OktaIM2:log"))
    assert "azure:signinlogs" in names(ls("azure:aad:signin"))
    assert "m365:unified" in names(ls("o365:management:activity"))


def test_vendor_product_fields():
    n = names(ls("Vendor / Product", vendor="Palo Alto Networks", product="PAN-OS"))
    assert "NSM:Firewall" in n


def test_explicit_and_unmapped():
    assert names(ls("acme:totally_custom")) == set()
    assert names(ls("acme:totally_custom", explicit=["WinEventLog:Security"])) == {"WinEventLog:Security"}


def test_crowdstrike_sensor_covers_endpoint_sources():
    n = names(ls("crowdstrike:fdr", vendor="CrowdStrike", product="Falcon"))
    assert {"EDR:Telemetry", "WinEventLog:Sysmon", "auditd:SYSCALL"} <= n


def test_override_anchor_only_matches_full_name(tmp_env):
    from app.coverage.mapping import override_rules
    from app.models import MappingOverride

    rules = override_rules([MappingOverride(id=1, pattern="^custom$", field="name", mitre_log_sources=["dns:query"], enabled=True)])
    assert map_log_source(ls("custom"), rules)[0] == {"dns:query"}
    assert map_log_source(ls("custom-not"), rules)[0] == set()
