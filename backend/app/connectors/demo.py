"""Built-in sample data so the heatmap renders before any SIEM is connected."""
from __future__ import annotations

from .base import BaseConnector, FetchResult, FieldSpec, LogSourceRecord, RuleRecord, TestResult

SAMPLE_LOG_SOURCES = [
    ("XmlWinEventLog:Security", "Microsoft", "Windows", 48_212_331),
    ("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "Microsoft", "Sysmon", 120_993_120),
    ("XmlWinEventLog:System", "Microsoft", "Windows", 5_120_004),
    ("XmlWinEventLog:Microsoft-Windows-PowerShell/Operational", "Microsoft", "PowerShell", 2_311_900),
    ("crowdstrike:fdr", "CrowdStrike", "Falcon", 310_441_002),
    ("aws:cloudtrail", "AWS", "CloudTrail", 9_874_112),
    ("o365:management:activity", "Microsoft", "Office 365", 3_001_552),
    ("azure:aad:signin", "Microsoft", "Entra ID", 1_400_770),
    ("OktaIM2:log", "Okta", "Okta", 804_211),
    ("pan:traffic", "Palo Alto Networks", "PAN-OS", 988_120_330),
    ("pan:threat", "Palo Alto Networks", "PAN-OS", 2_203_118),
    ("zscalernss-web", "Zscaler", "ZIA", 455_300_120),
    ("linux_secure", "Linux", "auth", 1_203_112),
    ("syslog", "Linux", "syslog", 22_091_332),
    ("bro:conn:json", "Zeek", "conn", 601_230_118),
    ("bro:dns:json", "Zeek", "dns", 220_118_004),
    ("proofpoint:tap", "Proofpoint", "TAP", 140_221),
    ("kube:audit", "Kubernetes", "audit", 7_441_002),
]

SAMPLE_RULES = [
    ("ESCU - Suspicious PowerShell Encoded Command", ["T1059.001", "T1027.010"], "high"),
    ("ESCU - Windows Scheduled Task Created via Schtasks", ["T1053.005"], "medium"),
    ("ESCU - Detect Mimikatz With PowerShell Script Block Logging", ["T1003.001", "T1059.001"], "critical"),
    ("ESCU - Windows Service Created with Suspicious Path", ["T1543.003"], "medium"),
    ("ESCU - Registry Run Key Persistence", ["T1547.001"], "medium"),
    ("ESCU - WMI Lateral Movement", ["T1047", "T1021"], "high"),
    ("ESCU - Rundll32 Process Creating Exe Dll Files", ["T1218.011"], "high"),
    ("ESCU - Credential Dumping via LSASS Access", ["T1003.001"], "critical"),
    ("ESCU - Suspicious Kerberoasting Activity", ["T1558.003"], "high"),
    ("ESCU - AWS IAM Access Key Created For Another User", ["T1098.001"], "high"),
    ("ESCU - AWS CloudTrail Logging Disabled", ["T1562.008"], "critical"),
    ("ESCU - AWS Console Login Without MFA", ["T1078.004"], "medium"),
    ("ESCU - O365 New Inbox Rule Forwarding Email", ["T1114.003", "T1564.008"], "high"),
    ("ESCU - Okta MFA Fatigue Push Spam", ["T1621"], "high"),
    ("ESCU - Azure AD Privileged Role Assigned", ["T1098.003"], "high"),
    ("ESCU - DNS Query Length With High Entropy", ["T1071.004", "T1568"], "medium"),
    ("ESCU - Excessive Outbound Data Transfer", ["T1048", "T1041"], "medium"),
    ("ESCU - Suspicious Proxy Download of Executable", ["T1105"], "medium"),
    ("ESCU - Linux Sudoers Modification", ["T1548.003"], "medium"),
    ("ESCU - Linux SSH Authorized Keys Modification", ["T1098.004"], "medium"),
    ("ESCU - Kubernetes Pod Created in Kube-System", ["T1610"], "medium"),
    ("ESCU - Windows Event Log Cleared", ["T1070.001"], "high"),
    ("ESCU - Disabling Windows Defender", ["T1562.001"], "high"),
    ("ESCU - Remote Desktop Lateral Movement", ["T1021.001"], "medium"),
    ("ESCU - Phishing Attachment Opened by Office Application", ["T1566.001", "T1204.002"], "high"),
    ("ESCU - macOS Launch Agent Persistence", ["T1543.001"], "medium"),
    ("ESCU - ESXi VM Powered Off via esxcli", ["T1529"], "high"),
    ("ESCU - Network Share Discovery via net view", ["T1135"], "low"),
    ("ESCU - Spearphishing Link Detected by Proofpoint", ["T1566.002"], "high"),
    ("ESCU - Inhibit System Recovery via vssadmin", ["T1490"], "critical"),
]


class DemoConnector(BaseConnector):
    type = "demo"
    label = "Demo (sample data)"
    description = "Built-in sample inventory of 18 log sources and 30 rules so you can explore the heatmap without a SIEM."
    provides_rules = True
    fields = [
        FieldSpec("note", "Note", type="textarea", help="Free text. The sample data is static.", default=""),
    ]

    async def test(self) -> TestResult:
        return TestResult(True, "Demo connector is always available.")

    async def fetch(self) -> FetchResult:
        out = FetchResult()
        for name, vendor, product, count in SAMPLE_LOG_SOURCES:
            out.log_sources.append(
                LogSourceRecord(external_id=name, name=name, kind="sourcetype", vendor=vendor, product=product, event_count=count)
            )
        for i, (name, techniques, sev) in enumerate(SAMPLE_RULES):
            out.rules.append(
                RuleRecord(
                    external_id=f"demo-{i}",
                    name=name,
                    enabled=True,
                    severity=sev,
                    techniques=techniques,
                    attributes={"source": "demo"},
                )
            )
        return out
