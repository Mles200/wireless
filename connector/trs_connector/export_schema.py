"""The export file layout: the columns of the Security Center "Vulnerability Detail List" CSV
export, with the header names the Studio recognises (see COLS in the Studio source), and the
mapping from the fields of a ``vulndetails`` analysis record onto them.

Rows are plain dicts header -> text; ``HEADERS`` fixes the column order.  Dates are written as
ISO 8601 UTC (``2026-10-25T06:12:33Z``), which every browser parses, instead of the locale
dependent text of the UI export.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# (header as written in the CSV, Studio key or None, candidate field names in the Security Center record, kind)
COLUMNS: list[tuple[str, str | None, list[str], str]] = [
    ("Plugin", "plugin", ["pluginID"], "text"),
    ("Plugin Name", "name", ["pluginName"], "text"),
    ("Family", "family", ["family.name"], "text"),
    ("Severity", "severity", ["severity.name"], "text"),
    ("IP Address", "ip", ["ip"], "text"),
    ("Protocol", "protocol", ["protocol"], "text"),
    ("Port", "port", ["port"], "text"),
    ("Exploit?", "exploit", ["exploitAvailable"], "yesno"),
    ("Repository", "repository", ["repository.name"], "text"),
    ("MAC Address", "mac", ["macAddress"], "text"),
    ("DNS Name", "dns", ["dnsName"], "text"),
    ("NetBIOS Name", "netbios", ["netbiosName"], "text"),
    ("Plugin Text", "output", ["pluginText"], "text"),
    ("Synopsis", "synopsis", ["synopsis"], "text"),
    ("Description", "description", ["description"], "text"),
    ("Steps to Remediate", "solution", ["solution"], "text"),
    ("See Also", "seeAlso", ["seeAlso"], "text"),
    ("Risk Factor", None, ["riskFactor"], "text"),
    ("STIG Severity", None, ["stigSeverity"], "text"),
    ("VPR Score", "vpr", ["vprScore"], "num"),
    ("Exploit Prediction Scoring System (EPSS)", "epss", ["epssScore", "epss"], "num"),
    ("CVSS V2 Base Score", "cvss2", ["baseScore"], "num"),
    ("CVSS V3 Base Score", "cvss3", ["cvssV3BaseScore"], "num"),
    ("CVSS V2 Temporal Score", None, ["temporalScore"], "num"),
    ("CVSS V3 Temporal Score", None, ["cvssV3TemporalScore"], "num"),
    ("CVSS V2 Vector", None, ["cvssVector"], "text"),
    ("CVSS V3 Vector", "vector", ["cvssV3Vector"], "text"),
    ("CPE", "cpe", ["cpe"], "text"),
    ("CVE", "cve", ["cve"], "text"),
    ("BID", None, ["bid"], "text"),
    ("Cross References", "xref", ["xref"], "text"),
    ("Vuln Publication Date", "vulnPub", ["vulnPubDate"], "date"),
    ("Patch Publication Date", "patchDate", ["patchPubDate"], "date"),
    ("Plugin Publication Date", None, ["pluginPubDate"], "date"),
    ("Plugin Modification Date", None, ["pluginModDate"], "date"),
    ("Exploit Ease", "exploitEase", ["exploitEase"], "text"),
    ("Exploit Frameworks", "exploitFw", ["exploitFrameworks"], "text"),
    ("Security End of Life Date", "seol", ["seolDate", "securityEndOfLifeDate", "seol"], "date"),
    ("First Discovered", "firstSeen", ["firstSeen"], "date"),
    ("Last Observed", "lastSeen", ["lastSeen"], "date"),
    ("Check Type", "checkType", ["checkType"], "text"),
    ("Version", "version", ["version"], "text"),
    ("Host ID", "hostId", ["hostUUID", "hostUuid", "uuid"], "text"),
    ("Agent ID", "agentId", ["agentID", "agentUUID", "agentId", "agentUuid"], "text"),
    ("Accept Risk Comment", "acceptComment", ["acceptRiskRuleComment", "acceptRiskComment", "acceptRisk.comments"], "text"),
    ("Recast Risk Comment", "recastComment", ["recastRiskRuleComment", "recastRiskComment", "recastRisk.comments"], "text"),
]

HEADERS: list[str] = [c[0] for c in COLUMNS]
STUDIO_KEYS: dict[str, str] = {c[0]: c[1] for c in COLUMNS if c[1]}

# Column aliases the Studio accepts (copied from COLS in the Studio source) for the fidelity test
STUDIO_COLS: dict[str, list[str]] = {
    "plugin": ["Plugin", "Plugin ID", "pluginID", "Plugin Id"], "name": ["Plugin Name", "pluginName", "Name"], "family": ["Family", "Plugin Family"],
    "severity": ["Severity"], "ip": ["IP Address", "IP", "ip", "Host IP"], "protocol": ["Protocol"], "port": ["Port"], "exploit": ["Exploit?", "Exploit Available", "Exploitable"],
    "repository": ["Repository"], "mac": ["MAC Address"], "dns": ["DNS Name", "dnsName", "DNS"], "netbios": ["NetBIOS Name", "NetBIOS"], "output": ["Plugin Output", "Plugin Text", "pluginText"],
    "synopsis": ["Synopsis"], "description": ["Description"], "solution": ["Steps to Remediate", "Solution"], "cve": ["CVE"], "firstSeen": ["First Discovered", "First Seen"],
    "lastSeen": ["Last Observed", "Last Seen"], "patchDate": ["Patch Publication Date"], "vulnPub": ["Vuln Publication Date"], "xref": ["Cross References"],
    "cvss3": ["CVSS V3 Base Score", "CVSSv3 Base Score"], "cvss2": ["CVSS V2 Base Score", "CVSS Base Score"], "vpr": ["VPR Score", "Vulnerability Priority Rating", "VPR"],
    "exploitEase": ["Exploit Ease"], "exploitFw": ["Exploit Frameworks"], "hostId": ["Host ID"], "agentId": ["Agent ID"], "checkType": ["Check Type"], "os": ["OS", "Operating System"], "seeAlso": ["See Also"],
    "epss": ["Exploit Prediction Scoring System (EPSS)", "EPSS (%)", "EPSS", "EPSS Score"], "seol": ["Security End of Life Date", "Security EOL Date"], "cpe": ["CPE"], "vector": ["CVSS V3 Vector", "CVSS v3 Vector", "CVSSv3 Vector"],
    "version": ["Version", "Plugin Version"], "acceptComment": ["Accept Risk Comment", "Accept/Recast Risk Comment"], "recastComment": ["Recast Risk Comment"],
}

COMPLIANCE_PLUGIN_MIN = 1_000_000   # Security Center compliance plugins


def field(rec: dict, path: str) -> Any:
    """``severity.name`` style lookup; a dict value without a sub-key is reduced to its ``name``."""
    cur: Any = rec
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    if isinstance(cur, dict):
        cur = cur.get("name") or cur.get("id")
    return cur


def first_field(rec: dict, candidates: list[str]) -> Any:
    for c in candidates:
        v = field(rec, c)
        if v is not None and v != "":
            return v
    return None


def fmt_date(v: Any) -> str:
    """Security Center epoch seconds (string or int; -1 / 0 = none) -> ISO 8601 UTC."""
    if v is None or v == "":
        return ""
    if isinstance(v, str):
        s = v.strip()
        if not s or s in ("-1", "0", "N/A"):
            return ""
        if not s.lstrip("-").isdigit():
            return s          # already text (a converter wrote it)
        v = int(s)
    try:
        v = int(v)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    if v > 10_000_000_000:    # milliseconds
        v //= 1000
    return datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_num(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if s in ("", "-1", "N/A", "null"):
        return ""
    return s


def yes_no(v: Any) -> str:
    if isinstance(v, bool):
        return "Yes" if v else "No"
    return "Yes" if str(v).strip().lower() in ("yes", "true", "1") else "No"


def fmt_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ", ".join(fmt_text(x) for x in v)
    s = str(v)
    return s.replace("\r\n", "\n").replace("\r", "\n")


def sc_record_to_row(rec: dict) -> dict[str, str]:
    """One vulndetails record -> one export row (header -> text)."""
    row: dict[str, str] = {}
    for header, _key, candidates, kind in COLUMNS:
        v = first_field(rec, candidates)
        if kind == "date":
            row[header] = fmt_date(v)
        elif kind == "num":
            row[header] = fmt_num(v)
        elif kind == "yesno":
            row[header] = yes_no(v) if v is not None else ""
        else:
            row[header] = fmt_text(v)
    if not row["Port"]:
        row["Port"] = "0"
    row["Protocol"] = row["Protocol"].upper()
    return row


def is_compliance(rec: dict) -> bool:
    ftype = str(field(rec, "family.type") or "").lower()
    if ftype == "compliance":
        return True
    try:
        return int(rec.get("pluginID") or 0) >= COMPLIANCE_PLUGIN_MIN
    except (TypeError, ValueError):
        return False


def dedup_key(rec: dict) -> tuple:
    """Plugin, host, port, protocol and repository; compliance checks also by name, because a
    Nessus export reports every check of an audit under the same plugin ID."""
    return (str(rec.get("pluginID")), str(rec.get("ip")), str(rec.get("port") or "0"), str(rec.get("protocol") or "").upper(),
            str(field(rec, "repository.id") or field(rec, "repository.name") or ""), str(rec.get("pluginName") or "") if is_compliance(rec) else "")


def severity_name(rec: dict) -> str:
    return str(field(rec, "severity.name") or "Info")


def _has_field(rec: dict, path: str) -> bool:
    cur: Any = rec
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    return True


def resolve_mapping(rec: dict, prev: dict | None = None) -> dict[str, str | None]:
    """Which record field each export column comes from, by key presence (an empty value is
    still a present field), merged over the records it is called with; for ``trs-connector probe``."""
    out: dict[str, str | None] = dict(prev or {})
    for header, _key, candidates, _kind in COLUMNS:
        if out.get(header):
            continue
        out[header] = next((c for c in candidates if _has_field(rec, c)), None)
    return out
