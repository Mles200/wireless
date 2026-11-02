"""The Nessus source: .nessus parsing, scan selection, the pull against a mock Nessus and the
First Discovered carried forward between pulls."""
from __future__ import annotations

import time

import pytest
from fastapi import FastAPI, Request

from trs_connector.config import Config
from trs_connector.exporter import PullProgress
from trs_connector.export_schema import is_compliance, sc_record_to_row
from trs_connector.nessus_source import parse_nessus, pull_nessus, select_scans
from trs_connector.store import ExportStore, read_export

from tests.conftest import STUDIO, ServerThread, free_port

NESSUS_XML = """<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy><policyName>Agent VA + CIS</policyName></Policy>
<Report name="Agent VA + CIS" xmlns:cm="http://www.nessus.org/cm">
<ReportHost name="10.70.10.11"><HostProperties>
<tag name="HOST_END">Fri Oct 24 06:12:33 2026</tag><tag name="HOST_START">Fri Oct 24 05:40:01 2026</tag>
<tag name="host-ip">10.70.10.11</tag><tag name="host-fqdn">prdadds01.altanfeethi.local</tag><tag name="netbios-name">PRDADDS01</tag>
<tag name="mac-address">00:50:56:aa:bb:cc</tag><tag name="operating-system">Microsoft Windows Server 2022 Standard</tag>
<tag name="host-uuid">9d0f8a4e-1111-2222-3333-444444444444</tag><tag name="tenable_agent_uuid">aaaa-bbbb</tag>
</HostProperties>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="4" pluginID="208296" pluginName="KB5044281: Windows Server 2022 Security Update (October 2024)" pluginFamily="Windows : Microsoft Bulletins">
<description>The remote Windows host is missing security update 5044281.</description>
<plugin_output>The following Windows components are missing security update 5044281:
  - 10.0.20348.2762</plugin_output>
<plugin_publication_date>2024/10/08</plugin_publication_date><plugin_modification_date>2024/10/10</plugin_modification_date>
<patch_publication_date>2024/10/08</patch_publication_date><vuln_publication_date>2024/10/08</vuln_publication_date>
<plugin_type>local</plugin_type><risk_factor>Critical</risk_factor><script_version>1.3</script_version>
<see_also>https://support.microsoft.com/help/5044281</see_also><solution>Apply Security Update 5044281</solution>
<synopsis>The remote Windows host is affected by multiple vulnerabilities.</synopsis>
<cve>CVE-2024-43572</cve><cve>CVE-2024-43573</cve><xref>CISA-KNOWN-EXPLOITED:2024/10/29</xref><xref>MSKB:5044281</xref>
<cvss3_base_score>9.8</cvss3_base_score><cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</cvss3_vector><cvss_base_score>9.3</cvss_base_score>
<exploit_available>true</exploit_available><exploitability_ease>Exploits are available</exploitability_ease><exploit_framework_metasploit>true</exploit_framework_metasploit>
<vpr_score>9.2</vpr_score><epss_score>0.45</epss_score><cpe>cpe:/o:microsoft:windows_server_2022</cpe>
</ReportItem>
<ReportItem port="445" svc_name="cifs" protocol="tcp" severity="2" pluginID="57608" pluginName="SMB Signing not required" pluginFamily="Misc.">
<plugin_output></plugin_output><plugin_type>remote</plugin_type><risk_factor>Medium</risk_factor><solution>Enforce message signing in the host's configuration.</solution><synopsis>Signing is not required on the remote SMB server.</synopsis>
<cvss3_base_score>5.3</cvss3_base_score><cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N</cvss3_vector>
</ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="11936" pluginName="OS Identification" pluginFamily="General">
<plugin_output>
Remote operating system : Microsoft Windows Server 2022 Standard
Confidence level : 100</plugin_output><plugin_type>combined</plugin_type><risk_factor>None</risk_factor><synopsis>It is possible to guess the remote operating system.</synopsis>
</ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="3" pluginID="21156" pluginName="Windows Compliance Checks" pluginFamily="Policy Compliance">
<cm:compliance-check-name>1.1.4 Ensure 'Minimum password length' is set to '14 or more character(s)'</cm:compliance-check-name>
<cm:compliance-result>FAILED</cm:compliance-result><cm:compliance-actual-value>8</cm:compliance-actual-value><cm:compliance-policy-value>[14..MAX]</cm:compliance-policy-value>
<cm:compliance-info>This policy setting determines the least number of characters that make up a password.</cm:compliance-info>
<cm:compliance-solution>Set Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password length to 14 or more character(s)</cm:compliance-solution>
<cm:compliance-see-also>https://workbench.cisecurity.org/benchmarks/16913</cm:compliance-see-also><cm:compliance-reference>800-53|IA-5,CIS_Windows_2022|1.1.4</cm:compliance-reference>
<cm:compliance-audit-file>CIS_Microsoft_Windows_Server_2022_Benchmark_v3.0.0_L1_MS.audit</cm:compliance-audit-file>
<description>Minimum password length</description><plugin_type>local</plugin_type><risk_factor>None</risk_factor>
</ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="21156" pluginName="Windows Compliance Checks" pluginFamily="Policy Compliance">
<cm:compliance-check-name>1.1.1 Ensure 'Enforce password history' is set to '24 or more password(s)'</cm:compliance-check-name>
<cm:compliance-result>PASSED</cm:compliance-result><cm:compliance-actual-value>24</cm:compliance-actual-value><cm:compliance-policy-value>[24..MAX]</cm:compliance-policy-value>
<cm:compliance-audit-file>CIS_Microsoft_Windows_Server_2022_Benchmark_v3.0.0_L1_MS.audit</cm:compliance-audit-file>
<plugin_type>local</plugin_type><risk_factor>None</risk_factor>
</ReportItem>
</ReportHost>
<ReportHost name="preprdapp01.altanfeethi.local"><HostProperties>
<tag name="HOST_END">Fri Oct 24 06:20:00 2026</tag><tag name="host-ip">10.70.70.11</tag><tag name="operating-system">Ubuntu 22.04.4 LTS</tag>
</HostProperties>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="3" pluginID="210153" pluginName="OpenSSH &lt; 9.8 (CVE-2024-6387) RCE (regreSSHion)" pluginFamily="Misc.">
<plugin_output>Installed version : 8.9p1</plugin_output><plugin_type>remote</plugin_type><risk_factor>High</risk_factor><solution>Upgrade to OpenSSH version 9.8 or later.</solution><cve>CVE-2024-6387</cve>
<cvss3_base_score>8.1</cvss3_base_score><cvss3_vector>CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</cvss3_vector><exploit_available>true</exploit_available>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
"""


def test_parse_nessus_records():
    recs = list(parse_nessus(NESSUS_XML.encode("utf-8"), "Agent VA + CIS"))
    assert len(recs) == 6
    kb = recs[0]
    assert kb["pluginID"] == "208296" and kb["severity"]["name"] == "Critical" and kb["ip"] == "10.70.10.11" and kb["dnsName"] == "prdadds01.altanfeethi.local"
    assert kb["netbiosName"] == "PRDADDS01" and kb["macAddress"] == "00:50:56:aa:bb:cc" and kb["agentID"] == "aaaa-bbbb" and kb["hostUUID"].startswith("9d0f8a4e")
    assert kb["cve"] == "CVE-2024-43572, CVE-2024-43573" and "CISA-KNOWN-EXPLOITED" in kb["xref"] and kb["exploitFrameworks"] == "Metasploit"
    from datetime import datetime, timezone
    epoch = lambda *a: str(int(datetime(*a, tzinfo=timezone.utc).timestamp()))   # noqa: E731
    assert kb["lastSeen"] == epoch(2026, 10, 24, 6, 12, 33) and kb["patchPubDate"] == epoch(2024, 10, 8) and kb["vprScore"] == "9.2" and kb["epssScore"] == "0.45"
    row = sc_record_to_row(kb)
    assert row["Last Observed"] == "2026-10-24T06:12:33Z" and row["Exploit?"] == "Yes" and row["Steps to Remediate"] == "Apply Security Update 5044281" and row["Port"] == "0" and row["Protocol"] == "TCP"
    failed = recs[3]
    assert is_compliance(failed) and failed["severity"]["name"] == "High" and failed["pluginName"].startswith("1.1.4")
    assert "Result: FAILED" in failed["pluginText"] and "Actual Value: 8" in failed["pluginText"] and "Policy Value: [14..MAX]" in failed["pluginText"]
    assert "Solution: Set Computer Configuration" in failed["pluginText"] and "Reference Information: 800-53|IA-5" in failed["pluginText"] and failed["xref"] == "auditFile #windows, nessusPlugin:21156"
    passed = recs[4]
    assert passed["severity"]["name"] == "Info" and "Result: PASSED" in passed["pluginText"]
    # every check gets its own stable plugin ID in the Security Center compliance range
    assert int(failed["pluginID"]) >= 1_000_000 and int(passed["pluginID"]) >= 1_000_000 and failed["pluginID"] != passed["pluginID"]
    assert failed["pluginID"] == next(r for r in parse_nessus(NESSUS_XML.encode("utf-8"), "x") if r.get("nessusPluginID") and r["pluginName"].startswith("1.1.4"))["pluginID"]
    ssh = recs[5]
    assert ssh["ip"] == "10.70.70.11" and ssh["dnsName"] == "preprdapp01.altanfeethi.local" and ssh["severity"]["name"] == "High" and ssh["port"] == "22"
    assert not is_compliance(recs[2]) and recs[2]["severity"]["name"] == "Info"


def test_select_scans():
    now = 1_800_000_000
    listing = {"folders": [{"id": 3, "name": "My Scans"}, {"id": 4, "name": "Trash"}],
               "scans": [{"id": 1, "name": "Weekly", "status": "completed", "folder_id": 3, "last_modification_date": now - 86400},
                         {"id": 2, "name": "Old", "status": "completed", "folder_id": 3, "last_modification_date": now - 100 * 86400},
                         {"id": 3, "name": "Running", "status": "running", "folder_id": 3, "last_modification_date": now},
                         {"id": 4, "name": "Binned", "status": "completed", "folder_id": 4, "last_modification_date": now}]}
    assert [s["id"] for s in select_scans(listing, [], "", 45, now)] == [1, 4]
    assert [s["id"] for s in select_scans(listing, [], "My Scans", 45, now)] == [1]
    assert [s["id"] for s in select_scans(listing, ["old"], "", 0, now)] == [2]
    assert [s["id"] for s in select_scans(listing, [4], "", 45, now)] == [4]


def mock_nessus(xml: bytes) -> FastAPI:
    app = FastAPI()
    now = int(time.time())

    @app.middleware("http")
    async def auth(request: Request, call_next):
        if request.url.path != "/healthz" and request.headers.get("x-apikeys") != "accessKey=NA; secretKey=NS":
            from fastapi.responses import JSONResponse
            return JSONResponse({"error": "Invalid Credentials"}, status_code=401)
        return await call_next(request)

    @app.get("/healthz")
    async def hz():
        return {"ok": True}

    @app.get("/server/properties")
    async def props():
        return {"server_version": "10.8.3", "nessus_type": "Nessus Manager"}

    @app.get("/scans")
    async def scans():
        return {"folders": [{"id": 3, "name": "My Scans"}], "scans": [{"id": 11, "name": "Agent VA + CIS", "status": "completed", "folder_id": 3, "last_modification_date": now - 3600},
                                                                      {"id": 12, "name": "Discovery", "status": "running", "folder_id": 3, "last_modification_date": now}]}

    @app.post("/scans/{scan_id}/export")
    async def export(scan_id: int):
        return {"file": 77, "token": "tok"}

    @app.get("/scans/{scan_id}/export/{file_id}/status")
    async def status(scan_id: int, file_id: int):
        return {"status": "ready"}

    @app.get("/scans/{scan_id}/export/{file_id}/download")
    async def download(scan_id: int, file_id: int):
        from fastapi.responses import Response
        return Response(xml, media_type="application/xml")

    return app


@pytest.fixture()
def nessus_cfg(tmp_path):
    srv = ServerThread(mock_nessus(NESSUS_XML.encode("utf-8")), free_port()).start()
    c = Config()
    c.sc.enabled = False
    c.nessus.enabled = True
    c.nessus.url = f"http://127.0.0.1:{srv.port}"
    c.nessus.access_key, c.nessus.secret_key = "NA", "NS"
    c.store.dir = str(tmp_path / "ndata")
    c.schedule.enabled = False
    c.studio.path = str(STUDIO)
    yield c
    srv.stop()


def test_pull_nessus_and_first_seen_carry_forward(nessus_cfg):
    store = ExportStore(nessus_cfg.store.dir)
    m = pull_nessus(nessus_cfg, store, PullProgress("test", "nessus"))
    assert m["status"] == "ok" and m["source"]["type"] == "nessus" and m["source"]["version"] == "10.8.3" and [s["name"] for s in m["source"]["scans"]] == ["Agent VA + CIS"]
    va = read_export(store, m["id"], m["files"][0]["name"])
    cmp = read_export(store, m["id"], m["files"][1]["name"])
    assert len(va) == 4 and len(cmp) == 2 and m["files"][0]["hosts"] == 2
    assert all(r["First Discovered"] == r["Last Observed"] for r in va), "first pull: first seen = last observed"
    assert all(r["Repository"] == "Agent VA + CIS" for r in va)
    # a second pull a week later keeps the First Discovered of the first pull
    later = NESSUS_XML.replace("Fri Oct 24 06:12:33 2026", "Fri Oct 31 06:12:33 2026").replace("Fri Oct 24 06:20:00 2026", "Fri Oct 31 06:20:00 2026")
    srv = ServerThread(mock_nessus(later.encode("utf-8")), free_port()).start()
    try:
        nessus_cfg.nessus.url = f"http://127.0.0.1:{srv.port}"
        m2 = pull_nessus(nessus_cfg, store, PullProgress("test", "nessus"))
    finally:
        srv.stop()
    va2 = read_export(store, m2["id"], m2["files"][0]["name"])
    kb = next(r for r in va2 if r["Plugin"] == "208296")
    assert kb["Last Observed"] == "2026-10-31T06:12:33Z" and kb["First Discovered"] == "2026-10-24T06:12:33Z"
    assert m2["counts"]["first_seen_carried"] == 6 and m2["counts"]["first_seen_new"] == 0
    assert store.latest()["id"] == m2["id"] and len(store.list_pulls()) == 2
