"""A synthetic Security Center dataset shaped like real ``vulndetails`` records: the hosts follow
the ALTANFEETHI segmentation rules of the Studio (subnets and host names), the plugins are
real plugin names and families, the compliance rows carry the CIS plugin output the Studio
parses, and the inventory plugins give the hosts their OS and names.  Used by the mock
Security Center (tests and ``trs-connector demo``).
"""
from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

DAY = 86400


@dataclass
class SynthOptions:
    hosts: int = 40
    seed: int = 1
    scan_date: str = "2026-10-25"      # Last Observed of the current scan (UTC)
    shift_days: int = 0                # a previous scan: everything moved back by this many days
    drop_plugin_ids: tuple = ()        # plugins removed (for a "fixed" dataset)


VA_PLUGINS = [
    # id, name, family, severity, cvss3, vector, vpr, epss, exploit, kev, cve, solution, checkType, cpe, seol, synopsis
    (209293, "Microsoft Edge (Chromium) < 130.0.2849.46 Multiple Vulnerabilities", "Windows", "High", 8.8, "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.4, 0.02, True, False, "CVE-2024-9954, CVE-2024-9955, CVE-2024-9956", "Upgrade to Microsoft Edge version 130.0.2849.46 or later.", "local", "cpe:/a:microsoft:edge", "", "The remote host has a web browser installed that is affected by multiple vulnerabilities."),
    (208754, "Microsoft Edge (Chromium) < 129.0.2792.89 Multiple Vulnerabilities", "Windows", "High", 8.8, "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.1, 0.01, False, False, "CVE-2024-9602, CVE-2024-9603", "Upgrade to Microsoft Edge version 129.0.2792.89 or later.", "local", "cpe:/a:microsoft:edge", "", "The remote host has a web browser installed that is affected by multiple vulnerabilities."),
    (208296, "KB5044281: Windows Server 2022 Security Update (October 2024)", "Windows : Microsoft Bulletins", "Critical", 9.8, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.2, 0.45, True, True, "CVE-2024-43572, CVE-2024-43573, CVE-2024-43583", "Apply Security Update 5044281", "local", "cpe:/o:microsoft:windows_server_2022", "", "The remote Windows host is affected by multiple vulnerabilities."),
    (208289, "KB5044277: Windows 10 Version 21H2 / Windows 10 Version 22H2 Security Update (October 2024)", "Windows : Microsoft Bulletins", "Critical", 9.8, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.0, 0.40, True, True, "CVE-2024-43572, CVE-2024-43573", "Apply Security Update 5044277", "local", "cpe:/o:microsoft:windows_10", "", "The remote Windows host is affected by multiple vulnerabilities."),
    (206896, "VMware Tools 12.x < 12.5.0 Vulnerability (VMSA-2024-0020)", "General", "High", 7.8, "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 6.7, 0.00, False, False, "CVE-2024-38814", "Upgrade to VMware Tools version 12.5.0 or later.", "local", "cpe:/a:vmware:tools", "", "A virtualization tool suite installed on the remote host is affected by a vulnerability."),
    (57582, "SSL Self-Signed Certificate", "General", "Medium", 6.5, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.4, 0.00, False, False, "", "Purchase or generate a proper SSL certificate for this service.", "remote", "", "", "The SSL certificate chain for this service ends in an unrecognized self-signed certificate."),
    (51192, "SSL Certificate Cannot Be Trusted", "General", "Medium", 6.5, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.4, 0.00, False, False, "", "Purchase or generate a proper SSL certificate for this service.", "remote", "", "", "The SSL certificate for this service cannot be trusted."),
    (42873, "SSL Medium Strength Cipher Suites Supported (SWEET32)", "General", "High", 7.5, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, 0.03, False, False, "CVE-2016-2183", "Reconfigure the affected application if possible to avoid use of medium strength ciphers.", "remote", "", "", "The remote service supports the use of medium strength SSL ciphers."),
    (57608, "SMB Signing not required", "Misc.", "Medium", 5.3, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 3.6, 0.00, False, False, "", "Enforce message signing in the host's configuration. On Windows, this is found in the policy setting 'Microsoft network server: Digitally sign communications (always)'.", "remote", "", "", "Signing is not required on the remote SMB server."),
    (11219, "Nessus SYN scanner", "Port scanners", "Info", None, "", None, None, False, False, "", "Protect your target with an IP filter.", "remote", "", "", "It is possible to determine which TCP ports are open."),
    (65821, "SSL RC4 Cipher Suites Supported (Bar Mitzvah)", "General", "Medium", 5.9, "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.0, 0.01, False, False, "CVE-2013-2566, CVE-2015-2808", "Reconfigure the affected application, if possible, to avoid use of RC4 ciphers.", "remote", "", "", "The remote service supports the use of the RC4 cipher."),
    (207086, "Oracle Java SE 1.8.0_421 / 11.0.24 / 17.0.12 / 21.0.4 / 22.0.2 Multiple Vulnerabilities (July 2024 CPU)", "Misc.", "High", 7.5, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.2, 0.00, False, False, "CVE-2024-21131, CVE-2024-21138", "Upgrade to Oracle JDK / JRE 22 Update 2, 21 Update 4, 17 Update 12, 11 Update 24, 8 Update 421 or later.", "local", "cpe:/a:oracle:jre", "", "Oracle (formerly Sun) Java SE or Java for Business is affected by multiple vulnerabilities."),
    (200286, "Microsoft .NET Core SEoL (3.1.x)", "Windows", "Critical", 10.0, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 6.7, 0.00, False, False, "", "Upgrade to a version of Microsoft .NET Core that is currently supported.", "local", "cpe:/a:microsoft:.net_core:3.1", "2022-12-13", "An unsupported version of Microsoft .NET Core is installed on the remote host."),
    (195152, "Microsoft Windows Server 2012 R2 SEoL", "Windows", "Critical", 10.0, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 7.4, 0.00, False, False, "", "Upgrade to a version of Windows Server that is currently supported.", "local", "cpe:/o:microsoft:windows_server_2012:r2", "2023-10-10", "An unsupported version of Windows Server is installed on the remote host."),
    (10114, "ICMP Timestamp Request Remote Date Disclosure", "General", "Low", 2.1, "", 1.4, 0.00, False, False, "CVE-1999-0524", "Filter out the ICMP timestamp requests (13), and the outgoing ICMP timestamp replies (14).", "remote", "", "", "It is possible to determine the exact time set on the remote host."),
    (187315, "Microsoft Windows SMB Server (CVE-2024-21371) Elevation of Privilege", "Windows", "High", 7.0, "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 5.9, 0.00, False, False, "CVE-2024-21371", "Apply the applicable security update.", "local", "", "", "The remote Windows host is affected by an elevation of privilege vulnerability."),
    (205364, "Fortinet FortiOS Multiple Vulnerabilities (FG-IR-24-015)", "Firewalls", "Critical", 9.8, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.6, 0.90, True, True, "CVE-2024-21762", "Upgrade to FortiOS version 7.4.3, 7.2.7, 7.0.14 or later.", "remote", "cpe:/o:fortinet:fortios", "", "The remote host is affected by multiple vulnerabilities."),
    (210153, "OpenSSH < 9.8 (CVE-2024-6387) RCE (regreSSHion)", "Misc.", "High", 8.1, "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4, 0.15, True, False, "CVE-2024-6387", "Upgrade to OpenSSH version 9.8 or later.", "remote", "cpe:/a:openbsd:openssh", "", "The SSH server running on the remote host is affected by a remote code execution vulnerability."),
    (209452, "Ubuntu 22.04 LTS : Linux kernel vulnerabilities (USN-7069-1)", "Ubuntu Local Security Checks", "High", 7.8, "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 6.7, 0.00, False, False, "CVE-2024-42240, CVE-2024-43882", "Update the affected kernel packages.", "local", "cpe:/o:canonical:ubuntu_linux:22.04", "", "The remote Ubuntu host is missing one or more security updates."),
    (208985, "Adobe Acrobat < 20.005.30710 / 24.003.20112 Multiple Vulnerabilities (APSB24-70)", "Windows", "Critical", 7.8, "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 6.7, 0.01, False, False, "CVE-2024-45112, CVE-2024-41869", "Upgrade to Adobe Acrobat version 20.005.30710 / 24.003.20112 or later.", "local", "cpe:/a:adobe:acrobat", "", "The version of Adobe Acrobat installed on the remote Windows host is affected by multiple vulnerabilities."),
    (26920, "Microsoft Windows SMB NULL Session Authentication", "Windows", "Medium", 5.0, "", 3.9, 0.00, False, False, "CVE-1999-0519, CVE-2002-1117", "Restrict anonymous access: set RestrictAnonymous = 2.", "remote", "", "", "It is possible to log into the remote Windows host with a NULL session."),
]

INVENTORY = {
    11936: ("OS Identification", "General"), 55472: ("Device Hostname", "General"), 19506: ("Nessus Scan Information", "Settings"),
    45590: ("Common Platform Enumeration (CPE)", "General"), 209654: ("OS Security Patch Assessment Information", "Settings"),
}

CIS_CHECKS = [   # (check name, policy value, actual value when failing, solution, section refs)
    ("1.1.1 Ensure 'Enforce password history' is set to '24 or more password(s)'", "[24..MAX]", "10", "To establish the recommended configuration via GP, set the following UI path to 24 or more password(s): Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Enforce password history", "800-53|IA-5,CIS_Windows_2022|1.1.1"),
    ("1.1.2 Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'", "[1..365]", "0", "Set Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Maximum password age to 365 or fewer days, but not 0", "800-53|IA-5"),
    ("1.1.4 Ensure 'Minimum password length' is set to '14 or more character(s)'", "[14..MAX]", "8", "Set Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password length to 14 or more character(s)", "800-53|IA-5"),
    ("2.3.1.1 Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'", "3", "0", "Set Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Accounts: Block Microsoft accounts", "800-53|AC-2"),
    ("2.3.7.1 Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'", "0", "1", "Set Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Do not require CTRL+ALT+DEL to Disabled", "800-53|AC-7"),
    ("2.3.9.2 Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'", "1", "0", "Set Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Microsoft network server: Digitally sign communications (always) to Enabled", "800-53|SC-8"),
    ("9.1.1 Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'", "1", "0", "Set Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Firewall with Advanced Security\\Domain Profile\\Firewall state to On", "800-53|SC-7"),
    ("17.5.1 Ensure 'Audit Account Lockout' is set to include 'Failure'", "Failure", "No Auditing", "Set Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Logon/Logoff\\Audit Account Lockout to include Failure", "800-53|AU-2"),
    ("18.4.3 Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'", "0", "1", "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel:DisableExceptionChainValidation to 0", "800-53|SI-16"),
    ("18.9.4.1 Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'", "0", "2", "Set Computer Configuration\\Policies\\Administrative Templates\\System\\Credentials Delegation\\Encryption Oracle Remediation to Enabled: Force Updated Clients", "800-53|SC-8"),
    ("5.3 Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'", "4", "3", "Set the Computer Browser service startup type to Disabled", "800-53|CM-7"),
    ("3.1 Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'", "[32768..MAX]", "20480", "Set Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Event Log Service\\Application\\Specify the maximum log file size (KB) to 32,768 or greater", "800-53|AU-4"),
]
AUDIT_FILE = "CIS_Microsoft_Windows_Server_2022_Benchmark_v3.0.0_L1_MS.audit from CIS Microsoft Windows Server 2022 Benchmark"


def _epoch(date: str) -> int:
    return int(datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()) + 6 * 3600


def synth_hosts(n: int, rng: random.Random) -> list[dict]:
    """Hosts across the ALTANFEETHI subnets with the host names the segmentation rules expect."""
    roles = [("ADDS", "Active Directory"), ("SQLDB", "Database"), ("CRMAPP", "CRM"), ("HAYAK", "Hayaak"), ("INTSP", "SharePoint"), ("ADFS", "ADFS"), ("WAP1", "Web Application Proxy"), ("JUMP", "Jump server"), ("CRIBL", "Log collection"), ("APP", ""), ("WEB", ""), ("FILE", "")]
    hosts = []
    i = 0
    while len(hosts) < n:
        kind = i % 10
        if kind < 5:        # production server, agent + network
            role, _ = roles[(i // 10) % len(roles)]
            idx = len([h for h in hosts if h["env"] == "prod"]) + 1
            hosts.append({"ip": f"10.70.10.{10 + idx}", "name": f"PRD{role}{idx:02d}", "dns": f"prd{role.lower()}{idx:02d}.altanfeethi.local", "env": "prod", "os": "Microsoft Windows Server 2022 Standard", "agent": True, "network": True, "cis": True, "cpe": "cpe:/o:microsoft:windows_server_2022"})
        elif kind == 5:     # DR server, agent only
            idx = len([h for h in hosts if h["env"] == "dr"]) + 1
            hosts.append({"ip": f"10.70.20.{10 + idx}", "name": f"DRSQLDB{idx:02d}" if idx % 2 else f"DRAPP{idx:02d}", "dns": f"drsqldb{idx:02d}.altanfeethi.local", "env": "dr", "os": "Microsoft Windows Server 2019 Standard", "agent": True, "network": False, "cis": True, "cpe": "cpe:/o:microsoft:windows_server_2019"})
        elif kind == 6:     # pre-production, both (duplicates)
            idx = len([h for h in hosts if h["env"] == "preprod"]) + 1
            hosts.append({"ip": f"10.70.70.{10 + idx}", "name": f"PREPRDAPP{idx:02d}", "dns": f"preprdapp{idx:02d}.altanfeethi.local", "env": "preprod", "os": "Ubuntu 22.04.4 LTS" if idx % 2 else "Microsoft Windows Server 2022 Standard", "agent": True, "network": True, "cis": idx % 2 == 0, "cpe": "cpe:/o:canonical:ubuntu_linux:22.04" if idx % 2 else "cpe:/o:microsoft:windows_server_2022"})
        elif kind == 7:     # HQ workstation, agent
            idx = len([h for h in hosts if h["env"] == "hq"]) + 1
            hosts.append({"ip": f"10.200.5.{20 + idx}", "name": f"HQ-WS-{idx:03d}", "dns": f"hq-ws-{idx:03d}.altanfeethi.local", "env": "hq", "os": "Microsoft Windows 10 Enterprise", "agent": True, "network": False, "cis": False, "cpe": "cpe:/o:microsoft:windows_10"})
        elif kind == 8:     # CCTV server
            idx = len([h for h in hosts if h["env"] == "cctv"]) + 1
            hosts.append({"ip": f"10.80.81.{10 + idx}", "name": f"RUHT5CCTVJUMP{idx:02d}", "dns": f"ruht5cctvjump{idx:02d}.altanfeethi.local", "env": "cctv", "os": "Microsoft Windows Server 2016 Standard", "agent": True, "network": True, "cis": False, "cpe": "cpe:/o:microsoft:windows_server_2016"})
        else:               # firewall (network only)
            idx = len([h for h in hosts if h["env"] == "network"]) + 1
            hosts.append({"ip": f"192.168.10.{idx}", "name": "", "dns": "", "env": "network", "os": "FortiOS", "agent": False, "network": True, "cis": False, "cpe": "cpe:/o:fortinet:fortios"})
        i += 1
    for h in hosts:
        h["mac"] = "00:50:56:%02x:%02x:%02x" % (rng.randrange(256), rng.randrange(256), rng.randrange(256))
        h["uuid"] = str(uuid.UUID(int=rng.getrandbits(128)))
        h["agent_id"] = str(uuid.UUID(int=rng.getrandbits(128))) if h["agent"] else ""
        h["netbios"] = ("ALTANFEETHI\\" + h["name"]) if h["name"] else ""
    return hosts


def synth_dataset(opts: SynthOptions | None = None) -> dict:
    opts = opts or SynthOptions()
    rng = random.Random(opts.seed)
    hosts = synth_hosts(opts.hosts, rng)
    scan_ts = _epoch(opts.scan_date) - opts.shift_days * DAY
    repos = [{"id": "1", "name": "Vulnerability Repository", "description": "Network scans", "type": "Local", "dataFormat": "IPv4"},
             {"id": "2", "name": "Compliance Repository", "description": "Agent scans", "type": "Local", "dataFormat": "agent"}]
    records: list[dict] = []
    drop = set(int(p) for p in opts.drop_plugin_ids)

    def rec(h, p, repo, port, proto, sev, text, first_days=None, extra=None) -> dict:
        pid, name, family, severity, cvss3, vector, vpr, epss, exploit, kev, cve, solution, check, cpe, seol, synopsis = p
        first = scan_ts - (first_days if first_days is not None else rng.choice([3, 12, 30, 45, 75, 120, 200])) * DAY
        r = {"pluginID": str(pid), "pluginName": name, "family": {"id": "1", "name": family, "type": "active"}, "severity": {"id": {"Info": "0", "Low": "1", "Medium": "2", "High": "3", "Critical": "4"}[sev], "name": sev, "description": f"{sev} Severity"},
             "ip": h["ip"], "uuid": h["uuid"], "hostUUID": h["uuid"], "agentID": h["agent_id"] if repo["id"] == "2" else "", "port": str(port), "protocol": proto, "netbiosName": h["netbios"], "dnsName": h["dns"], "macAddress": h["mac"],
             "firstSeen": str(first), "lastSeen": str(scan_ts - rng.randrange(0, 5 * 3600)), "exploitAvailable": "Yes" if exploit else "No", "exploitEase": "Exploits are available" if exploit else "No known exploits are available",
             "exploitFrameworks": "Metasploit" if exploit and kev else "", "synopsis": synopsis, "description": f"{synopsis} The installed version is affected. {name}.", "solution": solution, "seeAlso": "https://www.tenable.com/plugins/nessus/%d" % pid,
             "riskFactor": sev, "stigSeverity": "", "baseScore": "" if cvss3 is None else str(round(cvss3 - 0.3, 1)), "temporalScore": "", "cvssVector": "", "cvssV3BaseScore": "" if cvss3 is None else str(cvss3), "cvssV3TemporalScore": "", "cvssV3Vector": vector,
             "cpe": cpe, "vprScore": "" if vpr is None else str(vpr), "vprContext": "", "epssScore": "" if epss is None else str(epss), "cve": cve, "bid": "", "xref": ("CISA-KNOWN-EXPLOITED:2024/10/29, " if kev else "") + ("MSKB:" + name[2:9] if name.startswith("KB") else "IAVA:2024-A-0001"),
             "pluginPubDate": str(first - 20 * DAY), "pluginModDate": str(first - 5 * DAY), "checkType": check, "version": "1.%d" % rng.randrange(1, 9), "vulnPubDate": str(first - 30 * DAY), "patchPubDate": str(first - 28 * DAY) if solution.startswith(("Apply", "Upgrade", "Update")) else "",
             "pluginText": text, "recastRisk": "", "acceptRisk": "", "hasBeenMitigated": "0", "repository": repo, "operatingSystem": h["os"], "seolDate": str(_epoch(seol)) if seol else "", "acceptRiskRuleComment": "", "recastRiskRuleComment": ""}
        if extra:
            r.update(extra)
        return r

    inv_text = {
        11936: lambda h: f"\nRemote operating system : {h['os']}\nConfidence level : 100\nMethod : SMB\n\n \nThe remote host is running {h['os']}",
        55472: lambda h: f"\n  Hostname : {h['name'] or h['ip']}\n  FQDN : {h['dns'] or h['ip']}\n",
        19506: lambda h: "Information about this scan : \n\nNessus version : 10.8.3\nPlugin feed version : 202410250612\nScan type : Agent\nScanner IP : 10.70.30.2\nCredentialed checks : yes\n",
        45590: lambda h: f"\nThe remote operating system matched the following CPE : \n\n  {h['cpe']}\n",
        209654: lambda h: "\nOS Security Patch Assessment is available.\n",
    }
    for h in hosts:
        repo_list = ([repos[1]] if h["agent"] else []) + ([repos[0]] if h["network"] else [])
        # local findings (agent repository), remote findings (network repository); pre-production hosts have everything in both
        local = [p for p in VA_PLUGINS if p[12] == "local" and p[0] not in drop]
        remote = [p for p in VA_PLUGINS if p[12] == "remote" and p[0] not in drop]
        if h["env"] == "network":
            # the first two firewalls have remote findings; the others were only seen by the ping / SYN scan (inventory rows only)
            fw_index = int(h["ip"].rsplit(".", 1)[1])
            chosen_local, chosen_remote = [], ([p for p in remote if p[0] in (205364, 57582, 10114)] if fw_index <= 2 else [])
        else:
            n_local = rng.randrange(4, min(9, len(local)))
            chosen_local = rng.sample([p for p in local if _applies(p, h)], min(n_local, len([p for p in local if _applies(p, h)])))
            chosen_remote = rng.sample([p for p in remote if p[0] != 205364], rng.randrange(1, 4)) if h["network"] else []
        for p in chosen_local:
            text = f"\nPath              : C:\\Program Files (x86)\\Microsoft\\Edge\\Application\nInstalled version : 128.0.2739.42\nFixed version     : 130.0.2849.46\n" if "Edge" in p[1] else f"\nThe following Windows components are missing security update {p[1][2:9]}:\n  - 10.0.20348.2762\n" if p[1].startswith("KB") else f"\n  Path              : C:\\Program Files\\{p[1].split(' ')[0]}\n  Installed version : affected\n"
            for repo in ([repos[1]] if h["agent"] else [repos[0]]):
                records.append(rec(h, p, repo, 0, "TCP", p[3], text))
            if h["env"] == "preprod" and h["network"]:    # same finding stored in both repositories (the duplicates the Studio removes)
                records.append(rec(h, p, repos[0], 0, "TCP", p[3], text))
        for p in chosen_remote:
            port = 443 if "SSL" in p[1] else 445 if "SMB" in p[1] else 22 if "SSH" in p[1] else 0
            text = f"\nThe following certificate was at the top of the certificate\nchain sent by the remote host, but it is self-signed:\n\n|-Subject : CN={h['dns'] or h['ip']}\n" if "SSL" in p[1] else "\nThe remote host supports the following ciphers : RC4-SHA\n" if "RC4" in p[1] else ""
            records.append(rec(h, p, repos[0] if h["network"] else repos[1], port, "ICMP" if port == 0 and "ICMP" in p[1] else "TCP", p[3], text))
        # inventory rows
        for pid, (pname, fam) in INVENTORY.items():
            if h["env"] == "network" and pid not in (11936, 19506):
                continue
            p = (pid, pname, fam, "Info", None, "", None, None, False, False, "", "n/a", "remote", "", "", pname)
            records.append(rec(h, p, repo_list[0], 0, "TCP", "Info", inv_text[pid](h), 0))
        # compliance rows (agent repository)
        if h["cis"]:
            audit_row = rec(h, (1000000, AUDIT_FILE, "Policy Compliance", "Info", None, "", None, None, False, False, "", "", "local", "", "", AUDIT_FILE), repos[1], 0, "TCP", "Info", f'"{AUDIT_FILE}" : [PASSED]\n\nInformation: audit file applied\n\nResult: PASSED\n', 0)
            audit_row["family"] = {"id": "41", "name": "Policy Compliance", "type": "compliance"}
            records.append(audit_row)
            for ci, (cname, policy, actual_bad, solution, refs) in enumerate(CIS_CHECKS, start=1):
                pid = 1000000 + ci
                failed = rng.random() < 0.35
                warn = not failed and rng.random() < 0.05
                result = "FAILED" if failed else "WARNING" if warn else "PASSED"
                sev = "High" if failed else "Medium" if warn else "Info"
                actual = actual_bad if failed else ("" if warn else policy.strip("[]").split("..")[0])
                text = (f'"{cname}" : [{result}]\n\nInformation: {cname.split(" ", 1)[1]}. Rationale: a weaker setting lowers the security of the host.\n\n'
                        f"Result: {result}\n\nActual Value: {actual or 'unable to determine'}\n\nPolicy Value: {policy}\n\nSolution: {solution}\n\nImpact: None, the recommended setting is the default in hardened builds.\n\n"
                        f"See Also: https://workbench.cisecurity.org/benchmarks/16913\n\nReference Information: {refs}")
                p = (pid, cname, "Policy Compliance", sev, None, "", None, None, False, False, "", solution, "local", "", "", cname)
                r = rec(h, p, repos[1], 0, "TCP", sev, text, 30, {"xref": "auditFile #windows"})
                r["family"] = {"id": "41", "name": "Policy Compliance", "type": "compliance"}
                r["solution"] = ""     # the audit solution lives in the plugin text, as in Security Center
                records.append(r)
    rules_accept = [
        {"id": "1", "hostType": "ip", "hostValue": hosts[0]["ip"], "port": "445", "protocol": "6", "expires": str(scan_ts + 180 * DAY), "status": "0", "comments": "SMB signing exception for the backup appliance, risk accepted by the CISO (ticket SEC-421)", "createdTime": str(scan_ts - 40 * DAY), "modifiedTime": str(scan_ts - 40 * DAY), "plugin": {"id": "57608", "name": "SMB Signing not required"}, "repository": {"id": "1", "name": "Vulnerability Repository"}, "user": {"id": "3", "username": "cybersec.admin"}},
        {"id": "2", "hostType": "all", "hostValue": "", "port": "-1", "protocol": "-1", "expires": "-1", "status": "0", "comments": "ICMP timestamp: no exposure, accepted", "createdTime": str(scan_ts - 90 * DAY), "modifiedTime": str(scan_ts - 90 * DAY), "plugin": {"id": "10114", "name": "ICMP Timestamp Request Remote Date Disclosure"}, "repository": {"id": "1", "name": "Vulnerability Repository"}, "user": {"id": "3", "username": "cybersec.admin"}},
    ]
    rules_recast = [
        {"id": "1", "hostType": "ip", "hostValue": hosts[2]["ip"], "port": "-1", "protocol": "-1", "newSeverity": {"id": "2", "name": "Medium"}, "status": "0", "comments": "Internal only, behind the WAF; recast to Medium pending the upgrade window", "createdTime": str(scan_ts - 20 * DAY), "modifiedTime": str(scan_ts - 20 * DAY), "plugin": {"id": "42873", "name": "SSL Medium Strength Cipher Suites Supported (SWEET32)"}, "repository": {"id": "1", "name": "Vulnerability Repository"}, "user": {"id": "3", "username": "cybersec.admin"}},
    ]
    scans = [
        {"id": "101", "name": "Weekly VA - all servers", "status": "Completed", "startTime": str(scan_ts - 7 * 3600), "finishTime": str(scan_ts - 2 * 3600), "scannedIPs": str(len(hosts) - 4), "totalIPs": str(len(hosts)), "completedIPs": str(len(hosts) - 4), "importStatus": "Successful", "totalChecks": "188000", "repository": {"id": "1", "name": "Vulnerability Repository"}},
        {"id": "102", "name": "Agent VA + CIS", "status": "Completed", "startTime": str(scan_ts - 6 * 3600), "finishTime": str(scan_ts - 3 * 3600), "scannedIPs": str(len([h for h in hosts if h["agent"]])), "totalIPs": str(len([h for h in hosts if h["agent"]])), "completedIPs": str(len([h for h in hosts if h["agent"]])), "importStatus": "Successful", "totalChecks": "212000", "repository": {"id": "2", "name": "Compliance Repository"}},
        {"id": "103", "name": "Firewall discovery", "status": "Completed", "startTime": str(scan_ts - 8 * 3600), "finishTime": str(scan_ts - 7 * 3600), "scannedIPs": "28", "totalIPs": "28", "completedIPs": "28", "importStatus": "Successful", "totalChecks": "1200", "repository": {"id": "1", "name": "Vulnerability Repository"}},
        {"id": "97", "name": "Weekly VA - all servers", "status": "Completed", "startTime": str(scan_ts - 7 * DAY - 7 * 3600), "finishTime": str(scan_ts - 7 * DAY - 2 * 3600), "scannedIPs": str(len(hosts) - 2), "totalIPs": str(len(hosts)), "completedIPs": str(len(hosts) - 2), "importStatus": "Successful", "totalChecks": "188000", "repository": {"id": "1", "name": "Vulnerability Repository"}},
    ]
    return {"hosts": hosts, "repositories": repos, "records": records, "accept_rules": rules_accept, "recast_rules": rules_recast, "scans": scans, "scan_ts": scan_ts,
            "system": {"version": "6.9.0", "buildID": "20261001", "licenseStatus": "Valid", "releaseID": "202610011200", "uuid": "11111111-2222-3333-4444-555555555555"},
            "user": {"id": "3", "username": "studio.api", "firstname": "Studio", "lastname": "Connector", "role": {"id": "2", "name": "Security Manager"}, "organization": {"id": "1", "name": "ALTANFEETHI"}}}


def _applies(p, h) -> bool:
    name = p[1]
    if "Ubuntu" in h["os"]:
        return "Ubuntu" in name or "OpenSSH" in name or "Java" in name
    if "Windows 10" in h["os"]:
        return "Windows 10" in name or "Edge" in name or "Adobe" in name or "Java" in name or ".NET" in name
    if "2012" in h["os"]:
        return "2012" in name or "Edge" in name or ".NET" in name
    return "Windows 10" not in name and "Ubuntu" not in name and "2012" not in name and "OpenSSH" not in name


def dataset_counts(data: dict, inventory_plugins: tuple = tuple(INVENTORY)) -> dict:
    """What a correct pull must produce from this dataset: duplicates by plugin/host/port/protocol/
    repository removed, and of the Info rows only the inventory plugins (the pull asks for
    severities Critical to Low plus those plugins, like the recommended UI export)."""
    seen = set()
    va = cmp = 0
    va_hosts, cmp_hosts = set(), set()
    sev: dict[str, int] = {}
    for r in data["records"]:
        if r["family"]["type"] != "compliance" and r["severity"]["name"] == "Info" and int(r["pluginID"]) not in inventory_plugins:
            continue
        key = (r["pluginID"], r["ip"], r["port"], r["protocol"], r["repository"]["id"])
        if key in seen:
            continue
        seen.add(key)
        if r["family"]["type"] == "compliance":
            cmp += 1
            cmp_hosts.add(r["ip"])
        else:
            va += 1
            va_hosts.add(r["ip"])
            sev[r["severity"]["name"]] = sev.get(r["severity"]["name"], 0) + 1
    return {"va_rows": va, "cmp_rows": cmp, "va_hosts": len(va_hosts), "cmp_hosts": len(cmp_hosts), "severity": sev, "records": len(data["records"]), "duplicates": len(data["records"]) - len(seen)}
