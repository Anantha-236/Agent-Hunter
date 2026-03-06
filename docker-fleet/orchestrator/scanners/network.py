"""
Network Scanner — Nmap
Covers: open ports, service versions, OS detection, known vuln scripts
"""

import asyncio
import xml.etree.ElementTree as ET
from urllib.parse import urlparse


DANGEROUS_SERVICES = {
    "ftp":      ("MEDIUM", "FTP transmits credentials in plaintext"),
    "telnet":   ("HIGH",   "Telnet is unencrypted — replace with SSH"),
    "rsh":      ("CRITICAL", "RSH allows unauthenticated remote shell"),
    "rlogin":   ("CRITICAL", "rlogin is unauthenticated"),
    "tftp":     ("HIGH",   "TFTP has no authentication"),
    "finger":   ("MEDIUM", "finger leaks user information"),
    "chargen":  ("MEDIUM", "chargen can be used in amplification attacks"),
    "daytime":  ("LOW",    "Unnecessary service exposure"),
    "time":     ("LOW",    "Unnecessary service exposure"),
    "ms-sql-s": ("HIGH",   "MSSQL exposed — check auth"),
    "mysql":    ("HIGH",   "MySQL exposed — verify auth is required"),
    "redis":    ("HIGH",   "Redis exposed — often unauthenticated"),
    "mongodb":  ("HIGH",   "MongoDB exposed — check auth"),
    "vnc":      ("HIGH",   "VNC exposed — verify password strength"),
    "rdp":      ("MEDIUM", "RDP exposed — BlueKeep and other CVEs apply"),
}

DEPTH_NMAP_FLAGS = {
    "light":  ["-T3", "-F",           "--open"],
    "medium": ["-T4", "-sV", "-sC",   "--open", "-O"],
    "deep":   ["-T4", "-sV", "-sC",   "--open", "-O", "-A",
               "--script=vuln,exploit,auth,default"],
}


def parse_nmap_xml(xml_str: str, base_url: str) -> list[dict]:
    findings = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        addr_el = host.find("address")
        host_ip = addr_el.get("addr", base_url) if addr_el is not None else base_url

        for port_el in host.findall(".//port"):
            port_num = port_el.get("portid", "?")
            protocol = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            svc_el   = port_el.find("service")
            svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            svc_prod = svc_el.get("product", "")      if svc_el is not None else ""
            svc_ver  = svc_el.get("version", "")       if svc_el is not None else ""

            sev, reason = DANGEROUS_SERVICES.get(svc_name, ("LOW", "Open port detected"))

            findings.append({
                "id":          f"net-{len(findings)+1}",
                "type":        f"Open Port — {svc_name.upper()}",
                "severity":    sev,
                "category":    "network",
                "location":    f"{host_ip}:{port_num}/{protocol}",
                "description": f"{reason}. Service: {svc_prod} {svc_ver}".strip(),
                "remediation": "Firewall this port if not required. Ensure latest patches applied.",
                "cve":         None,
                "raw": {"host": host_ip, "port": port_num, "service": svc_name,
                        "product": svc_prod, "version": svc_ver}
            })

            # Script output — vuln scripts embed CVE info
            for script_el in port_el.findall("script"):
                script_id  = script_el.get("id", "")
                script_out = script_el.get("output", "")
                if "VULNERABLE" in script_out or "CVE" in script_out:
                    cve = ""
                    for token in script_out.split():
                        if token.startswith("CVE-"):
                            cve = token.strip("().,")
                            break
                    findings.append({
                        "id":          f"net-{len(findings)+1}",
                        "type":        f"Nmap Script: {script_id}",
                        "severity":    "HIGH",
                        "category":    "network",
                        "location":    f"{host_ip}:{port_num}",
                        "description": script_out[:500],
                        "remediation": "Apply vendor patch for identified CVE immediately.",
                        "cve":         cve or None,
                        "raw":         {"script": script_id, "output": script_out}
                    })

    return findings


async def run_network_scan(url: str, depth: str, auth_cookie: str | None,
                           scan_id: str, log_fn) -> list[dict]:
    parsed = urlparse(url)
    target = parsed.hostname or url

    flags   = DEPTH_NMAP_FLAGS.get(depth, DEPTH_NMAP_FLAGS["medium"])
    xml_out = f"/results/{scan_id}_nmap.xml"

    cmd = ["nmap"] + flags + ["-oX", xml_out, target]
    log_fn("INFO", f"Running: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        if proc.returncode != 0:
            log_fn("ERROR", f"Nmap exited {proc.returncode}: {stderr.decode()[:200]}")
            return []

        log_fn("INFO", "Nmap complete — parsing XML output")

        try:
            with open(xml_out) as f:
                xml_data = f.read()
        except FileNotFoundError:
            xml_data = stdout.decode()

        findings = parse_nmap_xml(xml_data, target)
        log_fn("INFO", f"Network scan done — {len(findings)} findings")
        return findings

    except asyncio.TimeoutError:
        log_fn("ERROR", "Nmap timed out after 5 minutes")
        return []
    except FileNotFoundError:
        log_fn("ERROR", "nmap binary not found in container — is instrumentisto/nmap running?")
        return []
    except Exception as e:
        log_fn("ERROR", f"Network scan error: {e}")
        return []
