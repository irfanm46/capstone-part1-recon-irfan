# Penetration Testing & Vulnerability Assessment Report

**Engagement Standard:** PTES (Penetration Testing Execution Standard)  
**Target Scope:** `192.168.56.0/24`  
**Assessor:** Irfan Musthafa  

---

## Lab Architecture

| Hostname | IP Address | OS / Role | Notes |
| :--- | :--- | :--- | :--- |
| `kali-sec-node` | `192.168.56.10` | Kali Linux 2024.x | Assessment Workstation |
| `ns1.lab.local` | `192.168.56.20` | Ubuntu Server (BIND9) | Authoritative DNS Server |
| `vuln-target01` | `192.168.56.30` | Metasploitable 2 (Linux 2.6.x) | Vulnerable Target Host |

---

## 1. Executive Summary
A non-intrusive network vulnerability assessment was conducted on `192.168.56.0/24`. Critical vulnerabilities were identified, including unauthenticated remote code execution backdoors and unrestricted DNS zone transfers. Immediate remediation focuses on patching legacy services and enforcing access control lists.

---

## 2. Scope & Rules of Engagement

* **Target Range:** `192.168.56.0/24` (Subnet mask `255.255.255.0`).
* **In-Scope:** Passive OSINT, ICMP/ARP host discovery, TCP SYN scanning (ports 1–1024), service/OS detection, DNS enumeration, and automated vulnerability scanning.
* **Out-of-Scope:** Active exploitation, payload execution, DoS/DDoS, social engineering, and out-of-subnet IP addresses.
* **Operational Rules:** Testing hours 09:00–18:00 IST; rate limit capped at 300 pps (`--max-rate 300`); emergency point of contact: `security-ops@campus.internal`.

---

## 3. Methodology (PTES Mapping)

* **Pre-Engagement:** Scope validation, target network verification, and Rules of Engagement agreement.
* **Intelligence Gathering:** Passive DNS/Shodan queries, host discovery, and port enumeration.
* **Vulnerability Analysis:** Service fingerprinting, DNS zone transfer audit, and automated Nessus scanning.
* **Reporting:** Risk quantification using CVSS v3.1 and prioritized remediation planning.

---

## 4. Technical Reconnaissance & Enumeration

### Passive OSINT Demonstration

| Target / Query | Data Identified | Risk Level | Attacker Inference |
| :--- | :--- | :--- | :--- |
| `dig example.com ANY` | `A`, `MX`, `NS`, `TXT` | **Low** | Maps perimeter routing and mail infrastructure. |
| `dig _dmarc.example.com TXT` | `v=DMARC1; p=none;` | **Medium** | Lacks mail rejection policy; vulnerable to email spoofing. |
| `shodan search "port:22 product:OpenSSH"` | OpenSSH 8.2p1 banners | **High** | Identifies unpatched server builds remotely. |

### Active Host Discovery
* **Command:** `nmap -sn -PR 192.168.56.0/24 -oN outputs/02_nmap_ping_sweep.txt`
  * `-sn`: Host discovery only (no port scan).
  * `-PR`: Uses ARP requests for fast, firewall-resilient local discovery.
  * `-oN`: Saves standard text output to file.
* **Discovered Hosts:** `192.168.56.10` (Kali), `192.168.56.20` (DNS), `192.168.56.30` (Target).
* **Rationale:** Performing discovery first prevents scanning inactive IPs, minimizing detection and network latency.

### Port Scanning & Service Enumeration
* **Command:** `nmap -sS -sV -O -p 1-1024 192.168.56.30 -oN outputs/03_nmap_syn_ports.txt`
* **SYN vs. Connect Scan:** A TCP Connect scan (`-sT`) completes the 3-way handshake (`SYN` $\rightarrow$ `SYN/ACK` $\rightarrow$ `ACK`), creating an established OS socket that triggers application logs. A TCP SYN scan (`-sS`) sends `RST` immediately upon receiving `SYN/ACK`, tearing down the connection before it can be logged by the application layer.

| Host | Port | State | Service | Software Version | Operating System |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `192.168.56.30` | `21/tcp` | Open | FTP | vsftpd 2.3.4 | Linux 2.6.x |
| `192.168.56.30` | `22/tcp` | Open | SSH | OpenSSH 4.7p1 | Linux 2.6.x |
| `192.168.56.30` | `53/tcp` | Open | DNS | ISC BIND 9.4.2 | Linux 2.6.x |
| `192.168.56.30` | `80/tcp` | Open | HTTP | Apache httpd 2.2.8 | Linux 2.6.x |
| `192.168.56.30` | `445/tcp` | Open | SMB | Samba 3.X - 4.X | Linux 2.6.x |
| `192.168.56.30` | `3632/tcp`| Open | Distcc | distccd v1 | Linux 2.6.x |

### DNS Enumeration & Zone Transfer
* **Record Query:** `dig @192.168.56.20 lab.local ANY +noall +answer`
  * Successfully retrieved `A`, `NS`, `SOA`, `MX`, `TXT`, and `CNAME` records.
* **Zone Transfer Test:** `dig axfr @192.168.56.20 lab.local`
  * **Result:** **Success (AXFR Allowed).** Unrestricted zone transfers expose internal domain topology and unlinked hosts.
* **Reverse Lookup:** `dig -x 192.168.56.30 @192.168.56.20 +short` $\rightarrow$ `vuln-target01.lab.local.`

---

## 5. Vulnerability Assessment Findings

| ID | Vulnerability | CVE / Ref | CVSS v3.1 | Severity | Asset & Port |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **V-01** | vsftpd 2.3.4 Backdoor RCE | `CVE-2011-2523` | **9.8** | 🔴 Critical | `192.168.56.30:21` |
| **V-02** | Distcc Daemon Remote Command Execution | `CVE-2004-2687` | **9.8** | 🔴 Critical | `192.168.56.30:3632` |
| **V-03** | Apache HTTP Slowloris Denial of Service | `CVE-2007-6750` | **7.5** | 🟠 High | `192.168.56.30:80` |
| **V-04** | Unrestricted DNS Zone Transfer (AXFR) | CWE-200 | **5.3** | 🟡 Medium | `192.168.56.20:53` |

### Technical Details & Remediation

* **V-01 (vsftpd 2.3.4 RCE):** Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Contains a hardcoded backdoor triggered on authentication.  
  * *Fix:* Upgrade package to `vsftpd 3.0.5+` or replace with SFTP.
* **V-02 (Distcc RCE):** Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Allows unauthenticated remote command execution.  
  * *Fix:* Implement compiler IP whitelisting (`--allow`) or disable the service.
* **V-03 (Apache Slowloris DoS):** Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. Exploits lack of timeout limits on partial headers.  
  * *Fix:* Upgrade to Apache 2.4.x and enable `mod_reqtimeout`.
* **V-04 (DNS Zone Transfer):** Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`. Permits unauthorized zone replication.  
  * *Fix:* Add `allow-transfer { none; };` inside BIND9 `named.conf.local`.

### False Positive Analysis
* **Finding:** OpenSSH 4.7p1 Command Injection (`CVE-2020-15778`).
* **Evaluation:** **False Positive.** The target restricts SSH to key authentication without automated `scp` command execution pipelines. The banner-based detection does not translate into real-world exploitability in this environment.

---

## 6. Textual Risk Heat Map (Likelihood × Impact)

```text
  HIGH IMPACT        │ [V-03] Slowloris DoS    │ [V-01] vsftpd Backdoor
                     │                         │ [V-02] Distcc RCE
  ───────────────────┼─────────────────────────┼────────────────────────────
  LOW / MED IMPACT   │                         │ [V-04] DNS Zone Transfer
                     │                         │
  ───────────────────┴─────────────────────────┴────────────────────────────
                       LOW / MEDIUM LIKELIHOOD   HIGH LIKELIHOOD
```

## 7. Remediation Priority List

* **Priority 1 (CVSS 9.8 - Critical):** Upgrade vsftpd on `192.168.56.30:21`.
* **Priority 2 (CVSS 9.8 - Critical):** Restrict or disable Distcc daemon on `192.168.56.30:3632`.
* **Priority 3 (CVSS 7.5 - High):** Configure `mod_reqtimeout` on Apache HTTP (`192.168.56.30:80`).
* **Priority 4 (CVSS 5.3 - Medium):** Restrict DNS Zone Transfers on `192.168.56.20:53`.

                       
