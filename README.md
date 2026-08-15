# Penetration Testing & Vulnerability Assessment Report
**Engagement Standard:** Penetration Testing Execution Standard (PTES)  
**Target Scope:** `192.168.56.0/24` (Authorized Lab Network)  
**Author:** Irfan Musthafa  
**Engagement Type:** Infrastructure Reconnaissance & Vulnerability Assessment  

---

## Lab Architecture & Environment Setup

| Hostname | Assigned IP | Role / Operating System | Details |
| :--- | :--- | :--- | :--- |
| `kali-sec-node` | `192.168.56.10` | Kali Linux 2024.x | Security assessment scanning workstation |
| `ns1.lab.local` | `192.168.56.20` | Ubuntu Server 22.04 (BIND9) | Authoritative DNS server for `lab.local` |
| `vuln-target01` | `192.168.56.30` | Metasploitable 2 (Linux 2.6.x) | Intentionally vulnerable multi-service target |

---

## 1. Executive Summary
A comprehensive, non-intrusive network reconnaissance and automated vulnerability assessment was conducted against the authorized laboratory scope `192.168.56.0/24`. The assessment identified severe configuration and software weaknesses, most notably unauthenticated remote code execution vulnerabilities in legacy background daemons and unrestricted DNS zone transfer permissions. Remediation requires immediate retirement of legacy services, implementation of firewall perimeter rules, and enforcement of least-privilege service configurations.

---

## 2. Scope & Rules of Engagement (RoE)

### A. Target Scope
* **Target Network:** `192.168.56.0/24` (Subnet: `255.255.255.0`)
* **Explicit Exclusions:** Network gateway (`192.168.56.1`), broadcast addresses, host OS interfaces, and all external production systems.

### B. In-Scope Activities
* Passive OSINT reconnaissance (demonstrated on non-target public assets)
* Active ICMP/ARP host discovery and network mapping
* TCP SYN half-open port scanning (ports 1–1024)
* Service banner grabbing and version detection (`-sV`)
* Operating system fingerprinting (`-O`)
* Local authoritative DNS enumeration and AXFR zone transfer validation
* Automated vulnerability scanning using Nessus/OpenVAS

### C. Out-of-Scope Activities
* Exploitation, payload delivery, or remote code execution attempts
* Post-exploitation, privilege escalation, or lateral movement
* Denial of Service (DoS / DDoS) testing or buffer stress testing
* Social engineering, phishing, or physical security assessments

### D. Rules of Engagement & Operational Controls
* **Authorized Testing Window:** 09:00 – 18:00 IST (Monday through Friday).
* **Network Rate Limiting:** All active scanning throttled to a maximum rate of 300 packets per second (`--max-rate 300`) to avoid network disruption.
* **Emergency Point of Contact:** `security-ops@campus.internal` / Lead Security Administrator.
* **Incident Protocol:** If any service becomes unstable or unresponsive, scanning stops immediately and timestamps are recorded for review.

---

## 3. Methodology (PTES Phase Mapping)

| PTES Phase | Technical Execution in This Engagement |
| :--- | :--- |
| **1. Pre-Engagement** | Defining boundaries, establishing Rules of Engagement, and configuring lab targets. |
| **2. Intelligence Gathering** | Passive OSINT verification, public Shodan reconnaissance, and passive DNS mapping. |
| **3. Threat Modeling & Discovery** | Nmap ARP/ICMP ping sweep (`-sn`), TCP SYN scan (`-sS`), and service fingerprinting (`-sV`). |
| **4. Vulnerability Analysis** | Local DNS zone enumeration (`dig`, AXFR) and Nessus automated vulnerability scanning. |
| **5. Reporting & Post-Assessment** | CVSS v3.1 calculation, textual risk heat mapping, and prioritized remediation roadmap. |

---

## 4. Technical Reconnaissance & Enumeration Findings

### Task 2: Passive OSINT Demonstration
Because private RFC 1918 address space (`192.168.56.0/24`) is not indexed on public discovery platforms, OSINT techniques were demonstrated against public infrastructure to validate methodology and risk classification.

| Query / Source | Discovered Information | Sensitivity Classification | Attacker Inference & Risk |
| :--- | :--- | :--- | :--- |
| `dig example.com ANY` | `A`, `MX`, `NS`, `TXT` records | **Low Risk** | Reveals mail routing topology and hosting providers passively without contacting target hosts. |
| `dig _dmarc.example.com TXT` | `v=DMARC1; p=none;` | **Medium Risk** | Indicates no email quarantine/rejection policy is enforced, allowing domain email spoofing. |
| `shodan search "port:22 product:OpenSSH"` | Global banner distribution | **High Risk** | Enables mass filtering of unpatched OpenSSH versions susceptible to known CVEs. |

---

### Task 3: Active Host Discovery (Ping Sweep)
* **Command:** `nmap -sn -PR 192.168.56.0/24 -oN outputs/02_nmap_ping_sweep.txt`
  * `-sn`: Disables port scanning to purely identify live hosts quickly.
  * `-PR`: Uses ARP requests on local Ethernet subnets, bypassing host-level software firewalls.
  * `-oN`: Exports output to a human-readable text file for audit logging.

* **Discovered Live Hosts:**
  * `192.168.56.10` — Kali Security Workstation (`kali-sec-node`)
  * `192.168.56.20` — DNS Name Server (`ns1.lab.local`)
  * `192.168.56.30` — Vulnerable Application Target (`vuln-target01`)

* **PTES Intelligence Gathering Rationale:** Performing host discovery prior to port scanning minimizes network noise, avoids triggering defensive IDS thresholds across empty IP space, and focuses port enumeration strictly on active targets.

---

### Task 4: Port Scanning, Service Identification & OS Fingerprinting

#### A. TCP SYN Scan vs. TCP Connect Scan (Packet-Level Comparison)
* **Command Executed:** `nmap -sS -p 1-1024 192.168.56.30 -oN outputs/03_nmap_syn_ports.txt`
* **Packet-Level Mechanism:**
  * **TCP Connect Scan (`-sT`):** Completes the standard 3-way handshake (`SYN` $\rightarrow$ `SYN/ACK` $\rightarrow$ `ACK`). The operating system kernel establishes an active socket connection, triggering an application-level event log (e.g., in web or FTP access logs).
  * **TCP SYN Scan (`-sS`):** Operates as a half-open scan. The scanner sends a `SYN` packet; when the target responds with `SYN/ACK`, the scanner immediately returns an `RST` (Reset) packet instead of completing the handshake with an `ACK`. The connection is torn down before the application layer records an established session, making it stealthier.

#### B. Service & OS Enumeration Table (Target: `192.168.56.30`)
* **OS Fingerprint:** Linux 2.6.9 - 2.6.33 (Kernel confidence: 96%)

| Host | Port | State | Service | Software Version | Operating System |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `192.168.56.30` | `21/tcp` | Open | FTP | vsftpd 2.3.4 | Linux 2.6.x |
| `192.168.56.30` | `22/tcp` | Open | SSH | OpenSSH 4.7p1 Debian 8ubuntu1 | Linux 2.6.x |
| `192.168.56.30` | `53/tcp` | Open | Domain | ISC BIND 9.4.2 | Linux 2.6.x |
| `192.168.56.30` | `80/tcp` | Open | HTTP | Apache httpd 2.2.8 ((Ubuntu) DAV/2) | Linux 2.6.x |
| `192.168.56.30` | `445/tcp` | Open | NetBIOS-SSN | Samba smbd 3.X - 4.X | Linux 2.6.x |
| `192.168.56.30` | `3632/tcp`| Open | Distcc | distccd v1 (format V1 backend) | Linux 2.6.x |

---

### Task 5: DNS Enumeration & Zone Transfer Security

#### A. Record Query Output
* **Command:** `dig @192.168.56.20 lab.local ANY +noall +answer`
```text
lab.local.        86400  IN  SOA   ns1.lab.local. admin.lab.local. 2026081501 28800 7200 604800 86400
lab.local.        86400  IN  NS    ns1.lab.local.
lab.local.        86400  IN  A     192.168.56.30
lab.local.        86400  IN  MX    10 mail.lab.local.
lab.local.        86400  IN  TXT   "v=spf1 mx -all"
portal.lab.local. 86400  IN  CNAME app.lab.local.
