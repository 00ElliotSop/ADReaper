<div align="center">

```
  █████╗ ██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
 ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
 ███████║██║  ██║██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
 ██╔══██║██║  ██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
 ██║  ██║██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
 ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

**ADReaper v1.0** — Active Directory Enumeration & Attack Path Mapper

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-ElliotSop-black?style=flat-square)](https://elliotsop.com)
[![OSCP](https://img.shields.io/badge/OSCP-Certified-orange?style=flat-square)](https://elliotsop.com)

*LDAP-native AD enumeration that maps users, groups, computers, GPOs, and delegation chains — then surfaces every viable attack path in a single pass.*

[elliotsop.com](https://elliotsop.com) · [GitHub](https://github.com/00ElliotSop) · [LinkedIn](https://linkedin.com/in/padeshina)

</div>

---

## Overview

ADReaper performs **comprehensive Active Directory enumeration over LDAP** and automatically identifies attack paths from the collected data. One authenticated (or null session) bind surfaces Kerberoastable accounts, AS-REP roastable targets, unconstrained/constrained delegation chains, privileged group membership, domain policy weaknesses, and passwords hiding in description fields.

Output is a colour-coded terminal table for live ops, a structured JSON file for toolchain integration, and a Markdown report ready for client deliverables.

---

## Features

- **LDAP enumeration** — NTLM or simple bind, null session, LDAPS support
- **Full user attribute extraction** — UAC flags, SPNs, adminCount, pwdLastSet, lastLogon, group membership, description, mail
- **UAC flag decoder** — surfaces every relevant flag including `DONT_REQ_PREAUTH`, `TRUSTED_FOR_DELEGATION`, `TRUSTED_TO_AUTH_FOR_DELEGATION`, `DONT_EXPIRE_PASSWORD`, `PASSWD_NOTREQD`
- **Group enumeration** — members, adminCount, high-value group identification
- **Computer enumeration** — OS, last logon, SPNs, delegation flags
- **GPO enumeration** — all Group Policy Objects with UNC paths
- **Domain policy** — machine account quota, password policy, lockout thresholds
- **Attack path analyzer** — automatic identification of:
  - Kerberoastable accounts (admin accounts sorted first)
  - AS-REP roastable accounts
  - Unconstrained delegation (users and non-DC computers separately)
  - Constrained delegation
  - Privileged group membership (DA, EA, Schema Admins, DNSAdmins, etc.)
  - Passwords/credentials in description fields
- **Three output formats** — terminal (live ops), JSON (toolchain), Markdown (client report)

---

## Installation

```bash
git clone https://github.com/00ElliotSop/ADReaper
cd ADReaper
pip install -r requirements.txt
```

**requirements.txt**
```
ldap3
colorama
```

---

## Usage

### Standard authenticated bind (NTLM)
```bash
python3 adreaper.py \
  --dc 192.168.1.10 \
  --domain corp.local \
  -u analyst \
  -p 'P@ssw0rd'
```

### Null/anonymous session attempt
```bash
python3 adreaper.py \
  --dc 10.10.10.5 \
  --domain corp.local \
  --null-session
```

### Simple bind (UPN format)
```bash
python3 adreaper.py \
  --dc 10.10.10.5 \
  --domain corp.local \
  -u analyst@corp.local \
  -p 'P@ssw0rd' \
  --simple-bind
```

### LDAPS (port 636)
```bash
python3 adreaper.py \
  --dc 10.10.10.5 \
  --domain corp.local \
  -u analyst \
  -p 'P@ssw0rd' \
  --ssl
```

### Include disabled accounts + custom output base name
```bash
python3 adreaper.py \
  --dc 10.10.10.5 \
  --domain corp.local \
  -u analyst \
  -p 'P@ssw0rd' \
  --enum-all \
  --output /tmp/engagement_corp
```
> Creates `engagement_corp.json` and `engagement_corp.md`

---

## Options

| Flag | Description |
|------|-------------|
| `--dc` | Domain Controller IP or hostname (required) |
| `--domain` | Domain FQDN, e.g. `corp.local` (required) |
| `-u`, `--user` | Username. Leave blank or omit for null session. |
| `-p`, `--pass` | Password |
| `--null-session` | Force anonymous/null bind |
| `--simple-bind` | Use simple bind (LDAP SIMPLE) instead of NTLM |
| `--ssl` | Connect via LDAPS on port 636 |
| `--enum-all` | Include disabled accounts in terminal output |
| `-o`, `--output` | Output base path (default: `adreaper_report`) |

---

## Attack Path Coverage

| Attack | Detection Logic |
|--------|----------------|
| **Kerberoasting** | Users with `servicePrincipalName` set and account not disabled. Admin accounts sorted first. |
| **AS-REP Roasting** | Users with `DONT_REQ_PREAUTH` UAC flag and account not disabled. |
| **Unconstrained Delegation (Users)** | `TRUSTED_FOR_DELEGATION` UAC flag on user objects. |
| **Unconstrained Delegation (Computers)** | `TRUSTED_FOR_DELEGATION` on non-Domain-Controller computer objects. |
| **Constrained Delegation** | `TRUSTED_TO_AUTH_FOR_DELEGATION` — surfaces S4U2Proxy attack candidates. |
| **Privileged Group Membership** | Members of DA, EA, Schema Admins, Account Operators, Backup Operators, DNSAdmins, Print Operators, Server Operators, GPCO. |
| **Credentials in Description** | User descriptions containing `password`, `pwd`, `pass`, `cred`, `temp`. |

---

## Sample Terminal Output

```
  ══════════════════════════════════════════════════════════
    USER ACCOUNTS (48 total)
  ══════════════════════════════════════════════════════════

  SAM                       ADMIN  KERB   ASREP  DELEG  PWD_SET
  ───────────────────────── ────── ────── ────── ────── ──────────────────────
  svc_mssql                 YES    YES    no     no     2024-01-15 08:00:00
  svc_backup                YES    YES    no     CON    2023-11-02 09:14:32
  john.smith                no     no     YES    no     2025-03-10 11:22:01
  jane.doe                  no     no     no     UNC    2024-07-04 15:30:45

  ══════════════════════════════════════════════════════════
    ATTACK PATH ANALYSIS
  ══════════════════════════════════════════════════════════

  [!!] Kerberoastable Accounts (3)
      → svc_mssql    MSSQLSvc/db01.corp.local:1433
      → svc_backup   BackupSvc/backup01.corp.local
      → web_svc      HTTP/web01.corp.local

  [!!] AS-REP Roastable Accounts (2)
      → john.smith
      → guest_lab

  [!!] Unconstrained Delegation (Computers) (1)
      → WEB01

  [!!] Passwords in Description (1)
      → helpdesk    "Temp password: Welcome2024!"
```

---

## Report Outputs

### JSON (`adreaper_report.json`)
Full structured data across all enumerated objects — users, groups, computers, GPOs, domain policy, and attack paths. Designed for integration with BloodHound custom queries, reporting pipelines, and toolchain automation.

### Markdown (`adreaper_report.md`)
Professional formatted report with tables for users, computers, GPOs, and an attack path summary section. Drop directly into a pentest report template or push to a private engagement wiki.

---

## Combining with BloodHound

ADReaper complements BloodHound — use ADReaper for rapid LDAP triage and targeted attack path identification, then run SharpHound/BloodHound for full graph-based path analysis on complex environments.

```bash
# Typical workflow
python3 adreaper.py --dc 10.10.10.5 --domain corp.local -u lowpriv -p 'Pass123'
# Review attack paths, identify Kerberoastable targets
# Proceed with targeted Rubeus / Impacket follow-up
```

---

## Legal

> **For authorised penetration testing engagements only.**  
> Querying Active Directory without explicit written permission is illegal.  
> ElliotSop Security LLC accepts no liability for misuse.

---

## Author

**Prince Adeshina** — OSCP · CRTP  
[elliotsop.com](https://elliotsop.com) · [contact@elliotsop.com](mailto:contact@elliotsop.com)  
ElliotSop Security LLC
