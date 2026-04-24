#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       ElliotSop Security — ADReaper v1.0                     ║
║   Active Directory enumeration & attack path mapper          ║
║   OSCP / Red Team Ops toolkit — github.com/00ElliotSop       ║
╚══════════════════════════════════════════════════════════════╝

Maps: Users → Groups → SPNs → Delegations → Attack Paths
Outputs: terminal table, JSON, and Markdown report

Usage:
    python3 adreaper.py --dc 192.168.1.10 --domain corp.local -u analyst -p 'P@ssw0rd'
    python3 adreaper.py --dc 10.10.10.5 --domain corp.local --null-session
    python3 adreaper.py --dc 10.10.10.5 --domain corp.local -u '' -p '' --enum-all

Requires:
    pip install ldap3 colorama impacket

Notes:
    - Run against your authorised lab / engagement targets only.
    - Kerberoast candidates: accounts with SPNs and non-default enctype.
    - AS-REP candidates: accounts with DONT_REQ_PREAUTH set.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SUBTREE, ALL_ATTRIBUTES
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("[!] Missing dependencies. Run: pip install ldap3 colorama")
    sys.exit(1)

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

BANNER = f"""
{Fore.RED}
   █████╗ ██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ███████║██║  ██║██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
  ██╔══██║██║  ██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ██║  ██║██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.WHITE}  ADReaper v1.0 — ElliotSop Security LLC{Style.RESET_ALL}
{Fore.YELLOW}  Active Directory Enumeration & Attack Path Mapper{Style.RESET_ALL}
  {Fore.RED}github.com/00ElliotSop  |  elliotsop.com{Style.RESET_ALL}
  ─────────────────────────────────────────────────────────────
"""

# ─────────────────────────────────────────────
#  UAC FLAG DECODER
# ─────────────────────────────────────────────

UAC_FLAGS = {
    0x0001:   'SCRIPT',
    0x0002:   'ACCOUNTDISABLE',
    0x0008:   'HOMEDIR_REQUIRED',
    0x0010:   'LOCKOUT',
    0x0020:   'PASSWD_NOTREQD',
    0x0040:   'PASSWD_CANT_CHANGE',
    0x0080:   'ENCRYPTED_TEXT_PWD_ALLOWED',
    0x0100:   'TEMP_DUPLICATE_ACCOUNT',
    0x0200:   'NORMAL_ACCOUNT',
    0x0800:   'INTERDOMAIN_TRUST_ACCOUNT',
    0x1000:   'WORKSTATION_TRUST_ACCOUNT',
    0x2000:   'SERVER_TRUST_ACCOUNT',
    0x10000:  'DONT_EXPIRE_PASSWORD',
    0x20000:  'MNS_LOGON_ACCOUNT',
    0x40000:  'SMARTCARD_REQUIRED',
    0x80000:  'TRUSTED_FOR_DELEGATION',
    0x100000: 'NOT_DELEGATED',
    0x200000: 'USE_DES_KEY_ONLY',
    0x400000: 'DONT_REQ_PREAUTH',
    0x800000: 'PASSWORD_EXPIRED',
    0x1000000:'TRUSTED_TO_AUTH_FOR_DELEGATION',
    0x4000000:'PARTIAL_SECRETS_ACCOUNT',
}

def decode_uac(uac_val: int) -> list[str]:
    flags = []
    for bit, name in UAC_FLAGS.items():
        if uac_val & bit:
            flags.append(name)
    return flags

def filetime_to_dt(ft: int) -> str:
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to ISO string."""
    if not ft or ft in (0, 9223372036854775807):
        return 'Never'
    try:
        epoch_delta = 116444736000000000  # 100-ns intervals between epochs
        ts = (ft - epoch_delta) / 10_000_000
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return str(ft)


# ─────────────────────────────────────────────
#  LDAP CONNECTION
# ─────────────────────────────────────────────

def connect_ldap(dc: str, domain: str, username: str, password: str,
                 use_ntlm: bool = True, null_session: bool = False,
                 use_ssl: bool = False) -> Connection:
    port = 636 if use_ssl else 389
    server = Server(dc, port=port, use_ssl=use_ssl, get_info=ALL)

    if null_session or (not username and not password):
        print(f"  {Fore.YELLOW}[*] Attempting null/anonymous session...{Style.RESET_ALL}")
        conn = Connection(server, authentication=ldap3.ANONYMOUS)
    elif use_ntlm:
        user = f"{domain}\\{username}" if '\\' not in username else username
        print(f"  {Fore.YELLOW}[*] Connecting via NTLM as {user}...{Style.RESET_ALL}")
        conn = Connection(server, user=user, password=password, authentication=NTLM)
    else:
        user = f"{username}@{domain}" if '@' not in username else username
        print(f"  {Fore.YELLOW}[*] Connecting via SIMPLE BIND as {user}...{Style.RESET_ALL}")
        conn = Connection(server, user=user, password=password, authentication=SIMPLE)

    if not conn.bind():
        print(f"{Fore.RED}  [!] LDAP bind failed: {conn.result}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"  {Fore.GREEN}[✔] Bound successfully.{Style.RESET_ALL}")
    return conn


def get_base_dn(domain: str) -> str:
    return ','.join(f'DC={part}' for part in domain.split('.'))


# ─────────────────────────────────────────────
#  ENUMERATION MODULES
# ─────────────────────────────────────────────

def enum_domain_info(conn: Connection, base_dn: str) -> dict:
    """Pull root DSE and domain policy basics."""
    info = {}
    conn.search(base_dn,
                '(objectClass=domain)',
                attributes=['ms-DS-MachineAccountQuota', 'minPwdLength',
                            'maxPwdAge', 'lockoutThreshold', 'lockoutDuration',
                            'pwdHistoryLength', 'ms-DS-Password-Complexity-Enabled'])
    if conn.entries:
        e = conn.entries[0]
        info['machine_account_quota'] = str(e['ms-DS-MachineAccountQuota']) if 'ms-DS-MachineAccountQuota' in e else 'N/A'
        info['min_pwd_length']         = str(e['minPwdLength']) if 'minPwdLength' in e else 'N/A'
        info['pwd_history_length']     = str(e['pwdHistoryLength']) if 'pwdHistoryLength' in e else 'N/A'
        info['lockout_threshold']      = str(e['lockoutThreshold']) if 'lockoutThreshold' in e else 'N/A'
    return info


def enum_users(conn: Connection, base_dn: str) -> list[dict]:
    """Enumerate all user accounts with key attributes."""
    users = []
    conn.search(
        base_dn,
        '(&(objectCategory=person)(objectClass=user))',
        search_scope=SUBTREE,
        attributes=[
            'sAMAccountName', 'userPrincipalName', 'displayName',
            'memberOf', 'userAccountControl', 'pwdLastSet',
            'lastLogonTimestamp', 'description', 'mail',
            'servicePrincipalName', 'msDS-SupportedEncryptionTypes',
            'adminCount', 'objectSid', 'distinguishedName'
        ]
    )

    for entry in conn.entries:
        uac = int(str(entry['userAccountControl'])) if entry['userAccountControl'] else 0
        uac_flags = decode_uac(uac)
        spns = [str(s) for s in entry['servicePrincipalName']] if entry['servicePrincipalName'] else []

        pwd_last_set_raw = entry['pwdLastSet'].value
        if isinstance(pwd_last_set_raw, int):
            pwd_last_set = filetime_to_dt(pwd_last_set_raw)
        else:
            pwd_last_set = str(pwd_last_set_raw) if pwd_last_set_raw else 'Never'

        last_logon_raw = entry['lastLogonTimestamp'].value
        if isinstance(last_logon_raw, int):
            last_logon = filetime_to_dt(last_logon_raw)
        else:
            last_logon = str(last_logon_raw) if last_logon_raw else 'Never'

        groups = [str(g).split(',')[0].replace('CN=', '') for g in (entry['memberOf'] or [])]
        admin_count = str(entry['adminCount'].value) if entry['adminCount'] else '0'

        # ── Attack flags ────────────────────────────────────────
        is_kerberoastable = bool(spns) and 'ACCOUNTDISABLE' not in uac_flags
        is_asrep_roastable = 'DONT_REQ_PREAUTH' in uac_flags and 'ACCOUNTDISABLE' not in uac_flags
        is_unconstrained = 'TRUSTED_FOR_DELEGATION' in uac_flags and 'ACCOUNTDISABLE' not in uac_flags
        is_constrained = 'TRUSTED_TO_AUTH_FOR_DELEGATION' in uac_flags
        is_disabled = 'ACCOUNTDISABLE' in uac_flags
        no_expiry = 'DONT_EXPIRE_PASSWORD' in uac_flags
        is_admin = admin_count != '0'

        users.append({
            'sam': str(entry['sAMAccountName']),
            'upn': str(entry['userPrincipalName']) if entry['userPrincipalName'] else '',
            'display_name': str(entry['displayName']) if entry['displayName'] else '',
            'description': str(entry['description']) if entry['description'] else '',
            'mail': str(entry['mail']) if entry['mail'] else '',
            'groups': groups,
            'uac': uac,
            'uac_flags': uac_flags,
            'spns': spns,
            'pwd_last_set': pwd_last_set,
            'last_logon': last_logon,
            'admin_count': admin_count,
            'dn': str(entry['distinguishedName']),
            # Attack path flags
            'kerberoastable': is_kerberoastable,
            'asrep_roastable': is_asrep_roastable,
            'unconstrained_delegation': is_unconstrained,
            'constrained_delegation': is_constrained,
            'disabled': is_disabled,
            'no_expiry': no_expiry,
            'is_admin': is_admin,
        })

    return users


def enum_groups(conn: Connection, base_dn: str) -> list[dict]:
    """Enumerate all groups and their membership."""
    groups = []
    conn.search(
        base_dn,
        '(objectClass=group)',
        search_scope=SUBTREE,
        attributes=['sAMAccountName', 'description', 'member', 'adminCount', 'distinguishedName']
    )
    for entry in conn.entries:
        members = [str(m).split(',')[0].replace('CN=', '') for m in (entry['member'] or [])]
        groups.append({
            'name': str(entry['sAMAccountName']),
            'description': str(entry['description']) if entry['description'] else '',
            'admin_count': str(entry['adminCount'].value) if entry['adminCount'] else '0',
            'member_count': len(members),
            'members': members,
            'dn': str(entry['distinguishedName']),
        })
    return groups


def enum_computers(conn: Connection, base_dn: str) -> list[dict]:
    """Enumerate domain computers."""
    computers = []
    conn.search(
        base_dn,
        '(objectClass=computer)',
        search_scope=SUBTREE,
        attributes=[
            'sAMAccountName', 'operatingSystem', 'operatingSystemVersion',
            'lastLogonTimestamp', 'userAccountControl',
            'servicePrincipalName', 'description', 'distinguishedName'
        ]
    )
    for entry in conn.entries:
        uac = int(str(entry['userAccountControl'])) if entry['userAccountControl'] else 0
        uac_flags = decode_uac(uac)
        spns = [str(s) for s in entry['servicePrincipalName']] if entry['servicePrincipalName'] else []
        last_logon_raw = entry['lastLogonTimestamp'].value
        last_logon = filetime_to_dt(int(last_logon_raw)) if isinstance(last_logon_raw, int) else str(last_logon_raw or 'Never')

        computers.append({
            'name': str(entry['sAMAccountName']).rstrip('$'),
            'os': str(entry['operatingSystem']) if entry['operatingSystem'] else 'Unknown',
            'os_version': str(entry['operatingSystemVersion']) if entry['operatingSystemVersion'] else '',
            'description': str(entry['description']) if entry['description'] else '',
            'last_logon': last_logon,
            'spns': spns,
            'unconstrained_delegation': 'TRUSTED_FOR_DELEGATION' in uac_flags,
            'dn': str(entry['distinguishedName']),
        })
    return computers


def enum_gpos(conn: Connection, base_dn: str) -> list[dict]:
    """Enumerate Group Policy Objects."""
    gpos = []
    conn.search(
        base_dn,
        '(objectClass=groupPolicyContainer)',
        search_scope=SUBTREE,
        attributes=['displayName', 'gPCFileSysPath', 'distinguishedName']
    )
    for entry in conn.entries:
        gpos.append({
            'name': str(entry['displayName']) if entry['displayName'] else '',
            'path': str(entry['gPCFileSysPath']) if entry['gPCFileSysPath'] else '',
            'dn': str(entry['distinguishedName']),
        })
    return gpos


# ─────────────────────────────────────────────
#  ATTACK PATH ANALYZER
# ─────────────────────────────────────────────

HIGH_VALUE_GROUPS = {
    'Domain Admins', 'Enterprise Admins', 'Schema Admins',
    'Administrators', 'Account Operators', 'Backup Operators',
    'Print Operators', 'Server Operators', 'Group Policy Creator Owners',
    'DNSAdmins', 'Remote Desktop Users', 'Remote Management Users',
    'DnsAdmins'
}

def analyze_attack_paths(users: list[dict], computers: list[dict],
                          groups: list[dict]) -> dict:
    """Identify and prioritize attack paths from enumeration data."""
    paths = {
        'kerberoastable':          [],
        'asrep_roastable':         [],
        'unconstrained_users':     [],
        'unconstrained_computers': [],
        'constrained_delegation':  [],
        'privileged_members':      [],
        'high_value_descriptions': [],
        'stale_accounts':          [],
        'no_preauth_accounts':     [],
    }

    for u in users:
        sam = u['sam']
        if u['kerberoastable']:
            paths['kerberoastable'].append({
                'account': sam,
                'spns': u['spns'],
                'groups': u['groups'],
                'is_admin': u['is_admin']
            })
        if u['asrep_roastable']:
            paths['asrep_roastable'].append(sam)
        if u['unconstrained_delegation']:
            paths['unconstrained_users'].append(sam)
        if u['constrained_delegation']:
            paths['constrained_delegation'].append({'account': sam, 'spns': u['spns']})
        if u['is_admin'] and not u['disabled']:
            for g in u['groups']:
                if g in HIGH_VALUE_GROUPS:
                    paths['privileged_members'].append({'account': sam, 'group': g})
        if u['description'] and any(kw in u['description'].lower()
                                     for kw in ['password', 'pwd', 'pass', 'cred', 'temp']):
            paths['high_value_descriptions'].append({'account': sam, 'description': u['description']})

    for c in computers:
        if c['unconstrained_delegation'] and 'Domain Controllers' not in c['dn']:
            paths['unconstrained_computers'].append(c['name'])

    # Sort kerberoastable by admin first
    paths['kerberoastable'].sort(key=lambda x: x['is_admin'], reverse=True)

    return paths


# ─────────────────────────────────────────────
#  OUTPUT / REPORTING
# ─────────────────────────────────────────────

def print_section(title: str):
    print(f"\n  {Fore.RED}{'═' * 60}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  {title}{Style.RESET_ALL}")
    print(f"  {Fore.RED}{'═' * 60}{Style.RESET_ALL}")


def print_attack_summary(paths: dict):
    print_section("ATTACK PATH ANALYSIS")

    def section(label, items, color=Fore.RED):
        if items:
            print(f"\n  {color}[!!] {label} ({len(items)}){Style.RESET_ALL}")
            for item in items[:20]:
                if isinstance(item, dict):
                    acct = item.get('account', '')
                    detail = item.get('spns', item.get('group', item.get('description', '')))
                    if isinstance(detail, list):
                        detail = detail[0] if detail else ''
                    print(f"      {Fore.YELLOW}→ {acct}{Style.RESET_ALL}  {Fore.WHITE}{detail}{Style.RESET_ALL}")
                else:
                    print(f"      {Fore.YELLOW}→ {item}{Style.RESET_ALL}")
            if len(items) > 20:
                print(f"      {Fore.WHITE}... and {len(items) - 20} more{Style.RESET_ALL}")

    section("Kerberoastable Accounts",      paths['kerberoastable'],          Fore.RED)
    section("AS-REP Roastable Accounts",    paths['asrep_roastable'],         Fore.RED)
    section("Unconstrained Delegation (Users)", paths['unconstrained_users'],  Fore.MAGENTA)
    section("Unconstrained Delegation (Computers)", paths['unconstrained_computers'], Fore.MAGENTA)
    section("Constrained Delegation",       paths['constrained_delegation'],   Fore.YELLOW)
    section("Privileged Group Members",     paths['privileged_members'],       Fore.RED)
    section("Passwords in Description",     paths['high_value_descriptions'],  Fore.CYAN)


def print_user_table(users: list[dict], show_all: bool = False):
    print_section(f"USER ACCOUNTS ({len(users)} total)")
    target_users = [u for u in users if not u['disabled']] if not show_all else users

    header = f"  {'SAM':<25} {'ADMIN':<6} {'KERB':<6} {'ASREP':<6} {'DELEG':<6} {'PWD_SET':<22}"
    print(f"\n{Fore.CYAN}{header}{Style.RESET_ALL}")
    print(f"  {'─'*25} {'─'*6} {'─'*6} {'─'*6} {'─'*6} {'─'*22}")

    for u in target_users[:50]:
        admin   = f"{Fore.RED}YES{Style.RESET_ALL}" if u['is_admin'] else f"{Fore.WHITE}no{Style.RESET_ALL}"
        kerb    = f"{Fore.RED}YES{Style.RESET_ALL}" if u['kerberoastable'] else f"{Fore.WHITE}no{Style.RESET_ALL}"
        asrep   = f"{Fore.RED}YES{Style.RESET_ALL}" if u['asrep_roastable'] else f"{Fore.WHITE}no{Style.RESET_ALL}"
        deleg   = f"{Fore.MAGENTA}UNC{Style.RESET_ALL}" if u['unconstrained_delegation'] else \
                  f"{Fore.YELLOW}CON{Style.RESET_ALL}" if u['constrained_delegation'] else \
                  f"{Fore.WHITE}no{Style.RESET_ALL}"
        sam_col = f"{Fore.RED}{u['sam'][:24]:<24}{Style.RESET_ALL}" if u['is_admin'] else f"{u['sam'][:24]:<24}"
        print(f"  {sam_col} {admin:<15} {kerb:<15} {asrep:<15} {deleg:<15} {u['pwd_last_set'][:19]}")

    if len(target_users) > 50:
        print(f"  {Fore.YELLOW}... {len(target_users) - 50} more accounts. See JSON output for full list.{Style.RESET_ALL}")


def write_markdown_report(domain_info: dict, users: list[dict], groups: list[dict],
                           computers: list[dict], gpos: list[dict],
                           attack_paths: dict, filepath: str):
    """Generate a professional Markdown pentest report section."""
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(filepath, 'w') as f:
        f.write(f"# Active Directory Enumeration Report\n\n")
        f.write(f"**Tool:** ElliotSop ADReaper v1.0  \n")
        f.write(f"**Website:** [elliotsop.com](https://elliotsop.com)  \n")
        f.write(f"**GitHub:** [github.com/00ElliotSop](https://github.com/00ElliotSop)  \n")
        f.write(f"**Generated:** {ts}\n\n")
        f.write("---\n\n")

        f.write("## Domain Policy\n\n")
        f.write("| Setting | Value |\n|---|---|\n")
        for k, v in domain_info.items():
            f.write(f"| {k.replace('_', ' ').title()} | {v} |\n")
        f.write("\n")

        f.write("## Attack Path Summary\n\n")
        for path_name, items in attack_paths.items():
            if items:
                label = path_name.replace('_', ' ').title()
                f.write(f"### {label} ({len(items)})\n\n")
                for item in items[:15]:
                    if isinstance(item, dict):
                        f.write(f"- **{item.get('account', '')}**")
                        detail = item.get('spns', item.get('group', item.get('description', '')))
                        if isinstance(detail, list):
                            detail = ', '.join(detail[:2])
                        if detail:
                            f.write(f" — `{detail}`")
                        f.write('\n')
                    else:
                        f.write(f"- `{item}`\n")
                if len(items) > 15:
                    f.write(f"- *...and {len(items) - 15} more*\n")
                f.write('\n')

        f.write("## Users\n\n")
        f.write("| Account | Admin | Kerberoastable | AS-REP | Delegation | Password Set |\n")
        f.write("|---|---|---|---|---|---|\n")
        for u in users[:100]:
            deleg = 'Unconstrained' if u['unconstrained_delegation'] else \
                    'Constrained' if u['constrained_delegation'] else 'None'
            f.write(f"| `{u['sam']}` | {'✓' if u['is_admin'] else ''} | "
                    f"{'✓' if u['kerberoastable'] else ''} | "
                    f"{'✓' if u['asrep_roastable'] else ''} | {deleg} | {u['pwd_last_set'][:10]} |\n")
        f.write('\n')

        f.write("## Computers\n\n")
        f.write("| Host | OS | Unconstrained Delegation | Last Logon |\n|---|---|---|---|\n")
        for c in computers[:50]:
            unc = '⚠️ YES' if c['unconstrained_delegation'] else 'No'
            f.write(f"| `{c['name']}` | {c['os']} | {unc} | {c['last_logon'][:10]} |\n")
        f.write('\n')

        f.write("## Group Policy Objects\n\n")
        f.write("| GPO Name | Path |\n|---|---|\n")
        for g in gpos:
            f.write(f"| {g['name']} | `{g['path']}` |\n")

    print(f"  {Fore.GREEN}[✔] Markdown report written: {filepath}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description='ElliotSop ADReaper — AD Enumeration & Attack Path Mapper',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--dc',           required=True, help='Domain Controller IP or hostname')
    parser.add_argument('--domain',       required=True, help='Domain FQDN e.g. corp.local')
    parser.add_argument('-u', '--user',   default='', help='Username (leave blank for null session)')
    parser.add_argument('-p', '--pass',   dest='password', default='', help='Password')
    parser.add_argument('--null-session', action='store_true', help='Force anonymous/null bind')
    parser.add_argument('--simple-bind',  action='store_true', help='Use simple bind instead of NTLM')
    parser.add_argument('--ssl',          action='store_true', help='Use LDAPS (port 636)')
    parser.add_argument('--enum-all',     action='store_true', help='Include disabled accounts in output')
    parser.add_argument('--output',       '-o', default='adreaper_report',
                        help='Output base name (creates .json and .md files)')
    args = parser.parse_args()

    base_dn = get_base_dn(args.domain)
    print(f"  DC             : {Fore.CYAN}{args.dc}{Style.RESET_ALL}")
    print(f"  Domain         : {Fore.CYAN}{args.domain}{Style.RESET_ALL}")
    print(f"  Base DN        : {Fore.CYAN}{base_dn}{Style.RESET_ALL}")

    conn = connect_ldap(
        dc=args.dc,
        domain=args.domain,
        username=args.user,
        password=args.password,
        use_ntlm=not args.simple_bind,
        null_session=args.null_session,
        use_ssl=args.ssl
    )

    print(f"\n  {Fore.YELLOW}[*] Enumerating domain objects...{Style.RESET_ALL}")
    start = time.time()

    domain_info = enum_domain_info(conn, base_dn)
    print(f"  {Fore.GREEN}[✔] Domain policy collected{Style.RESET_ALL}")

    users = enum_users(conn, base_dn)
    print(f"  {Fore.GREEN}[✔] {len(users)} user accounts enumerated{Style.RESET_ALL}")

    groups = enum_groups(conn, base_dn)
    print(f"  {Fore.GREEN}[✔] {len(groups)} groups enumerated{Style.RESET_ALL}")

    computers = enum_computers(conn, base_dn)
    print(f"  {Fore.GREEN}[✔] {len(computers)} computers enumerated{Style.RESET_ALL}")

    gpos = enum_gpos(conn, base_dn)
    print(f"  {Fore.GREEN}[✔] {len(gpos)} GPOs enumerated{Style.RESET_ALL}")

    elapsed = time.time() - start
    print(f"\n  Enumeration complete in {elapsed:.1f}s")

    attack_paths = analyze_attack_paths(users, computers, groups)

    print_user_table(users, show_all=args.enum_all)
    print_attack_summary(attack_paths)

    # ── Write reports ──────────────────────────────────────────
    json_path = args.output + '.json'
    md_path   = args.output + '.md'

    with open(json_path, 'w') as f:
        json.dump({
            'tool': 'ElliotSop ADReaper v1.0',
            'domain': args.domain, 'dc': args.dc,
            'base_dn': base_dn,
            'generated': datetime.now().isoformat(),
            'domain_info': domain_info,
            'users': users, 'groups': groups,
            'computers': computers, 'gpos': gpos,
            'attack_paths': attack_paths
        }, f, indent=2, default=str)
    print(f"\n  {Fore.GREEN}[✔] JSON report: {json_path}{Style.RESET_ALL}")

    write_markdown_report(domain_info, users, groups, computers, gpos, attack_paths, md_path)

    print(f"\n  {Fore.RED}★ ElliotSop Security | elliotsop.com | github.com/00ElliotSop{Style.RESET_ALL}\n")


if __name__ == '__main__':
    main()
