#!/usr/bin/env bash
# php-patchkit 1.01 - https://github.com/Skittel/php-patchkit
# Read-only inventory for CVE-2026-109618 and CVE-2026-109619.
# Requirements: Linux, root, Plesk, Bash, Python >= 3.6. No network requests.
# Run: bash plesk-php-security-check.sh
# Exit: 0=no version findings, 1=findings/unconfirmed, 2=incomplete audit/error.
set -eu
command -v python3 >/dev/null || { echo 'ERROR: python3 is required.' >&2; exit 2; }
command -v plesk >/dev/null || { echo 'ERROR: plesk was not found.' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: Run this script as root.' >&2; exit 2; }
exec python3 - <<'PY'
import datetime
import io
import os
import re
import shutil
import socket
import subprocess
import sys
from collections import Counter, defaultdict
# Report output must survive any server locale. Handler paths, package names
# and IDN domain names can carry non-ASCII bytes, and on a latin-1 or ascii
# stdout a single one of them would abort the audit with UnicodeEncodeError
# halfway through the report.
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except AttributeError:  # Python 3.6
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8',
                                  errors='replace', line_buffering=True)
FIXES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
SOURCE = 'https://www.php.net/archive/2026.php'
VERSION = '1.01'
errors = []

def run(args, timeout=90):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout,
                           env=dict(os.environ, LC_ALL='C'))
        return p.returncode, p.stdout, p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 2, '', str(e)
def table(headers, rows):
    rows = [[str(x).replace('\n', ' ').replace('\r', ' ').replace('\x1b', '?')
             for x in row] for row in rows]
    if not rows:
        print('(none)')
        return
    widths = [max(len(str(h)), max(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    print('  '.join(str(h).ljust(w) for h, w in zip(headers, widths)))
    print('  '.join('-' * w for w in widths))
    for row in rows:
        print('  '.join(x.ljust(w) for x, w in zip(row, widths)))
def version_status(v):
    # Only stable releases in explicitly documented branches can be confirmed.
    m = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(.*)', v)
    if not m:
        return 'UNKNOWN', 'Unable to determine version'
    major, minor, patch = map(int, m.group(1, 2, 3))
    suffix = m.group(4)
    if re.search(r'(?:RC|alpha|beta|dev)', suffix, re.I):
        return 'UNKNOWN', 'Pre-release; manual verification required'
    if (major, minor) in FIXES:
        minimum = FIXES[(major, minor)]
        if patch >= minimum:
            return 'PATCHED', 'Installed version includes the upstream fixes'
        return 'BELOW FIX / CHECK BACKPORT', 'Vendor backport possible; verify with vendor advisory'
    if (major, minor) <= (8, 1):
        return 'OLD / CHECK BACKPORT', 'EOL branch; verify backports for both CVEs'
    return 'UNKNOWN', 'Branch not covered by this version matrix'
print('Plesk PHP Security Check {} - read-only'.format(VERSION))
print('Host: {} | Checked at: {}'.format(socket.getfqdn(), datetime.datetime.now().astimezone().isoformat()))
print('CVE-2026-109618 / CVE-2026-109619 | Reference: ' + SOURCE)
print('Fixed upstream versions: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (2026-10-21)')
print('Checks installed handler binaries for both Apache- and nginx-served Plesk websites; does not run exploits.\n')
rc, raw, err = run(['plesk', 'bin', 'php_handler', '--list'])
if rc:
    print('ERROR reading PHP handlers: ' + err)
    sys.exit(2)
# Plesk table: id, display name, full version, version, type, cgi-bin,
# php-cli, php.ini, custom, status. Display names may contain spaces.
pattern = re.compile(r'^\s*(\S+)\s+(.+?)\s+(\d+\.\d+\.\d+\S*)\s+'
                     r'(\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$')
handlers = {}
for line in raw.splitlines():
    if not line.strip() or ('id:' in line and 'version:' in line):
        continue
    m = pattern.match(line)
    if not m:
        errors.append('Unable to parse PHP handler entry: ' + line.strip())
        continue
    hid, name, registered, branch, kind, binary, cli, ini, custom, enabled = m.groups()
    actual = '?'
    evidence = 'No readable handler binary'
    if os.path.isfile(binary) and os.access(binary, os.X_OK) and '.so' not in os.path.basename(binary):
        rc, out, err = run([binary, '-n', '-v'], timeout=15)
        vm = re.search(r'^PHP\s+(\d+\.\d+\.\d+\S*)', out, re.M)
        if rc == 0 and vm:
            actual = vm.group(1)
            evidence = 'Handler binary -n -v'
        else:
            errors.append('{}: Unable to read binary version: {}'.format(hid, err or out[:150]))
    status, reason = version_status(actual)
    handlers[hid] = dict(id=hid, name=name, registered=registered, actual=actual,
                         kind=kind, binary=binary, cli=cli, enabled=enabled,
                         status=status, reason=reason, evidence=evidence)
if not handlers:
    print(raw)
    print('ERROR: No readable handlers. No all-clear can be given.')
    sys.exit(2)
# Plesk subscription root is domains.webspace_id, or the domain itself for roots.
# All PHP-enabled physical hosting entries, including suspended domains, count.
sql = """SELECT COALESCE(s.name,d.name),d.name,h.php_handler_id,
COALESCE(u.login,'?'),d.status
FROM domains d JOIN hosting h ON h.dom_id=d.id
LEFT JOIN domains s ON s.id=NULLIF(d.webspace_id,0)
LEFT JOIN sys_users u ON u.id=h.sys_user_id
WHERE h.php='true' ORDER BY 1,2"""
rc, out, err = run(['plesk', 'db', '-N', '-B', '-e', sql])
if rc:
    print('ERROR reading domain/subscription assignments: ' + err)
    sys.exit(2)
sites = []
usage = defaultdict(list)
for line in out.splitlines():
    fields = line.split('\t')
    if len(fields) != 5:
        errors.append('Unable to parse database row: ' + line)
        continue
    sub, domain, hid, user, state = fields
    row = dict(sub=sub, domain=domain, hid=hid, user=user, state=state)
    sites.append(row)
    usage[hid].append(row)
print('1. ALL REGISTERED PHP HANDLERS')
table(['Handler', 'Plesk', 'Binary', 'Enabled', 'Websites', 'Status'],
      [(h['id'], h['registered'], h['actual'], h['enabled'], len(usage[h['id']]), h['status'])
       for h in sorted(handlers.values(), key=lambda h: h['id'])])
print('\nPATCHED = installed handler binary meets the upstream fixed version.')
print('BELOW FIX / OLD = not confirmed patched; vendor backports may retain older version numbers.')
print('Disabled handlers are also checked. PHP-disabled websites are excluded from usage counts.\n')
print('2. WEBSITES AND SUBSCRIPTIONS WITHOUT A CONFIRMED FIX (INCLUDING SUSPENDED)')
affected = [s for s in sites if handlers.get(s['hid'], {}).get('status') != 'PATCHED']
table(['Subscription', 'Website', 'System user', 'Handler', 'Status', 'Domain state'],
      [(s['sub'], s['domain'], s['user'], s['hid'],
        handlers.get(s['hid'], {}).get('status', 'HANDLER MISSING'), s['state']) for s in affected])
print('Domain state 0 = active; other values represent Plesk suspension status/bitmasks.')
print('Suspended websites remain listed to account for possible reactivation.\n')
# Report each subscription using PHP 8.1 or older, including addon domains.
# Prefer the executed binary version; use Plesk's registered version only
# if the binary version was unavailable. Never infer from the handler ID.
def old_php_branch(handler):
    for source in ('actual', 'registered'):
        m = re.match(r'^(\d+)\.(\d+)(?:\.|$)', handler[source])
        if m:
            branch = tuple(map(int, m.groups()))
            return ('{}.{}'.format(*branch), source) if branch <= (8, 1) else (None, source)
    return None, 'unknown'
legacy = []
for site in sites:
    handler = handlers.get(site['hid'])
    if not handler:
        continue
    branch, source = old_php_branch(handler)
    if branch is not None:
        legacy.append((site, branch, source))
print('3. SUBSCRIPTIONS USING PHP 8.1 OR OLDER (INCLUDING SUSPENDED)')
table(['Subscription', 'Website', 'PHP', 'Handler', 'Version source'],
      [(site['sub'], site['domain'], branch, site['hid'],
        'binary' if source == 'actual' else 'Plesk (fallback)')
       for site, branch, source in sorted(legacy, key=lambda x: (x[0]['sub'], x[0]['domain']))])
print('Subscriptions: {} | Websites: {}'.format(len({s['sub'] for s, _, _ in legacy}), len(legacy)))
print('Only PHP-enabled hosting entries are included. Version checks do not verify vendor backports.\n')
print('4. HANDLERS WITHOUT A CONFIRMED FIX - DETAILS')
for h in sorted(handlers.values(), key=lambda h: h['id']):
    if h['status'] == 'PATCHED':
        continue
    print('{}: {} | {}'.format(h['id'], h['status'], h['reason']))
    print('  Type: {} | Binary: {} | Plesk version: {} | Binary version: {}'.format(
        h['kind'], h['binary'], h['registered'], h['actual']))
    print('  Subscriptions: ' + (', '.join(sorted({s['sub'] for s in usage[h['id']]})) or '(none)'))
missing = sorted(set(usage) - set(handlers))
for hid in missing:
    errors.append('Handler referenced by a website is missing from inventory: ' + hid)
print('\n5. INSTALLED PHP PACKAGES (FOR VENDOR BACKPORT VERIFICATION)')
if shutil.which('dpkg-query'):
    rc, out, err = run(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'])
    package_rows = [r.split('\t')[:2] for r in out.splitlines()
                    if 'php' in r.split('\t')[0].lower() and r.endswith('\tinstalled')]
elif shutil.which('rpm'):
    rc, out, err = run(['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n'])
    package_rows = [r.split('\t') for r in out.splitlines() if 'php' in r.split('\t')[0].lower()]
else:
    rc, err, package_rows = 2, 'Neither dpkg-query nor rpm is available.', []
table(['Package', 'Full version'], sorted(package_rows))
if rc:
    errors.append('Incomplete package inventory: ' + err)
print('\nSUMMARY')
counts = Counter(h['status'] for h in handlers.values())
print('Handlers: {} | {}'.format(len(handlers), ', '.join('{}: {}'.format(k, v) for k, v in sorted(counts.items()))))
print('PHP-enabled websites: {} | without confirmed fix: {} | affected subscriptions: {}'.format(
    len(sites), len(affected), len({s['sub'] for s in affected})))
print('PHP 8.1 or older: {} websites in {} subscriptions'.format(
    len(legacy), len({s['sub'] for s, _, _ in legacy})))
print('IMPORTANT: Version checks cannot confirm vendor-specific security backports.')
print('PATCHED does not prove that all running PHP-FPM workers or Apache processes have restarted.')
print('Plesk panel PHP, webmail, Docker, and PHP installations not registered in Plesk are not checked.')
if errors:
    print('\nAUDIT INCOMPLETE:')
    for e in errors:
        print('  - ' + e)
    sys.exit(2)
sys.exit(1 if affected or any(h['status'] != 'PATCHED' for h in handlers.values()) else 0)
PY
