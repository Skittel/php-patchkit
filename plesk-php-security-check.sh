#!/usr/bin/env bash
# php-patchkit 1.11 - https://github.com/Skittel/php-patchkit
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
# Plesk rebuilt its EOL branches with the SAME version number and only a new
# build date, so for 7.4/8.0/8.1 a version comparison proves nothing at all -
# the build date is the only evidence. Patched builds are dated 21 Oct 2026 or
# later. Branches 7.3 and older get no Plesk fix (TuxCare ELS or upgrade).
PLESK_EOL = {(7, 4): 33, (8, 0): 30, (8, 1): 34}
PLESK_FIX_DATE = datetime.date(2026, 10, 21)
# The panel runs its own PHP (sw-engine), fixed by a Plesk hotfix rather than
# by a PHP package, so it needs a separate check against the panel version.
PANEL_FIX = {'18.0.80': 11, '18.0.81': 4}
PANEL_PHP = '/usr/local/psa/admin/bin/php'
SOURCE = 'https://www.php.net/archive/2026.php'
PLESK_KB = 'https://support.plesk.com/hc/en-us/articles/44397729587351'
VERSION = '1.11'
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
def patched(status):
    # Both PATCHED variants count as fixed; every other status does not.
    return status.startswith('PATCHED')
def build_date(text):
    # php -v prints: PHP 8.3.36 (cli) (built: Oct 21 2026 08:04:57) (NTS)
    # The day is space-padded for single digits. LC_ALL=C in run() keeps the
    # month name English, so %b parses regardless of the server locale.
    m = re.search(r'\(built:\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})', text)
    if not m:
        return None
    try:
        return datetime.datetime.strptime(' '.join(m.group(1, 2, 3)), '%b %d %Y').date()
    except ValueError:
        return None
def version_status(v, built, binary):
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
            return 'PATCHED', 'Version includes the upstream fixes'
        return 'BELOW FIX / CHECK BACKPORT', 'Vendor backport possible; verify with vendor advisory'
    if (major, minor) in PLESK_EOL:
        # Only builds from /opt/plesk/php are Plesk's own; a distribution PHP
        # of the same branch follows its vendor, not the Plesk rebuild date.
        if patch != PLESK_EOL[(major, minor)]:
            return ('EOL / NOT PATCHED', 'Plesk rebuilt only {}.{}.{}; this is {}'.format(
                major, minor, PLESK_EOL[(major, minor)], v))
        if not binary.startswith('/opt/plesk/php/'):
            return ('OLD / CHECK BACKPORT', 'EOL branch outside /opt/plesk/php (built {}); '
                    'the Plesk rebuild date does not apply, verify with the vendor'.format(
                        built or 'unknown'))
        if built is None:
            return ('UNKNOWN', 'EOL branch; build date unreadable, so the Plesk rebuild '
                    'cannot be confirmed')
        if built >= PLESK_FIX_DATE:
            return ('PATCHED / EOL', 'Built {}, on or after the Plesk rebuild date {}: both '
                    'CVEs are closed, but the branch stays end-of-life and will receive no '
                    'further upstream fixes'.format(built, PLESK_FIX_DATE))
        return ('EOL / NOT PATCHED', 'Built {}, before the Plesk rebuild date {}; install the '
                'rebuilt package via apt/dnf or plesk installer, then restart the PHP-FPM '
                'pools'.format(built, PLESK_FIX_DATE))
    if (major, minor) <= (7, 3):
        return ('EOL / NO PLESK FIX', 'Plesk ships no fix for this branch; TuxCare ELS or an '
                'upgrade to a supported branch is required')
    return 'UNKNOWN', 'Branch not covered by this version matrix'
print('Plesk PHP Security Check {} - read-only'.format(VERSION))
print('Host: {} | Checked at: {}'.format(socket.getfqdn(), datetime.datetime.now().astimezone().isoformat()))
print('CVE-2026-109618 / CVE-2026-109619 | Reference: ' + SOURCE)
print('Fixed upstream versions: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (2026-10-21)')
print('Plesk EOL rebuilds: 7.4.33 / 8.0.30 / 8.1.34 built on or after {} | {}'.format(
    PLESK_FIX_DATE, PLESK_KB))
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
    built = None
    evidence = 'No readable handler binary'
    if os.path.isfile(binary) and os.access(binary, os.X_OK) and '.so' not in os.path.basename(binary):
        rc, out, err = run([binary, '-n', '-v'], timeout=15)
        vm = re.search(r'^PHP\s+(\d+\.\d+\.\d+\S*)', out, re.M)
        if rc == 0 and vm:
            actual = vm.group(1)
            built = build_date(out)
            evidence = 'Handler binary -n -v'
            if built is None and (int(vm.group(1).split('.')[0]),
                                  int(vm.group(1).split('.')[1])) in PLESK_EOL:
                errors.append('{}: EOL branch without a readable build date; '
                              'patch state cannot be determined'.format(hid))
        else:
            errors.append('{}: Unable to read binary version: {}'.format(hid, err or out[:150]))
    status, reason = version_status(actual, built, binary)
    handlers[hid] = dict(id=hid, name=name, registered=registered, actual=actual,
                         kind=kind, binary=binary, cli=cli, enabled=enabled, built=built,
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
table(['Handler', 'Plesk', 'Binary', 'Built', 'Enabled', 'Websites', 'Status'],
      [(h['id'], h['registered'], h['actual'], h['built'] or '?', h['enabled'],
        len(usage[h['id']]), h['status'])
       for h in sorted(handlers.values(), key=lambda h: h['id'])])
print('\nPATCHED = handler binary meets the upstream fixed version and the branch is supported.')
print('PATCHED / EOL = both CVEs closed, but the branch is end-of-life. Applies to 7.4.33,')
print('  8.0.30 and 8.1.34 from /opt/plesk/php built on or after {}. Plesk rebuilt'.format(PLESK_FIX_DATE))
print('  these without changing the version number, so the build date is the only proof.')
print('  Fixed for today - no further upstream fixes will ever arrive. Plan the move to 8.2+.')
print('EOL / NOT PATCHED = Plesk rebuild exists but is not installed. Update and restart.')
print('EOL / NO PLESK FIX = 7.3 or older; Plesk ships nothing, TuxCare ELS or upgrade needed.')
print('Disabled handlers are also checked. PHP-disabled websites are excluded from usage counts.\n')
print('2. WEBSITES AND SUBSCRIPTIONS WITHOUT A CONFIRMED FIX (INCLUDING SUSPENDED)')
affected = [s for s in sites if not patched(handlers.get(s['hid'], {}).get('status', ''))]
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
table(['Subscription', 'Website', 'PHP', 'Handler', 'Built', 'Status', 'Version source'],
      [(site['sub'], site['domain'], branch, site['hid'],
        handlers[site['hid']]['built'] or '?', handlers[site['hid']]['status'],
        'binary' if source == 'actual' else 'Plesk (fallback)')
       for site, branch, source in sorted(legacy, key=lambda x: (x[0]['sub'], x[0]['domain']))])
print('Subscriptions: {} | Websites: {}'.format(len({s['sub'] for s, _, _ in legacy}), len(legacy)))
legacy_unpatched = [x for x in legacy if not patched(handlers[x[0]['hid']]['status'])]
print('Of those without a confirmed fix: {} websites in {} subscriptions'.format(
    len(legacy_unpatched), len({s['sub'] for s, _, _ in legacy_unpatched})))
print('These branches are end-of-life either way: a Plesk EOL rebuild closes these two CVEs')
print('but brings no future upstream fixes, so migrating to 8.2+ stays the real remedy.')
print('Only PHP-enabled hosting entries are included.\n')
print('4. HANDLERS WITHOUT A CONFIRMED FIX - DETAILS')
for h in sorted(handlers.values(), key=lambda h: h['id']):
    if patched(h['status']):
        continue
    print('{}: {} | {}'.format(h['id'], h['status'], h['reason']))
    print('  Type: {} | Binary: {} | Plesk version: {} | Binary version: {} | Built: {}'.format(
        h['kind'], h['binary'], h['registered'], h['actual'], h['built'] or '?'))
    print('  Subscriptions: ' + (', '.join(sorted({s['sub'] for s in usage[h['id']]})) or '(none)'))
missing = sorted(set(usage) - set(handlers))
for hid in missing:
    errors.append('Handler referenced by a website is missing from inventory: ' + hid)
# The panel has its own PHP (sw-engine). It is not a registered handler, so the
# inventory above never sees it, and it is fixed by a Plesk hotfix rather than
# by a PHP package - hence a separate check against the panel version.
print('\n5. PLESK PANEL ITSELF (sw-engine)')
panel_raw, panel_base, panel_upd = '?', None, None
rc, out, err = run(['plesk', 'version'])
if rc == 0:
    pm = re.search(r'^Product version:\s*(.+)$', out, re.M)
    if pm:
        panel_raw = pm.group(1).strip()
        vm = re.search(r'(\d+\.\d+\.\d+)(?:\D+(\d+))?', panel_raw)
        if vm:
            panel_base = vm.group(1)
            panel_upd = int(vm.group(2)) if vm.group(2) else 0
    else:
        errors.append('Unable to parse "plesk version" output: ' + out.strip()[:150])
else:
    errors.append('Unable to run "plesk version": ' + err)
panel_ver, panel_built = '?', None
if os.path.isfile(PANEL_PHP) and os.access(PANEL_PHP, os.X_OK):
    rc, out, err = run([PANEL_PHP, '-n', '-v'], timeout=15)
    vm = re.search(r'^PHP\s+(\d+\.\d+\.\d+\S*)', out, re.M)
    if rc == 0 and vm:
        panel_ver = vm.group(1)
        panel_built = build_date(out)
    else:
        errors.append('Unable to read panel PHP version: ' + (err or out[:150]))
else:
    errors.append('Panel PHP binary not found or not executable: ' + PANEL_PHP)
if panel_base in PANEL_FIX:
    need = PANEL_FIX[panel_base]
    if panel_upd >= need:
        panel_status = 'PATCHED'
        panel_reason = 'Update #{} meets the required hotfix #{}'.format(panel_upd, need)
    else:
        panel_status = 'NOT PATCHED'
        panel_reason = ('Update #{} is below the required hotfix #{}; it may not be released '
                        'yet - check the Plesk KB and run plesk installer'.format(panel_upd, need))
elif panel_base:
    panel_status = 'UNKNOWN'
    panel_reason = ('Panel version {} is not covered by this matrix (documented: {})'.format(
        panel_base, ', '.join('{}#{}'.format(k, v) for k, v in sorted(PANEL_FIX.items()))))
else:
    panel_status = 'UNKNOWN'
    panel_reason = 'Panel version could not be determined'
print('Panel version: {}'.format(panel_raw))
print('Panel PHP: {} | Built: {} | Binary: {}'.format(panel_ver, panel_built or '?', PANEL_PHP))
print('Status: {} | {}'.format(panel_status, panel_reason))
print('Required sw-engine hotfixes: ' + ', '.join(
    '{} Update #{}'.format(k, v) for k, v in sorted(PANEL_FIX.items())))
print('The panel is reachable without authentication on its own port, so an unpatched')
print('sw-engine is exposed independently of any website. Reference: ' + PLESK_KB + '\n')
print('6. INSTALLED PHP PACKAGES (FOR VENDOR BACKPORT VERIFICATION)')
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
print('PHP 8.1 or older: {} websites in {} subscriptions ({} without a confirmed fix)'.format(
    len(legacy), len({s['sub'] for s, _, _ in legacy}), len(legacy_unpatched)))
eol_ok = [h for h in handlers.values() if h['status'] == 'PATCHED / EOL']
eol_sites = [s for s in sites if handlers.get(s['hid'], {}).get('status') == 'PATCHED / EOL']
print('Patched but end-of-life: {} handlers, {} websites, {} subscriptions{}'.format(
    len(eol_ok), len(eol_sites), len({s['sub'] for s in eol_sites}),
    ' (' + ', '.join(sorted({h['actual'] for h in eol_ok})) + ')' if eol_ok else ''))
print('  Those are fixed for these two CVEs only. The next PHP vulnerability will not be')
print('  fixed for them, so they still need to move to 8.2 or newer.')
print('Plesk panel (sw-engine): {} | {}'.format(panel_status, panel_raw))
print('IMPORTANT: For 7.4/8.0/8.1 the version number is identical before and after the fix;')
print('this check relies on the build date reported by the binary itself.')
print('PATCHED does not prove that all running PHP-FPM workers or Apache processes have restarted.')
print('Webmail, Docker, and PHP installations not registered in Plesk are not checked.')
if errors:
    print('\nAUDIT INCOMPLETE:')
    for e in errors:
        print('  - ' + e)
    sys.exit(2)
sys.exit(1 if affected or panel_status != 'PATCHED'
         or any(not patched(h['status']) for h in handlers.values()) else 0)
PY
