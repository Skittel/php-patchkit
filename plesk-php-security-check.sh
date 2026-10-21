#!/usr/bin/env bash
# Read-only inventory for CVE-2026-109618 and CVE-2026-109619.
# Requirements: Linux, root, Plesk, Bash, Python >= 3.6. No network requests.
# Run: bash plesk-php-security-check.sh
# Exit: 0=no version findings, 1=findings/unconfirmed, 2=incomplete audit/error.
set -eu
command -v python3 >/dev/null || { echo 'FEHLER: python3 wird benötigt.' >&2; exit 2; }
command -v plesk >/dev/null || { echo 'FEHLER: plesk wurde nicht gefunden.' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'FEHLER: Als root ausführen.' >&2; exit 2; }
exec python3 - <<'PY'
import datetime
import os
import re
import shutil
import socket
import subprocess
import sys
from collections import Counter, defaultdict

FIXES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
SOURCE = 'https://www.php.net/archive/2026.php'
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
        print('(keine)')
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
        return 'UNKLAR', 'Version nicht ermittelbar'
    major, minor, patch = map(int, m.group(1, 2, 3))
    suffix = m.group(4)
    if re.search(r'(?:RC|alpha|beta|dev)', suffix, re.I):
        return 'UNKLAR', 'Vorabversion; separat prüfen'
    if (major, minor) in FIXES:
        minimum = FIXES[(major, minor)]
        if patch >= minimum:
            return 'FIX-VERSION', 'Upstream-Fixstand erreicht'
        return 'UNTER FIX', 'Backport möglich; Anbieterbeleg erforderlich'
    if (major, minor) <= (8, 1):
        return 'ALT / UNBESTÄTIGT', 'EOL; Backport für beide CVEs nachweisen'
    return 'UNKLAR', 'Zweig nicht in dieser Prüftabelle'

print('Plesk PHP-Sicherheitsprüfung — nur lesend')
print('Host: {} | Zeitpunkt: {}'.format(socket.getfqdn(), datetime.datetime.now().astimezone().isoformat()))
print('CVE-2026-109618 / CVE-2026-109619 | Referenz: ' + SOURCE)
print('Fixstände: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (21.10.2026)')
print('Prüft installierte Handler-Binaries, keine Exploits und keine Kundenanwendungen.\n')

rc, raw, err = run(['plesk', 'bin', 'php_handler', '--list'])
if rc:
    print('FEHLER beim Lesen der PHP-Handler: ' + err)
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
        errors.append('Handlerzeile nicht interpretierbar: ' + line.strip())
        continue
    hid, name, registered, branch, kind, binary, cli, ini, custom, enabled = m.groups()
    actual = '?'
    evidence = 'kein auslesbares Handler-Binary'
    if os.path.isfile(binary) and os.access(binary, os.X_OK) and '.so' not in os.path.basename(binary):
        rc, out, err = run([binary, '-n', '-v'], timeout=15)
        vm = re.search(r'^PHP\s+(\d+\.\d+\.\d+\S*)', out, re.M)
        if rc == 0 and vm:
            actual = vm.group(1)
            evidence = 'Handler-Binary -n -v'
        else:
            errors.append('{}: Binary-Version nicht lesbar: {}'.format(hid, err or out[:150]))
    status, reason = version_status(actual)
    handlers[hid] = dict(id=hid, name=name, registered=registered, actual=actual,
                         kind=kind, binary=binary, cli=cli, enabled=enabled,
                         status=status, reason=reason, evidence=evidence)

if not handlers:
    print(raw)
    print('FEHLER: Keine Handler lesbar. Keine Entwarnung möglich.')
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
    print('FEHLER: Domain-/Subskriptionszuordnung nicht lesbar: ' + err)
    sys.exit(2)
sites = []
usage = defaultdict(list)
for line in out.splitlines():
    fields = line.split('\t')
    if len(fields) != 5:
        errors.append('DB-Zeile nicht interpretierbar: ' + line)
        continue
    sub, domain, hid, user, state = fields
    row = dict(sub=sub, domain=domain, hid=hid, user=user, state=state)
    sites.append(row)
    usage[hid].append(row)

print('1. ALLE REGISTRIERTEN PHP-HANDLER')
table(['Handler', 'Plesk', 'Binary', 'Schalter', 'Websites', 'Befund'],
      [(h['id'], h['registered'], h['actual'], h['enabled'], len(usage[h['id']]), h['status'])
       for h in sorted(handlers.values(), key=lambda h: h['id'])])
print('\nFIX-VERSION = installierte Handler-Version enthält die beiden Upstream-Fixes.')
print('UNTER FIX / ALT = nicht als gepatcht bestätigt; Backports ändern oft nicht die Basisversion.')
print('Deaktivierte Handler werden mitgeprüft. PHP-deaktivierte Websites sind nicht in der Nutzungsliste.\n')

print('2. BETROFFENE SUBSKRIPTIONEN UND WEBSITES (einschließlich gesperrter)')
affected = [s for s in sites if handlers.get(s['hid'], {}).get('status') != 'FIX-VERSION']
table(['Subskription', 'Website', 'Systembenutzer', 'Handler', 'Befund', 'Domainstatus'],
      [(s['sub'], s['domain'], s['user'], s['hid'],
        handlers.get(s['hid'], {}).get('status', 'HANDLER FEHLT'), s['state']) for s in affected])
print('Domainstatus 0 = aktiv; andere Werte = Plesk-Sperrstatus/Bitmaske, nicht als aktiv gewertet.')
print('Auch deaktivierte Websites bleiben in der Liste, damit spätere Freigaben berücksichtigt werden.\n')

print('3. HANDLER OHNE BESTÄTIGTEN FIX — DETAILS')
for h in sorted(handlers.values(), key=lambda h: h['id']):
    if h['status'] == 'FIX-VERSION':
        continue
    print('{}: {} | {}'.format(h['id'], h['status'], h['reason']))
    print('  Typ: {} | Binary: {} | Plesk-Version: {} | Binary-Version: {}'.format(
        h['kind'], h['binary'], h['registered'], h['actual']))
    print('  Subskriptionen: ' + (', '.join(sorted({s['sub'] for s in usage[h['id']]})) or '(keine)'))
missing = sorted(set(usage) - set(handlers))
for hid in missing:
    errors.append('Von Websites referenzierter Handler fehlt im Inventar: ' + hid)

print('\n4. INSTALLIERTE PHP-PAKETE (für Backport-Abgleich beim Anbieter)')
if shutil.which('dpkg-query'):
    rc, out, err = run(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'])
    package_rows = [r.split('\t')[:2] for r in out.splitlines()
                    if 'php' in r.split('\t')[0].lower() and r.endswith('\tinstalled')]
elif shutil.which('rpm'):
    rc, out, err = run(['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n'])
    package_rows = [r.split('\t') for r in out.splitlines() if 'php' in r.split('\t')[0].lower()]
else:
    rc, err, package_rows = 2, 'Weder dpkg-query noch rpm verfügbar.', []
table(['Paket', 'Vollständige Version'], sorted(package_rows))
if rc:
    errors.append('Paketliste unvollständig: ' + err)

print('\nERGEBNIS')
counts = Counter(h['status'] for h in handlers.values())
print('Handler: {} | {}'.format(len(handlers), ', '.join('{}: {}'.format(k, v) for k, v in sorted(counts.items()))))
print('Websites mit PHP: {} | ohne bestätigten Fix: {} | betroffene Subskriptionen: {}'.format(
    len(sites), len(affected), len({s['sub'] for s in affected})))
print('WICHTIG: Versionstest ist kein Nachweis für installierte Anbieter-Backports.')
print('Kein Nachweis, dass alle laufenden Worker/Apache-Prozesse bereits neu gestartet wurden.')
print('Keine Prüfung von Plesk-Panel-PHP, Webmail, Docker oder nicht in Plesk registriertem PHP.')
if errors:
    print('\nPRÜFUNG UNVOLLSTÄNDIG:')
    for e in errors:
        print('  - ' + e)
    sys.exit(2)
sys.exit(1 if affected or any(h['status'] != 'FIX-VERSION' for h in handlers.values()) else 0)
PY
