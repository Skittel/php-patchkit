#!/usr/bin/env bash
# Read-only Ubuntu LAMP inventory for CVE-2026-109618 / CVE-2026-109619.
# No updates, restarts, configuration changes, network access or web test files.
# Run as root: bash ubuntu-lamp-php-security-check.sh
# Requires Python >= 3.6 and dpkg-query. Exit: 0=version checks pass,
# 1=unconfirmed/old versions or restart indications, 2=incomplete/error.
set -eu
command -v python3 >/dev/null || { echo 'FEHLER: python3 fehlt.' >&2; exit 2; }
command -v dpkg-query >/dev/null || { echo 'FEHLER: dpkg-query fehlt.' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'FEHLER: Als root ausführen.' >&2; exit 2; }
exec python3 - <<'PY'
import datetime
import glob
import gzip
import os
import re
import shutil
import socket
import subprocess
import sys
from collections import Counter
from pathlib import Path

FIXES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
CVES = ('CVE-2026-109618', 'CVE-2026-109619')

def run(args, timeout=30):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout,
                           env=dict(os.environ, LC_ALL='C'))
        return p.returncode, p.stdout, p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 2, '', str(e)

def classify(v):
    # Accept only stable versions in the four explicitly documented branches.
    m = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(.*)', v)
    if not m or re.search(r'RC|alpha|beta|dev', m.group(4), re.I):
        return 'UNKLAR'
    a, b, c = map(int, m.group(1, 2, 3))
    if (a, b) in FIXES:
        return 'FIX-VERSION' if c >= FIXES[(a, b)] else 'UNTER FIX / BACKPORT PRÜFEN'
    return 'ALT / BACKPORT PRÜFEN' if (a, b) <= (8, 1) else 'UNKLAR'

def upstream(package_version):
    # Debian epoch and packaging revision are not upstream PHP patch levels.
    return re.sub(r'^\d+:', '', package_version).split('-', 1)[0]

def table(headers, rows):
    rows = [[str(v).replace('\n', ' ').replace('\r', ' ').replace('\x1b', '?')
             for v in row] for row in rows]
    if not rows:
        print('(keine)')
        return
    sizes = [max(len(h), max(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    print('  '.join(h.ljust(n) for h, n in zip(headers, sizes)))
    print('  '.join('-' * n for n in sizes))
    for row in rows:
        print('  '.join(v.ljust(n) for v, n in zip(row, sizes)))

def runtime_package(name):
    return bool(re.fullmatch(r'(?:php\d+\.\d+-(?:cli|cgi|fpm|common|phpdbg)|libapache2-mod-php\d+\.\d+)', name))

def main():
    errors, warnings = [], []
    module_uncertain = False
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            release[k] = v.strip('"')
    print('Ubuntu LAMP PHP-Sicherheitsprüfung — nur lesend')
    print('Host: {} | {}'.format(socket.getfqdn(), datetime.datetime.now().astimezone().isoformat()))
    print('System: ' + release.get('PRETTY_NAME', '?'))
    print('CVEs: ' + ' / '.join(CVES))
    print('Upstream-Fixstände: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12')
    print('Quelle: https://www.php.net/archive/2026.php | Stand: 21.10.2026\n')
    if release.get('ID') != 'ubuntu':
        print('FEHLER: Dieses Skript ist für Ubuntu vorgesehen.')
        return 2

    rc, out, err = run(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\t${source:Package}\n'])
    if rc:
        print('FEHLER: Paketliste nicht lesbar: ' + err)
        return 2
    packages = []
    for line in out.splitlines():
        fields = line.split('\t')
        if len(fields) == 4 and fields[2] == 'installed' and 'php' in fields[0].lower():
            name, ver, state, source = fields
            packages.append((name, ver, source))
    runtimes = [(n, v, s, classify(upstream(v))) for n, v, s in packages if runtime_package(n.split(':')[0])]
    print('1. INSTALLIERTE PHP-LAUFZEITPAKETE')
    table(['Paket', 'Vollständige Version', 'Quellpaket', 'Befund'], runtimes)

    print('\n2. PHP-BINARIES AUF DEM DATEISYSTEM')
    candidates = set()
    for pat in ['/usr/bin/php', '/usr/bin/php[0-9]*', '/usr/bin/php-cgi*',
                '/usr/sbin/php-fpm*', '/usr/local/bin/php', '/usr/local/bin/php-cgi',
                '/usr/local/sbin/php-fpm', '/opt/plesk/php/*/bin/php',
                '/opt/plesk/php/*/sbin/php-fpm']:
        candidates.update(glob.glob(pat))
    if shutil.which('php'):
        candidates.add(shutil.which('php'))
    binaries, seen = [], set()
    for path in sorted(candidates):
        # Excludes phpize, php-config, phpdbg and arbitrary extension files.
        if not re.fullmatch(r'php(?:\d+\.\d+)?|php-cgi(?:\d+\.\d+)?|php-fpm(?:\d+\.\d+)?', os.path.basename(path)):
            continue
        real = os.path.realpath(path)
        if real in seen or not os.path.isfile(real) or not os.access(real, os.X_OK):
            continue
        seen.add(real)
        rc, text, err = run([real, '-n', '-v'], timeout=10)
        m = re.search(r'^PHP\s+(\d+\.\d+\.\d+\S*)', text, re.M)
        version = m.group(1) if rc == 0 and m else '?'
        binaries.append((real, version, classify(version)))
        if version == '?':
            errors.append('Binary nicht prüfbar: {} ({})'.format(real, err or 'keine Versionsausgabe'))
    table(['Binary (Symlinks aufgelöst)', 'Version', 'Befund'], binaries)

    print('\n3. APACHE: AKTUELLE KONFIGURATION')
    apache = shutil.which('apache2ctl') or shutil.which('apachectl')
    if apache:
        rc, text, err = run([apache, '-M'])
        if rc:
            errors.append('Apache-Konfiguration nicht auswertbar: ' + err)
        else:
            relevant = [line.strip() for line in text.splitlines() if re.search(r'php|proxy_fcgi|mpm_', line)]
            for line in relevant:
                print('  ' + line)
            if any('php' in line for line in relevant):
                warnings.append('mod_php konfiguriert: Paket des exakten LoadModule-Pfads prüfen; CLI-PHP ist kein Nachweis für Apache-PHP.')
        print('PHP-LoadModule-Zeilen aus mods-enabled (Konfiguration, kein Laufzeitnachweis):')
        for filename in sorted(glob.glob('/etc/apache2/mods-enabled/*.load')):
            for line in Path(filename).read_text(errors='replace').splitlines():
                if re.match(r'\s*LoadModule\s+\S*php', line, re.I):
                    print('  {}: {}'.format(filename, line.strip()))
                    parts = line.split()
                    if len(parts) >= 3 and parts[2].startswith('/'):
                        module = parts[2].strip('"')
                        rc, owner, err = run(['dpkg-query', '-S', module])
                        print('    Paketzuordnung: ' + (owner.strip() if rc == 0 else 'unbekannt/custom'))
                        if rc != 0:
                            module_uncertain = True
                            warnings.append('Apache-PHP-Modul ohne Paketzuordnung: ' + module)
                    else:
                        module_uncertain = True
                        warnings.append('Relativer/variabler Apache-PHP-Modulpfad separat zu prüfen.')
    else:
        print('Apache-Steuerprogramm nicht gefunden.')

    print('\n4. PHP-ZUORDNUNGEN IN AKTIVIERTEN APACHE-KONFIGURATIONEN')
    print('Fundstellen zum Zuordnen von Websites/FPM-Sockets; keine vollständige VHost-Auswertung:')
    for filename in sorted(set(glob.glob('/etc/apache2/sites-enabled/*') + glob.glob('/etc/apache2/conf-enabled/*'))):
        if not os.path.isfile(filename):
            continue
        for lineno, line in enumerate(Path(filename).read_text(errors='replace').splitlines(), 1):
            if line.lstrip().startswith('#'):
                continue
            if re.search(r'^\s*(?:ServerName|ServerAlias|DocumentRoot)\b', line, re.I) or (
                    re.search(r'SetHandler|ProxyPassMatch|FcgidWrapper|Action|Include', line, re.I)
                    and re.search(r'php|fcgi', line, re.I)):
                print('  {}:{}  {}'.format(filename, lineno, line.strip()))

    print('\n5. LAUFENDE APACHE-/PHP-PROZESSE UND ALTE DATEIEN')
    processes, stale = [], []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            comm = (proc / 'comm').read_text().strip()
            if not (comm.startswith('php') or comm in ('apache2', 'httpd')):
                continue
            exe = os.readlink(str(proc / 'exe'))
            maps = (proc / 'maps').read_text(errors='replace')
            old = exe.endswith(' (deleted)') or any('(deleted)' in line and re.search(r'php|apache2|httpd', line, re.I) for line in maps.splitlines())
            processes.append((proc.name, comm, exe, 'NEUSTART PRÜFEN' if old else 'kein gelöschtes PHP/Apache-Binary erkannt'))
            if old:
                stale.append(proc.name)
        except FileNotFoundError:
            continue  # A worker exited during the read.
        except (PermissionError, OSError) as e:
            errors.append('Prozess {} nicht lesbar: {}'.format(proc.name, e))
    table(['PID', 'Prozess', 'Executable', 'Hinweis'], processes)
    if stale:
        warnings.append('Prozesse mit ersetzten/gelöschten PHP-/Apache-Dateien: ' + ', '.join(stale))

    print('\n6. LOKALE PAKET-CHANGELOGS: HINWEISE AUF BACKPORTS')
    print('Nur Fundstellen, KEIN automatischer Patchnachweis. Es werden keine Daten heruntergeladen.')
    found = False
    for filename in sorted(glob.glob('/usr/share/doc/*php*/changelog*')):
        if not os.path.isfile(filename):
            continue
        try:
            if filename.endswith('.gz'):
                with gzip.open(filename, 'rt', errors='replace') as stream:
                    text = stream.read(8 * 1024 * 1024)
            else:
                text = Path(filename).read_text(errors='replace')[:8 * 1024 * 1024]
            hits = [cve for cve in CVES if cve in text]
            if hits:
                found = True
                print('  {}: {}'.format(filename, ', '.join(hits)))
        except (OSError, EOFError) as e:
            warnings.append('Changelog nicht lesbar: ' + filename)
    if not found:
        print('  Keine CVE-Nennung in den lokal vorhandenen PHP-Changelogs gefunden.')
    print('Anbieterbelege: https://ubuntu.com/security/CVE-2026-109618')
    print('               https://ubuntu.com/security/CVE-2026-109619')
    print('Ubuntu-Paketversion einschließlich Ubuntu-Revision gegen beide Meldungen abgleichen.')
    print('PPA-/Sury-/Custom-Pakete benötigen den Nachweis ihres eigenen Anbieters.')

    print('\n7. ALLE INSTALLIERTEN PHP-PAKETE')
    table(['Paket', 'Vollständige Version', 'Quellpaket'], sorted(packages))

    print('\nERGEBNIS')
    counts = Counter(row[3] for row in runtimes)
    print('Laufzeitpakete: {} | {}'.format(len(runtimes), ', '.join('{}: {}'.format(k, v) for k, v in sorted(counts.items()))))
    print('FIX-VERSION: Upstream-Fixstand der installierten Version erreicht.')
    print('UNTER FIX / ALT: Backport möglich; ohne Anbieterbeleg nicht bestätigt gepatcht.')
    print('Kein Gesamturteil "Server sicher": laufende Worker können trotz neuer Pakete alt sein.')
    print('Die Prozessprüfung erkennt typische ersetzte Dateien, beweist aber keinen vollständigen Neustart.')
    print('Kein Exploit-/HTTP-Test. Docker, entfernte FPM-Backends und beliebige Custom-Pfade sind nicht vollständig erfasst.')
    for warning in warnings:
        print('HINWEIS: ' + warning)
    if errors:
        for error in errors:
            print('FEHLER: ' + error)
        return 2
    if not runtimes and not binaries:
        print('Keine PHP-Laufzeit gefunden; PHP-Freiheit ist damit nicht bewiesen.')
        return 2
    return 1 if stale or module_uncertain or any(row[3] != 'FIX-VERSION' for row in runtimes) or any(row[2] != 'FIX-VERSION' for row in binaries) else 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print('FEHLER: Prüfung unvollständig: ' + str(exc), file=sys.stderr)
        sys.exit(2)
PY
