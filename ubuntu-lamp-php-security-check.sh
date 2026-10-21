#!/usr/bin/env bash
# Read-only Ubuntu Apache/nginx inventory for CVE-2026-109618 / CVE-2026-109619.
# No updates, restarts, configuration changes, network access or web test files.
# Run as root: bash ubuntu-lamp-php-security-check.sh
# Requires Python >= 3.6 and dpkg-query. Exit: 0=version checks pass,
# 1=unconfirmed/old versions or restart indications, 2=incomplete/error.
set -eu
command -v python3 >/dev/null || { echo 'ERROR: python3 is required.' >&2; exit 2; }
command -v dpkg-query >/dev/null || { echo 'ERROR: dpkg-query is required.' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: Run this script as root.' >&2; exit 2; }
exec python3 - <<'PY'
import datetime
import fnmatch
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
        return 'UNKNOWN'
    a, b, c = map(int, m.group(1, 2, 3))
    if (a, b) in FIXES:
        return 'PATCHED' if c >= FIXES[(a, b)] else 'BELOW FIX / CHECK BACKPORT'
    return 'OLD / CHECK BACKPORT' if (a, b) <= (8, 1) else 'UNKNOWN'
def upstream(package_version):
    # Debian epoch and packaging revision are not upstream PHP patch levels.
    return re.sub(r'^\d+:', '', package_version).split('-', 1)[0]
def table(headers, rows):
    rows = [[str(v).replace('\n', ' ').replace('\r', ' ').replace('\x1b', '?')
             for v in row] for row in rows]
    if not rows:
        print('(none)')
        return
    sizes = [max(len(h), max(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    print('  '.join(h.ljust(n) for h, n in zip(headers, sizes)))
    print('  '.join('-' * n for n in sizes))
    for row in rows:
        print('  '.join(v.ljust(n) for v, n in zip(row, sizes)))
def runtime_package(name):
    return bool(re.fullmatch(r'(?:php\d+\.\d+-(?:cli|cgi|fpm|common|phpdbg)|libapache2-mod-php\d+\.\d+)', name))
# Apache -S reports *active* VirtualHost definitions with the file and line.
# Static inspection cannot resolve every RewriteRule, .htaccess, environment
# variable, user-defined handler, or external PHP endpoint.
PHP_BRANCH_RE = re.compile(
    r'(?:php(?:-fpm|-cgi)?[/_-]?|libphp)([0-9]+)\.([0-9]+)(?![0-9])'
    r'|/php/([0-9]+)\.([0-9]+)(?:/|$)', re.I)
PHP_DIRECTIVE_RE = re.compile(
    r'^\s*(?:SetHandler|AddHandler|AddType|Action|ProxyPass|ProxyPassMatch|'
    r'FcgidWrapper|FastCgiServer|FastCgiExternalServer|ScriptAlias)\b', re.I)
INCLUDE_RE = re.compile(r'^\s*Include(Optional)?\s+(.+?)\s*$', re.I)
VHOST_RE = re.compile(r'^\s*<VirtualHost(?:\s|>)', re.I)

def php_branches(text):
    found = set()
    for m in PHP_BRANCH_RE.finditer(text):
        major, minor = m.group(1, 2) if m.group(1) else m.group(3, 4)
        found.add((int(major), int(minor)))
    return found

def apache_config_lines(path, stack=None, selected_block=None, notices=None):
    """Read PHP directives and Includes, optionally from just one VH block."""
    stack = stack or set()
    notices = notices if notices is not None else []
    path = os.path.abspath(path)
    if path in stack:
        return []
    if len(stack) > 15:
        notices.append('Include nesting limit reached at ' + path)
        return []
    try:
        lines = Path(path).read_text(errors='replace').splitlines()
    except OSError as exc:
        notices.append('Cannot read Apache config {}: {}'.format(path, exc))
        return []
    if selected_block is not None:
        start = selected_block - 1
        if start >= len(lines) or not VHOST_RE.match(lines[start]):
            notices.append('Could not locate <VirtualHost> at {}:{}'.format(path, selected_block))
            return []
        level = 0
        chosen = []
        for line in lines[start:]:
            if VHOST_RE.match(line):
                level += 1
            if re.match(r'^\s*</VirtualHost\s*>', line, re.I):
                level -= 1
                if level == 0:
                    break
            chosen.append(line)
        lines = chosen
    gathered = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        inc = INCLUDE_RE.match(line)
        if inc:
            import shlex
            try:
                args = shlex.split(inc.group(2), comments=True)
            except ValueError:
                args = []
            if len(args) != 1:
                notices.append('Cannot resolve Include in ' + path + ': ' + stripped)
                continue
            name = args[0]
            if '${' in name or '%' in name:
                notices.append('Variable Include needs manual review in ' + path + ': ' + name)
                continue
            target = name if os.path.isabs(name) else os.path.join('/etc/apache2', name)
            matches = [p for p in sorted(glob.glob(target)) if os.path.isfile(p)]
            if not matches and not inc.group(1):
                notices.append('Required Apache Include not found: ' + target)
            for included in matches:
                gathered.extend(apache_config_lines(included, stack | {path}, notices=notices))
        elif PHP_DIRECTIVE_RE.match(line):
            gathered.append((stripped, '{}'.format(path)))
    return gathered

def apache_vhost_inventory(apache, module_output):
    """Return legacy and unknown active Apache virtual hosts (best effort)."""
    notices = []
    rc, output, error = run([apache, '-S'])
    if rc:
        raise RuntimeError('Unable to enumerate Apache virtual hosts: ' + (error or output))
    virtual_hosts = {}
    last_key = None
    for line in output.splitlines():
        match = re.search(r'\((/[^()]+):(\d+)\)\s*$', line)
        if match:
            path, line_no = match.group(1), int(match.group(2))
            head = line[:match.start()]
            name_match = re.search(r'(?:default server|namevhost)\s+(\S+)\s*$', head)
            if not name_match:
                name_match = re.search(r'^\s*\S+:\d+\s+(\S+)\s*$', head)
            if not name_match:
                last_key = None
                continue
            key = (path, line_no)
            entry = virtual_hosts.setdefault(key, {'name': name_match.group(1), 'aliases': []})
            # Prefer the namevhost line if it follows 'default server'.
            entry['name'] = name_match.group(1)
            last_key = key
        else:
            alias_match = re.search(r'^\s+(?:alias|wild alias)\s+(\S+)\s*$', line)
            if last_key is not None and alias_match:
                alias = alias_match.group(1)
                if alias not in virtual_hosts[last_key]['aliases']:
                    virtual_hosts[last_key]['aliases'].append(alias)
    if not virtual_hosts:
        notices.append('apachectl -S returned no parseable VirtualHost entries; check Apache configuration manually.')
    global_lines = []
    for pattern in ('/etc/apache2/conf-enabled/*', '/etc/apache2/mods-enabled/*.conf'):
        for path in sorted(glob.glob(pattern)):
            if os.path.isfile(path):
                global_lines.extend(apache_config_lines(path, notices=notices))
    global_branches = set()
    for directive, filename in global_lines:
        if 'php' in directive.lower():
            global_branches.update(php_branches(directive))
    mod_php = bool(re.search(r'\bphp\d*_module\b', module_output))
    mod_branches = set()
    if mod_php:
        for path in sorted(glob.glob('/etc/apache2/mods-enabled/php*.load')):
            if os.path.isfile(path):
                try:
                    text = Path(path).read_text(errors='replace')
                except OSError as exc:
                    notices.append('Unable to inspect mod_php: ' + str(exc))
                    continue
                mod_branches.update(php_branches(path + '\n' + text))
        global_branches.update(mod_branches)
        if not mod_branches:
            notices.append('Apache mod_php is active but its PHP version could not be determined.')
    old_vhosts, unknown_vhosts = [], []
    for (path, line_no), vhost in sorted(virtual_hosts.items(), key=lambda e: (e[1]['name'], e[0])):
        local_lines = apache_config_lines(path, selected_block=line_no, notices=notices)
        local_branches = set()
        for directive, filename in local_lines:
            if 'php' in directive.lower():
                local_branches.update(php_branches(directive))
        # An explicitly configured PHP version in a virtual host usually
        # overrides globally configured handlers. If multiple versions appear,
        # list every legacy one (for example different FilesMatch locations).
        chosen = local_branches if local_branches else global_branches
        origin = 'VirtualHost/Include' if local_branches else ('global Apache config' if global_branches else 'unknown')
        aliases = ', '.join(vhost['aliases']) or '-'
        for branch in sorted(chosen):
            if branch <= (8, 1):
                old_vhosts.append((vhost['name'], aliases, '{}.{}'.format(*branch),
                                   origin, '{}:{}'.format(path, line_no)))
        if not chosen:
            unknown_vhosts.append((vhost['name'], aliases, '{}:{}'.format(path, line_no)))
    return old_vhosts, unknown_vhosts, notices, len(virtual_hosts)

# Nginx -T prints the included, enabled configuration as separate source files.
# Reconstruct the include tree so a PHP handler in an included location or an
# upstream can be associated with the correct HTTP server block. The inventory
# is static: variables, remote upstreams and runtime config reloads may differ.
NGINX_TOKEN_RE = re.compile(r'\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};#"\']+')
NGINX_HEADER_RE = re.compile(r'^# configuration file (.+):\s*$')

def parse_nginx_source(content, path):
    root = []
    blocks = [root]
    words = []
    lineno = 1
    startline = 1
    for match in NGINX_TOKEN_RE.finditer(content):
        token = match.group(0)
        current_line = lineno
        lineno += token.count('\n')
        if token.isspace() or token.startswith('#'):
            continue
        if token in ('{', ';'):
            if not words:
                raise RuntimeError('Unexpected {} in {}:{}'.format(token, path, current_line))
            node = {'args': words, 'children': [], 'path': path, 'line': startline}
            blocks[-1].append(node)
            words = []
            if token == '{':
                blocks.append(node['children'])
        elif token == '}':
            if words or len(blocks) == 1:
                raise RuntimeError('Unexpected closing brace in {}:{}'.format(path, current_line))
            blocks.pop()
        else:
            if not words:
                startline = current_line
            if token.startswith(('"', "'")):
                token = token[1:-1]
            words.append(token)
    if words or len(blocks) != 1:
        raise RuntimeError('Incomplete nginx configuration in ' + path)
    return root

def nginx_config_dump(output):
    chunks = {}
    active = None
    for line in output.splitlines(True):
        match = NGINX_HEADER_RE.match(line.rstrip('\r\n'))
        if match:
            active = os.path.normpath(match.group(1))
            chunks[active] = []
        elif active is not None:
            chunks[active].append(line)
    return {path: parse_nginx_source(''.join(lines), path) for path, lines in chunks.items()}

def nginx_expand(nodes, sources, prefix, notices, seen):
    expanded = []
    for node in nodes:
        args = node['args']
        if args[0] == 'include' and len(args) >= 2:
            target = args[1]
            if '$' in target:
                notices.append('Dynamic nginx include: {}:{}'.format(node['path'], node['line']))
                continue
            candidate = os.path.normpath(target if target.startswith('/') else os.path.join(prefix, target))
            matches = sorted(path for path in sources if fnmatch.fnmatchcase(path, candidate))
            if not matches and not glob.has_magic(candidate):
                notices.append('Cannot resolve nginx include in -T output: ' + candidate)
            for path in matches:
                if path in seen:
                    notices.append('Recursive nginx include ignored: ' + path)
                    continue
                expanded.extend(nginx_expand(sources[path], sources, prefix, notices, seen | {path}))
        else:
            item = dict(node)
            if node['children']:
                item['children'] = nginx_expand(node['children'], sources, prefix, notices, seen)
            expanded.append(item)
    return expanded

def nginx_walk(nodes):
    for node in nodes:
        yield node
        for child in nginx_walk(node['children']):
            yield child

def nginx_vhost_inventory(nginx):
    notices = []
    rc, output, error = run([nginx, '-T'], timeout=60)
    if rc:
        raise RuntimeError('Unable to inspect nginx configuration with nginx -T: ' + (error or output[:200]))
    sources = nginx_config_dump(output)
    if not sources:
        raise RuntimeError('nginx -T returned no parseable configuration file sections')
    main_config = next(iter(sources))
    prefix = os.path.dirname(main_config)
    nodes = nginx_expand(sources[main_config], sources, prefix, notices, {main_config})
    http_nodes = [node for node in nginx_walk(nodes) if node['args'][0] == 'http']
    if not http_nodes:
        raise RuntimeError('nginx -T did not expose an HTTP configuration block')
    old_vhosts, unknown_vhosts, proxied_vhosts = [], [], []
    total = 0
    for http in http_nodes:
        upstreams = {}
        for child in http['children']:
            if child['args'][0] == 'upstream' and len(child['args']) > 1:
                upstreams[child['args'][1]] = [n['args'][1] for n in nginx_walk(child['children'])
                                                  if n['args'][0] == 'server' and len(n['args']) > 1]
        for server in http['children']:
            if server['args'][0] != 'server':
                continue
            total += 1
            names = [name for node in server['children'] if node['args'][0] == 'server_name'
                     for name in node['args'][1:]]
            name = names[0] if names else '(default/unnamed)'
            aliases = ', '.join(names[1:]) or '-'
            listen = ', '.join(node['args'][1] for node in server['children']
                               if node['args'][0] == 'listen' and len(node['args']) > 1) or '(inherited)'
            location = '{}:{}'.format(server['path'], server['line'])
            branches, ambiguous = set(), False
            has_fastcgi = False
            proxy_targets = []
            for entry in nginx_walk(server['children']):
                args = entry['args']
                if args[0] == 'fastcgi_pass' and len(args) > 1:
                    has_fastcgi = True
                    backend = args[1]
                    endpoints = upstreams.get(backend, [backend])
                    versions = set()
                    for endpoint in endpoints:
                        versions.update(php_branches(endpoint))
                    branches.update(versions)
                    if not versions or any(not php_branches(endpoint) for endpoint in endpoints):
                        ambiguous = True
                if args[0] == 'proxy_pass' and len(args) > 1:
                    proxy_targets.append(args[1])
            for branch in sorted(branches):
                if branch <= (8, 1):
                    old_vhosts.append((name, aliases, '{}.{}'.format(*branch), listen, location))
            # An unknown FastCGI endpoint might use an older PHP version even
            # when some other paths/locations have known, newer versions.
            if ambiguous:
                unknown_vhosts.append((name, aliases, listen, location))
            if proxy_targets:
                proxied_vhosts.append((name, aliases, listen, location))
    return old_vhosts, unknown_vhosts, proxied_vhosts, notices, total

def main():
    errors, warnings = [], []
    module_uncertain = False
    apache_modules = ''
    old_vhosts, unknown_vhosts = [], []
    total_vhosts = 0
    nginx_old, nginx_unknown, nginx_proxied = [], [], []
    nginx_total = 0
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            release[k] = v.strip('"')
    print('Ubuntu Apache/nginx PHP Security Check — read-only')
    print('Host: {} | Checked at: {}'.format(socket.getfqdn(), datetime.datetime.now().astimezone().isoformat()))
    print('OS: ' + release.get('PRETTY_NAME', '?'))
    print('CVEs: ' + ' / '.join(CVES))
    print('Fixed upstream versions: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12')
    print('Reference: https://www.php.net/archive/2026.php | As of: 2026-10-21\n')
    if release.get('ID') != 'ubuntu':
        print('ERROR: This script is intended for Ubuntu.')
        return 2
    rc, out, err = run(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\t${source:Package}\n'])
    if rc:
        print('ERROR: Unable to read package inventory: ' + err)
        return 2
    packages = []
    for line in out.splitlines():
        fields = line.split('\t')
        if len(fields) == 4 and fields[2] == 'installed' and 'php' in fields[0].lower():
            name, ver, state, source = fields
            packages.append((name, ver, source))
    runtimes = [(n, v, s, classify(upstream(v))) for n, v, s in packages if runtime_package(n.split(':')[0])]
    print('1. INSTALLED PHP RUNTIME PACKAGES')
    table(['Package', 'Full version', 'Source package', 'Status'], runtimes)
    print('\n2. PHP BINARIES ON THE FILESYSTEM')
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
            errors.append('Unable to inspect binary: {} ({})'.format(real, err or 'no version output'))
    table(['Binary (symlinks resolved)', 'Version', 'Status'], binaries)
    print('\n3. APACHE: CURRENT CONFIGURATION')
    apache = shutil.which('apache2ctl') or shutil.which('apachectl')
    if apache:
        rc, text, err = run([apache, '-M'])
        if rc:
            errors.append('Unable to inspect Apache configuration: ' + err)
        else:
            apache_modules = text
            relevant = [line.strip() for line in text.splitlines() if re.search(r'php|proxy_fcgi|mpm_', line)]
            for line in relevant:
                print('  ' + line)
            if any('php' in line for line in relevant):
                warnings.append('mod_php is configured: check the package for the exact LoadModule path; CLI PHP does not prove Apache PHP is patched.')
        print('PHP LoadModule directives in mods-enabled (configuration, not proof of active runtime):')
        for filename in sorted(glob.glob('/etc/apache2/mods-enabled/*.load')):
            for line in Path(filename).read_text(errors='replace').splitlines():
                if re.match(r'\s*LoadModule\s+\S*php', line, re.I):
                    print('  {}: {}'.format(filename, line.strip()))
                    parts = line.split()
                    if len(parts) >= 3 and parts[2].startswith('/'):
                        module = parts[2].strip('"')
                        rc, owner, err = run(['dpkg-query', '-S', module])
                        print('    Package owner: ' + (owner.strip() if rc == 0 else 'unknown/custom'))
                        if rc != 0:
                            module_uncertain = True
                            warnings.append('Apache PHP module without package ownership: ' + module)
                    else:
                        module_uncertain = True
                        warnings.append('Relative or variable Apache PHP module path requires manual inspection.')
    else:
        print('Apache control executable not found.')
    print('\n4. PHP HANDLERS IN ENABLED APACHE CONFIGURATION FILES')
    print('Matches to identify websites and FPM sockets; not a complete virtual host audit:')
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
    print('\n5. APACHE VIRTUAL HOSTS USING PHP 8.1 OR OLDER')
    if apache:
        try:
            old_vhosts, unknown_vhosts, notices, total_vhosts = apache_vhost_inventory(apache, apache_modules)
            table(['VirtualHost', 'ServerAlias', 'PHP', 'Detected in', 'Config location'], old_vhosts)
            print('Active VirtualHosts: {} | using PHP <= 8.1: {}'.format(total_vhosts, len(set(r[4] for r in old_vhosts))))
            print('If a global PHP handler applies, VirtualHosts without their own version inherit it.')
            print('The list is based on Apache configuration, not requests to hosted websites.')
            if unknown_vhosts:
                print('\nVirtualHosts with PHP version NOT DETERMINED (manual review):')
                table(['VirtualHost', 'ServerAlias', 'Config location'], unknown_vhosts)
            print('NOTE: .htaccess, dynamic includes, rewrite rules, and external PHP backends may')
            print('hide additional old PHP versions; inspect such configurations separately.')
            for notice in sorted(set(notices)):
                warnings.append('Apache VirtualHost inventory: ' + notice)
        except RuntimeError as exc:
            errors.append(str(exc))
            print('ERROR: ' + str(exc))
    else:
        print('Apache is not installed; no Apache VirtualHosts can be listed.')
    print('\n6. NGINX HTTP SERVER BLOCKS USING PHP 8.1 OR OLDER')
    nginx = shutil.which('nginx')
    if nginx:
        try:
            nginx_old, nginx_unknown, nginx_proxied, notices, nginx_total = nginx_vhost_inventory(nginx)
            table(['Server name', 'Server aliases', 'PHP', 'Listen', 'Config location'], nginx_old)
            print('HTTP server blocks: {} | using PHP <= 8.1: {}'.format(
                nginx_total, len(set(row[4] for row in nginx_old))))
            print('PHP-FPM versions are inferred from configured fastcgi_pass sockets and upstream targets.')
            if nginx_unknown:
                print('\nFastCGI server blocks with UNKNOWN PHP version (manual check):')
                table(['Server name', 'Server aliases', 'Listen', 'Config location'], nginx_unknown)
            if nginx_proxied:
                print('\nReverse-proxy server blocks (backend PHP version NOT CHECKED):')
                table(['Server name', 'Server aliases', 'Listen', 'Config location'], nginx_proxied)
            print('NOTE: fastcgi_pass using a generic socket, variable, host:port, or remote backend')
            print('cannot be classified without inspecting the backend configuration.')
            print('Nginx -T shows configuration files, not necessarily the loaded worker configuration.')
            for notice in sorted(set(notices)):
                warnings.append('nginx VirtualHost inventory: ' + notice)
        except RuntimeError as exc:
            errors.append(str(exc))
            print('ERROR: ' + str(exc))
    else:
        print('nginx binary not found; no nginx HTTP server blocks can be listed.')
    print('\n7. RUNNING APACHE/NGINX/PHP PROCESSES AND REPLACED FILES')
    processes, stale = [], []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            comm = (proc / 'comm').read_text().strip()
            if not (comm.startswith('php') or comm in ('apache2', 'httpd', 'nginx')):
                continue
            exe = os.readlink(str(proc / 'exe'))
            maps = (proc / 'maps').read_text(errors='replace')
            old = exe.endswith(' (deleted)') or any('(deleted)' in line and re.search(r'php|apache2|httpd|nginx', line, re.I) for line in maps.splitlines())
            processes.append((proc.name, comm, exe, 'RESTART REQUIRED?' if old else 'No deleted PHP/web-server binary detected'))
            if old:
                stale.append(proc.name)
        except FileNotFoundError:
            continue  # A worker exited during the read.
        except (PermissionError, OSError) as e:
            errors.append('Unable to inspect process {}: {}'.format(proc.name, e))
    table(['PID', 'Process', 'Executable', 'Note'], processes)
    if stale:
        warnings.append('Processes using replaced/deleted PHP, Apache or nginx files: ' + ', '.join(stale))
    print('\n8. LOCAL PACKAGE CHANGELOGS: POSSIBLE BACKPORT REFERENCES')
    print('References only, NOT automatic proof of a security fix. No data is downloaded.')
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
            warnings.append('Unable to read changelog: ' + filename)
    if not found:
        print('  No references to the CVEs found in locally available PHP changelogs.')
    print('Vendor advisories: https://ubuntu.com/security/CVE-2026-109618')
    print('                  https://ubuntu.com/security/CVE-2026-109619')
    print('Compare the complete Ubuntu package version, including its Ubuntu revision, against both advisories.')
    print('PPA, Sury and custom packages require confirmation from their respective vendors.')
    print('\n9. ALL INSTALLED PHP PACKAGES')
    table(['Package', 'Full version', 'Source package'], sorted(packages))
    print('\nSUMMARY')
    counts = Counter(row[3] for row in runtimes)
    print('Runtime packages: {} | {}'.format(len(runtimes), ', '.join('{}: {}'.format(k, v) for k, v in sorted(counts.items()))))
    print('Apache VirtualHosts using PHP <= 8.1: {} of {} | version undetermined: {}'.format(
        len(set(r[4] for r in old_vhosts)), total_vhosts, len(unknown_vhosts)))
    print('nginx HTTP server blocks using PHP <= 8.1: {} of {} | FastCGI version unknown: {} | reverse-proxy: {}'.format(
        len(set(r[4] for r in nginx_old)), nginx_total, len(nginx_unknown), len(nginx_proxied)))
    print('PATCHED: installed version meets the upstream fixed version.')
    print('BELOW FIX / OLD: a vendor backport may exist, but has not been confirmed by this check.')
    print('This is not an overall statement that the server is secure: running workers may still use old files.')
    print('Process checks detect common replaced files but do not prove that all services have restarted.')
    print('No exploit or HTTP tests. Docker, remote FPM backends and arbitrary custom paths are not fully covered.')
    print('Reverse-proxied nginx/Apache sites may require checking the backend separately.')
    for warning in warnings:
        print('NOTICE: ' + warning)
    if errors:
        for error in errors:
            print('ERROR: ' + error)
        return 2
    if not runtimes and not binaries:
        print('No PHP runtime found; this does not prove PHP is absent.')
        return 2
    return 1 if old_vhosts or unknown_vhosts or nginx_old or nginx_unknown or nginx_proxied or stale or module_uncertain or any(row[3] != 'PATCHED' for row in runtimes) or any(row[2] != 'PATCHED' for row in binaries) else 0
if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print('ERROR: Audit incomplete: ' + str(exc), file=sys.stderr)
        sys.exit(2)
PY
