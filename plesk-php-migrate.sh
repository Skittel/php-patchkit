#!/usr/bin/env bash
# php-patchkit 1.12 - https://github.com/Skittel/php-patchkit
# Raises the PHP handler of Plesk websites to a target branch.
#
# THIS SCRIPT WRITES. Every other script in php-patchkit is read-only; this one
# changes Plesk configuration. It is a dry run unless --apply is given, and it
# records a rollback file before making the first change.
#
# Run as root: bash plesk-php-migrate.sh --target 7.4
# Exit: 0=nothing to do, 1=changes pending (dry run) or partial failure,
#       2=incomplete/error.
set -eu
command -v python3 >/dev/null || { echo 'ERROR: python3 is required.' >&2; exit 2; }
command -v plesk >/dev/null || { echo 'ERROR: plesk was not found.' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: Run this script as root.' >&2; exit 2; }
exec python3 - "$@" <<'PY'
import datetime
import io
import os
import re
import subprocess
import sys
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except AttributeError:  # Python 3.6
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8',
                                  errors='replace', line_buffering=True)
VERSION = '1.12'
ROLLBACK_DIR = '/var/log'
HELP = """plesk-php-migrate - raise the PHP version of Plesk websites

THIS SCRIPT WRITES. It is a dry run unless --apply is given.

  --target X.Y      PHP branch to move websites to (required)
  --below X.Y       only websites whose current branch is below this
                    (default: the target, i.e. everything older than it)
  --only a.com,b.de restrict to these website names
  --apply           perform the changes (default: print what would change)
  --rollback FILE   restore the handlers recorded in FILE
  --help

A website is never moved to a lower branch than it already runs, whatever the
flags say. The handler type is preserved: fpm stays fpm, fastcgi stays fastcgi,
fpm-dedicated stays fpm-dedicated.
"""

def run(args, timeout=120):
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
    w = [max(len(h), max(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    print('  '.join(h.ljust(n) for h, n in zip(headers, w)))
    print('  '.join('-' * n for n in w))
    for row in rows:
        print('  '.join(x.ljust(n) for x, n in zip(row, w)))

def parse_args(argv):
    opts = dict(target=None, below=None, only=None, apply=False, rollback=None)
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--help':
            print(HELP)
            sys.exit(0)
        elif a == '--apply':
            opts['apply'] = True
        elif a in ('--target', '--below', '--only', '--rollback'):
            if i + 1 >= len(argv):
                print('ERROR: {} needs a value.'.format(a))
                sys.exit(2)
            opts[a[2:]] = argv[i + 1]
            i += 1
        else:
            print('ERROR: unknown argument: ' + a)
            print(HELP)
            sys.exit(2)
        i += 1
    return opts

def branch_tuple(text):
    m = re.match(r'^(\d+)\.(\d+)$', text or '')
    return (int(m.group(1)), int(m.group(2))) if m else None

def read_handlers():
    # id -> dict(branch, kind, enabled, suffix). suffix is the part after
    # plesk-phpNN-, or None for the distribution handlers (cgi/fastcgi/fpm/
    # module), which carry no such prefix.
    rc, raw, err = run(['plesk', 'bin', 'php_handler', '--list'])
    if rc:
        print('ERROR reading PHP handlers: ' + err)
        sys.exit(2)
    pattern = re.compile(r'^\s*(\S+)\s+(.+?)\s+(\d+\.\d+\.\d+\S*)\s+'
                         r'(\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$')
    out = {}
    for line in raw.splitlines():
        if not line.strip() or ('id:' in line and 'version:' in line):
            continue
        m = pattern.match(line)
        if not m:
            continue
        hid, _name, _reg, branch, kind, _bin, _cli, _ini, _cust, enabled = m.groups()
        sm = re.match(r'^plesk-php(\d)(\d)-(.+)$', hid)
        out[hid] = dict(id=hid, branch=branch_tuple(branch), kind=kind,
                        enabled=(enabled == 'enabled'),
                        suffix=sm.group(3) if sm else None)
    if not out:
        print('ERROR: no PHP handlers could be parsed. Refusing to continue.')
        sys.exit(2)
    return out

def read_sites():
    sql = ("SELECT COALESCE(s.name,d.name),d.name,h.php_handler_id "
           "FROM domains d JOIN hosting h ON h.dom_id=d.id "
           "LEFT JOIN domains s ON s.id=NULLIF(d.webspace_id,0) "
           "WHERE h.php='true' ORDER BY 1,2")
    rc, out, err = run(['plesk', 'db', '-N', '-B', '-e', sql])
    if rc:
        print('ERROR reading websites: ' + err)
        sys.exit(2)
    sites = []
    for line in out.splitlines():
        f = line.split('\t')
        if len(f) == 3:
            sites.append(dict(sub=f[0], domain=f[1], hid=f[2]))
    return sites

def resolve_target(current, target_branch, handlers):
    # Pick the handler of target_branch that keeps the current handler's type.
    # Returns (handler_id, note) on success or (None, reason) when no type-
    # preserving target exists - changing the type silently would alter how the
    # site is served, which is not what "raise the PHP version" means.
    candidates = [h for h in handlers.values() if h['branch'] == target_branch]
    if not candidates:
        return None, 'no handler installed for PHP {}.{}'.format(*target_branch)
    if current.get('suffix'):
        exact = [h for h in candidates if h['suffix'] == current['suffix']]
        if exact:
            return exact[0]['id'], ''
        return None, 'no {} handler for PHP {}.{}'.format(current['suffix'], *target_branch)
    # Distribution handler: match on the handler kind instead of the suffix.
    same_kind = [h for h in candidates if h['kind'] == current['kind']]
    if same_kind:
        same_kind.sort(key=lambda h: len(h['suffix'] or ''))
        return same_kind[0]['id'], 'from distribution handler, matched by type ' + current['kind']
    return None, 'Plesk ships no {} handler (distribution-only type)'.format(current['kind'])

def set_handler(domain, handler):
    # plesk bin site covers websites, subdomains need plesk bin subdomain.
    # Which one applies is not visible in the data read above, so try site
    # first and fall back, rather than guessing from the database schema.
    rc, out, err = run(['plesk', 'bin', 'site', '--update', domain,
                        '-php_handler_id', handler])
    if rc == 0:
        return True, 'site'
    rc2, out2, err2 = run(['plesk', 'bin', 'subdomain', '--update', domain,
                           '-php_handler_id', handler])
    if rc2 == 0:
        return True, 'subdomain'
    return False, '{} | {}'.format(err or out.strip()[:120], err2 or out2.strip()[:120])

def do_rollback(path, apply_changes):
    if not os.path.isfile(path):
        print('ERROR: rollback file not found: ' + path)
        return 2
    entries = []
    with open(path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            line = line.rstrip('\n')
            if not line or line.startswith('#') or line.startswith('domain\t'):
                continue
            f = line.split('\t')
            if len(f) >= 2:
                entries.append((f[0], f[1]))
    if not entries:
        print('ERROR: no usable entries in ' + path)
        return 2
    print('ROLLBACK from {} - {} website(s)'.format(path, len(entries)))
    table(['Website', 'Restore handler'], entries)
    if not apply_changes:
        print('\nDry run. Add --apply to restore these handlers.')
        return 1
    failed = []
    for domain, handler in entries:
        ok, info = set_handler(domain, handler)
        print('  {} -> {}: {}'.format(domain, handler,
                                      'OK (' + info + ')' if ok else 'FAILED'))
        if not ok:
            failed.append((domain, info))
    for domain, info in failed:
        print('ERROR: {}: {}'.format(domain, info))
    return 1 if failed else 0

def main():
    opts = parse_args(sys.argv[1:])
    print('Plesk PHP Migrate {} - {}'.format(
        VERSION, 'APPLY MODE (writes)' if opts['apply'] else 'dry run (no changes)'))
    print('Host: {} | {}'.format(os.uname()[1],
                                 datetime.datetime.now().astimezone().isoformat()))
    print()
    if opts['rollback']:
        return do_rollback(opts['rollback'], opts['apply'])
    target = branch_tuple(opts['target'])
    if not target:
        print('ERROR: --target X.Y is required (e.g. --target 7.4).')
        print(HELP)
        return 2
    below = branch_tuple(opts['below']) if opts['below'] else target
    only = set(x.strip() for x in opts['only'].split(',')) if opts['only'] else None
    handlers = read_handlers()
    sites = read_sites()
    planned, skipped, blocked = [], [], []
    for s in sites:
        if only and s['domain'] not in only:
            continue
        cur = handlers.get(s['hid'])
        if not cur or not cur['branch']:
            blocked.append((s['sub'], s['domain'], s['hid'],
                            'handler missing from the Plesk inventory'))
            continue
        if cur['branch'] >= below:
            skipped.append((s['sub'], s['domain'], s['hid'],
                            'already {}.{} or newer'.format(*below)))
            continue
        # Hard guard: never move a website down, whatever the flags asked for.
        if cur['branch'] >= target:
            skipped.append((s['sub'], s['domain'], s['hid'],
                            'would be a downgrade, refused'))
            continue
        new, note = resolve_target(cur, target, handlers)
        if not new:
            blocked.append((s['sub'], s['domain'], s['hid'], note))
            continue
        if not handlers[new]['enabled']:
            blocked.append((s['sub'], s['domain'], s['hid'],
                            'target handler {} is disabled in Plesk'.format(new)))
            continue
        planned.append(dict(sub=s['sub'], domain=s['domain'], old=s['hid'],
                            new=new, note=note))
    print('1. PLANNED CHANGES ({}) - PHP below {}.{} raised to {}.{}'.format(
        len(planned), below[0], below[1], target[0], target[1]))
    table(['Subscription', 'Website', 'From', 'To', 'Note'],
          [(p['sub'], p['domain'], p['old'], p['new'], p['note']) for p in planned])
    print('\n2. BLOCKED - NO SAFE TARGET ({})'.format(len(blocked)))
    table(['Subscription', 'Website', 'Handler', 'Reason'], blocked)
    print('\n3. SKIPPED ({})'.format(len(skipped)))
    table(['Subscription', 'Website', 'Handler', 'Reason'], skipped)
    print('\nWARNINGS')
    print('- Service plans: if a subscription is locked to a plan, "Sync with plan" can')
    print('  revert this change. For a permanent move, raise PHP in the service plan.')
    print('- Compatibility: 7.3 -> 7.4 is usually uneventful, 7.0/7.1 -> 7.4 is not. Run')
    print('  --only for a few websites first and check them before the full batch.')
    print('- An end-of-life target closes these two CVEs and nothing that comes after.')
    print('- Dedicated FPM pool settings and custom php.ini values are not migrated here.')
    if not planned:
        print('\nNothing to change.')
        return 0
    if not opts['apply']:
        print('\nDry run - nothing changed. Add --apply to perform the {} change(s).'.format(
            len(planned)))
        return 1
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    rb = os.path.join(ROLLBACK_DIR, 'plesk-php-migrate-{}.tsv'.format(stamp))
    # The rollback file is written before the first change, and a failure to
    # write it aborts the run: changing handlers with no way back is worse than
    # not changing them at all.
    try:
        with open(rb, 'w', encoding='utf-8') as fh:
            fh.write('# plesk-php-migrate {} rollback, written {}\n'.format(
                VERSION, datetime.datetime.now().astimezone().isoformat()))
            fh.write('# restore with: bash plesk-php-migrate.sh --rollback {} --apply\n'.format(rb))
            fh.write('domain\thandler\n')
            for p in planned:
                fh.write('{}\t{}\n'.format(p['domain'], p['old']))
    except OSError as e:
        print('ERROR: could not write the rollback file, so nothing was changed: ' + str(e))
        return 2
    print('\n4. APPLYING - rollback file: ' + rb)
    done, failed = [], []
    for p in planned:
        ok, info = set_handler(p['domain'], p['new'])
        print('  {} : {} -> {} : {}'.format(
            p['domain'], p['old'], p['new'], 'OK (' + info + ')' if ok else 'FAILED'))
        (done if ok else failed).append((p['domain'], info))
    print('\nChanged: {} | failed: {}'.format(len(done), len(failed)))
    for domain, info in failed:
        print('ERROR: {}: {}'.format(domain, info))
    print('Rollback: bash plesk-php-migrate.sh --rollback {} --apply'.format(rb))
    print('The rollback file lists only the websites this run intended to change.')
    print('Verify the result with plesk-php-security-check.sh - Plesk reconfigures the')
    print('affected pools itself, but this script does not confirm that it did.')
    return 1 if failed else 0
if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print('ERROR: incomplete: ' + str(exc), file=sys.stderr)
        sys.exit(2)
PY
