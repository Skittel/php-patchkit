# PHP Update Toolkit 1.10

A collection of practical scripts, tools, and guides to help administrators manage PHP updates, security patches, and related issues.

The goal is to provide simple, reliable, and easy-to-use solutions for common PHP maintenance and security challenges.

## Current Advisory: Critical PHP RCE (2026-10-21)

Two critical remote code execution vulnerabilities in PHP's core request handling
were disclosed on 21 October 2026, both rated **CVSS 9.2 (v4.0)**:

| CVE | Issue |
|---|---|
| **CVE-2026-109618** | RCE via OOM corruption — out-of-memory handling can interrupt PHP while internal request data is only partially initialized; request cleanup then treats the invalid data as valid. |
| **CVE-2026-109619** | RCE via stale global state — request-owned internal state can survive after its backing memory has been freed, and a later request in the same worker may use it before initialization resets it. |

**Fixed upstream versions:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12

**Security fixes are published only for PHP 8.2 and newer — now and for the
foreseeable future.** Upstream patches only actively supported branches, which is
why 8.2, 8.3, 8.4 and 8.5 received the releases above. No further patch is
planned for any older branch.

**Every host still running PHP 8.1 or older is therefore problematic: those
branches are end-of-life and will not be fixed.** For them the only real remedy
is an upgrade to 8.2 or newer — this is precisely why the scripts report PHP 8.1
and older separately. Distribution vendors may ship backports that keep the old
version number, so a version check alone cannot confirm a backport — verify
against your vendor's advisory.

**Plesk servers are a special case.** Plesk rebuilt its EOL branches with the
**same version number** and only a newer build date — 7.4.33, 8.0.30 and 8.1.34
built **on or after 21 October 2026** contain the fixes. A version comparison
therefore proves nothing on those branches; only the build date does:

```bash
/opt/plesk/php/7.4/bin/php -v | head -1
# PHP 7.4.33 (cli) (built: Oct 21 2026 08:04:57) (NTS)   <- patched
```

Branches 7.3 and older get no Plesk fix at all — TuxCare ELS or an upgrade. And
the panel's own PHP (`sw-engine`) is fixed by a separate Plesk hotfix,
18.0.80 #11 or 18.0.81 #4, not by a PHP package. `plesk-php-security-check.sh`
checks all three: upstream versions, EOL build dates, and the panel.

Every SAPI serving web requests is affected (PHP-FPM, mod_php, php-cgi,
FrankenPHP, LiteSpeed). Risk is highest with mod_php, where unauthenticated
requests can trigger the flaw before any application code runs. Patching the
packages is not sufficient on its own: PHP-FPM pools and Apache workers must be
restarted to drop stale processes.

The scripts in this repository are read-only inventories for exactly these two
CVEs — they report affected handlers, websites and subscriptions, and flag hosts
still running PHP 8.1 or older. They do not patch, restart or exploit anything.

### Detecting exploit attempts

Public proof-of-concept tooling for these CVEs has been observed sending marker
strings in the `User-Agent` header. Grepping your access logs for them is free
and may surface scanning or exploitation attempts:

```bash
grep -rEi 'php2shell-10961[89]' /var/log/apache2/ /var/log/nginx/ 2>/dev/null
zgrep -Ei 'php2shell-10961[89]' /var/log/apache2/*.gz /var/log/nginx/*.gz 2>/dev/null
```

A hit is not proof of a successful compromise, and an empty result is not proof
of safety: these markers belong to known public tooling and are trivial for an
attacker to change. Treat them as a cheap first look, not as a verdict.

### References

- [php.net release archive 2026](https://www.php.net/archive/2026.php) — official announcements and fixed versions
- [CERT-EU Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/) — advisory and mitigation guidance
- [watchTowr: CVE-2026-109618 FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/) — technical analysis
- [Plesk KB: CVE-2026-109618 & CVE-2026-109619](https://support.plesk.com/hc/en-us/articles/44397729587351) - Plesk-shipped PHP, EOL rebuild dates and sw-engine hotfixes
- [administrator.de overview](https://administrator.de/info/php-kritische-rce-luecken-cve-2026-109618-notfall-release-679311.html) — German-language summary

## What's Included

- Scripts for checking and updating PHP versions
- Security fixes and workarounds
- Docker and container-based PHP environments
- Plesk and native Linux installations
- Troubleshooting guides and best practices

## Usage

Everyone is welcome to use these resources for personal or commercial purposes.

**Important:** Always review scripts before running them, especially on production systems. Test changes and create backups where appropriate.

## Contributions & Feedback

Contributions, improvements, bug reports, and suggestions are always welcome!

Feel free to open a GitHub issue, submit a pull request, or contact me directly:

**info@kittel.online**

## License

This project is intended to be freely available for everyone.
