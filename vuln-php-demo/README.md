# Intentionally Vulnerable PHP Demo

A small collection of PHP scripts, each deliberately vulnerable to one
common web vulnerability class. Built for local practice — testing
scanners/tools, learning exploitation basics, or demoing findings.

**Run only on localhost / an isolated VM. Never deploy this anywhere
reachable from the internet.**

## Setup

```bash
cd vuln-php-demo
php -S 127.0.0.1:8000
```

SQLi and IDOR demos need SQLite (bundled via PDO, no extra setup) —
run `php config/seed_db.php` once to create `data.sqlite` with sample
users.

## Contents

| File | Vulnerability | OWASP / CWE |
|---|---|---|
| `sqli.php` | SQL Injection (string-concatenated query) | CWE-89 |
| `xss.php` | Reflected + Stored XSS (unescaped output) | CWE-79 |
| `lfi.php` | Local File Inclusion / path traversal | CWE-98, CWE-22 |
| `cmdi.php` | OS Command Injection | CWE-78 |
| `upload.php` | Unrestricted File Upload | CWE-434 |
| `idor.php` | Insecure Direct Object Reference | CWE-639 |
| `deserialize.php` | Insecure Deserialization (`unserialize`) | CWE-502 |
| `ssrf.php` | Server-Side Request Forgery | CWE-918 |
| `weak_auth.php` | Hardcoded creds + broken auth logic | CWE-798, CWE-287 |
| `xxe.php` | XML External Entity Injection | CWE-611 |

Each file has:
- A comment block at the top explaining the flaw and how to trigger it
- A `// FIX:` comment showing the secure version of the vulnerable line
- No external dependencies beyond core PHP extensions (pdo_sqlite, libxml)

## Suggested use

- Point Burp/ZAP/your own scanner at `http://127.0.0.1:8000/<file>.php`
- Use as fixtures for a static-analysis or SAST tool you're building
- Use in writeups/portfolio pieces to demonstrate exploitation + remediation side by side
