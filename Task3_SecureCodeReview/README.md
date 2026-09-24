# CodeAlpha_SecureCodeReview

**Cyber Security Internship — Task 3: Secure Coding Review**
CodeAlpha | Author: Fares

## 📌 Overview
A hands-on secure code review of a small Flask web application
(`UserPortal`). Rather than reviewing a generic snippet, this project
builds a realistic vulnerable application, audits it with both manual
review and automated static analysis (Bandit), documents every finding in
a professional report, and ships a fully remediated version.

## 📂 Structure
```
app_before/app.py       # Original application — 7 intentional vulnerabilities
app_after/app.py        # Remediated application — 0 Bandit findings
SECURITY_REVIEW.md       # Full audit report: findings, CWE mapping, fixes
```

## 🔍 What was audited
| # | Vulnerability | Severity | CWE |
|---|----------------|----------|-----|
| 1 | SQL Injection | Medium | CWE-89 |
| 2 | Plaintext password storage | Medium | CWE-256 |
| 3 | Reflected XSS | Medium | CWE-79 |
| 4 | Path Traversal | Medium | CWE-22 |
| 5 | Insecure Deserialization (`pickle`) | Medium | CWE-502 |
| 6 | Hardcoded secret key | Low | CWE-798 |
| 7 | Debug mode on public bind | High | CWE-94 / CWE-605 |

Full details, vulnerable code, and exact fixes for each are in
[`SECURITY_REVIEW.md`](./SECURITY_REVIEW.md).

## 🛠️ Tooling used
- Manual line-by-line code review
- [Bandit](https://bandit.readthedocs.io/) static analyzer (`pip install bandit`)

Reproduce the scan yourself:
```bash
pip install bandit --break-system-packages
bandit -r app_before/     # 6 issues found
bandit -r app_after/      # 0 issues found
```

## 🎓 What I learned
- How to systematically audit a codebase for the most common real-world
  vulnerability classes (which map closely to the OWASP Top 10)
- How to use a SAST tool (Bandit) to validate and supplement manual review
- How to translate a vulnerability into a clear, actionable fix rather
  than just flagging that a problem exists

## ⚠️ Disclaimer
`app_before/app.py` contains intentional security flaws for educational
purposes only. Do not deploy it.

## 👤 Author
Fares Adel | SOC Analyst (Tier 2)
