# 🔒 Web Security Header Analyzer


## Get this repository

Clone the current project (this repository's canonical GitHub URL), then follow the installation and usage steps below.

```bash
git clone https://github.com/cyberworlduniversity/web_security_analyzer.git
cd web_security_analyzer
```

A Python-based command-line tool that scans any website and checks whether critical HTTP security headers are properly configured. It generates a security score, grade, and detailed recommendations.

---

## 📋 Features

- ✅ **Header Detection** — Checks for 7 essential security headers
- 📊 **Security Rating** — Scores websites from 0–100 with an A–F grade
- ❌ **Missing Header Detection** — Identifies missing headers with severity levels (HIGH / MEDIUM / LOW)
- 📄 **JSON Report Export** — Save detailed reports for auditing or CI/CD pipelines
- 🔁 **Redirect Handling** — Follows redirects and reports the final resolved URL
- 🔐 **SSL Fallback** — Gracefully falls back to HTTP if SSL errors occur

---

## 🛡️ Security Headers Checked

| Header | Severity | Purpose |
|---|---|---|
| `Content-Security-Policy` | HIGH | Prevents XSS attacks |
| `X-Frame-Options` | HIGH | Prevents Clickjacking |
| `Strict-Transport-Security` | HIGH | Enforces HTTPS (HSTS) |
| `X-XSS-Protection` | MEDIUM | Enables browser XSS filter |
| `X-Content-Type-Options` | MEDIUM | Prevents MIME sniffing |
| `Referrer-Policy` | LOW | Controls referrer leakage |
| `Permissions-Policy` | LOW | Restricts browser feature access |

---

## 🚀 Getting Started

### 1. Prerequisites

- Python 3.8 or higher
- pip

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Analyzer

**Basic scan:**
```bash
python analyzer.py https://example.com
```

**Scan and save a JSON report:**
```bash
python analyzer.py https://example.com --save
```

**Scan with a custom report filename:**
```bash
python analyzer.py https://example.com --save --output my_report.json
```

---

## 📊 Example Output

```
======================================================================
  🔒  WEB SECURITY HEADER ANALYZER — REPORT
======================================================================
  Target URL   : https://example.com
  Status Code  : 200
  Scan Time    : 2024-01-15 10:30:45
  Security Score: 57/100  |  Grade: C
======================================================================

  📋  HEADER CHECK RESULTS

  ✅  Content-Security-Policy
       Value: default-src 'self'

  ❌  X-Frame-Options [HIGH]
       Protects against Clickjacking attacks.

  ✅  Strict-Transport-Security
       Value: max-age=31536000; includeSubDomains

  ...

----------------------------------------------------------------------
  🛡️  SECURITY RECOMMENDATIONS

  [HIGH] X-Frame-Options
    → Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'
```

---

## 🏗️ Project Structure

```
web_security_analyzer/
├── analyzer.py        # Main analyzer script
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

---

## 📁 JSON Report Format

When using `--save`, a JSON file is generated:

```json
{
  "target_url": "https://example.com",
  "resolved_url": "https://www.example.com",
  "status_code": 200,
  "scan_time": "2024-01-15T10:30:45",
  "security_score": 57,
  "grade": "C",
  "headers": { ... },
  "summary": {
    "total_checked": 7,
    "present": 4,
    "missing": 3,
    "missing_high": 1,
    "missing_medium": 1,
    "missing_low": 1
  }
}
```

---

## 🔢 Scoring System

| Grade | Score | Meaning |
|---|---|---|
| A | 85–100 | Excellent security posture |
| B | 70–84 | Good, minor improvements needed |
| C | 50–69 | Average, several headers missing |
| D | 30–49 | Poor, significant risks present |
| F | 0–29 | Critical — most headers missing |

**Score weights:**
- HIGH severity headers: 30 points each
- MEDIUM severity headers: 15 points each
- LOW severity headers: 5 points each

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security auditing purposes only**. Always ensure you have permission to scan a target website before running this tool.

---

## 📜 License

MIT License — Free to use, modify, and distribute.

---

## 👤 Author

**hemanathan115**  
Web Security Header Analyzer v1.0
