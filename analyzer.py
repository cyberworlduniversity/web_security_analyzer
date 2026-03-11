#!/usr/bin/env python3
"""
Web Security Header Analyzer
Scans websites and checks for critical security headers.
"""

import requests
from urllib.parse import urlparse
from datetime import datetime
import json
import sys


# Security headers to check with details
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Prevents XSS attacks by specifying allowed content sources.",
        "severity": "HIGH",
        "recommendation": "Add 'Content-Security-Policy' header. Example: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';"
    },
    "X-Frame-Options": {
        "description": "Protects against Clickjacking attacks.",
        "severity": "HIGH",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to prevent your site from being embedded in iframes."
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS).",
        "severity": "HIGH",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS."
    },
    "X-XSS-Protection": {
        "description": "Enables browser's built-in XSS filter.",
        "severity": "MEDIUM",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' to enable XSS filtering in older browsers."
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing.",
        "severity": "MEDIUM",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing the content type."
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent.",
        "severity": "LOW",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer leakage."
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs.",
        "severity": "LOW",
        "recommendation": "Add 'Permissions-Policy' header to restrict access to browser features like camera, microphone, geolocation."
    }
}

SEVERITY_SCORE = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}


def normalize_url(url: str) -> str:
    """Ensure the URL has a proper scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def fetch_headers(url: str) -> dict | None:
    """Fetch HTTP response headers from a URL."""
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "WebSecurityAnalyzer/1.0"}
        )
        return dict(response.headers), response.status_code, response.url
    except requests.exceptions.SSLError:
        print(f"  [!] SSL Error — trying HTTP fallback...")
        try:
            http_url = url.replace("https://", "http://")
            response = requests.get(http_url, timeout=10, allow_redirects=True,
                                    headers={"User-Agent": "WebSecurityAnalyzer/1.0"})
            return dict(response.headers), response.status_code, response.url
        except Exception as e:
            print(f"  [!] HTTP fallback also failed: {e}")
            return None, None, None
    except requests.exceptions.ConnectionError:
        print(f"  [!] Connection error — cannot reach {url}")
        return None, None, None
    except Exception as e:
        print(f"  [!] Unexpected error: {e}")
        return None, None, None


def analyze_headers(headers: dict) -> dict:
    """Analyze headers and return findings."""
    findings = {}
    # Normalize header keys to lowercase for comparison
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header, info in SECURITY_HEADERS.items():
        present = header.lower() in lower_headers
        value = lower_headers.get(header.lower(), None)
        findings[header] = {
            "present": present,
            "value": value,
            "severity": info["severity"],
            "description": info["description"],
            "recommendation": info["recommendation"] if not present else None
        }
    return findings


def calculate_score(findings: dict) -> tuple[int, str]:
    """Calculate a security score (0–100) and grade."""
    max_score = sum(SEVERITY_SCORE[v["severity"]] for v in findings.values())
    earned = sum(
        SEVERITY_SCORE[v["severity"]]
        for v in findings.values()
        if v["present"]
    )
    score = int((earned / max_score) * 100) if max_score else 0

    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return score, grade


def print_report(url: str, final_url: str, status_code: int, findings: dict, score: int, grade: str):
    """Print a formatted report to the console."""
    width = 70
    print("\n" + "=" * width)
    print("  🔒  WEB SECURITY HEADER ANALYZER — REPORT")
    print("=" * width)
    print(f"  Target URL   : {url}")
    if final_url != url:
        print(f"  Resolved URL : {final_url}")
    print(f"  Status Code  : {status_code}")
    print(f"  Scan Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Security Score: {score}/100  |  Grade: {grade}")
    print("=" * width)

    print("\n  📋  HEADER CHECK RESULTS\n")
    for header, data in findings.items():
        status_icon = "✅" if data["present"] else "❌"
        severity_tag = f"[{data['severity']}]" if not data["present"] else ""
        print(f"  {status_icon}  {header} {severity_tag}")
        if data["present"]:
            print(f"       Value: {data['value']}")
        else:
            print(f"       {data['description']}")
        print()

    missing = {k: v for k, v in findings.items() if not v["present"]}
    if missing:
        print("\n" + "-" * width)
        print("  🛡️  SECURITY RECOMMENDATIONS\n")
        for header, data in missing.items():
            print(f"  [{data['severity']}] {header}")
            print(f"    → {data['recommendation']}\n")
    else:
        print("\n  🎉  All security headers are present! Great job.\n")

    print("=" * width + "\n")


def save_json_report(url: str, final_url: str, status_code: int, findings: dict, score: int, grade: str, output_path: str):
    """Save the report as a JSON file."""
    report = {
        "target_url": url,
        "resolved_url": final_url,
        "status_code": status_code,
        "scan_time": datetime.now().isoformat(),
        "security_score": score,
        "grade": grade,
        "headers": findings,
        "summary": {
            "total_checked": len(findings),
            "present": sum(1 for v in findings.values() if v["present"]),
            "missing": sum(1 for v in findings.values() if not v["present"]),
            "missing_high": sum(1 for v in findings.values() if not v["present"] and v["severity"] == "HIGH"),
            "missing_medium": sum(1 for v in findings.values() if not v["present"] and v["severity"] == "MEDIUM"),
            "missing_low": sum(1 for v in findings.values() if not v["present"] and v["severity"] == "LOW"),
        }
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  📄  JSON report saved to: {output_path}")


def scan(url: str, save_report: bool = False, output_file: str = None):
    """Main scan function."""
    url = normalize_url(url)
    print(f"\n  🔍  Scanning: {url}")

    headers, status_code, final_url = fetch_headers(url)
    if headers is None:
        print("  ❌  Could not retrieve headers. Aborting scan.\n")
        return

    findings = analyze_headers(headers)
    score, grade = calculate_score(findings)
    print_report(url, final_url, status_code, findings, score, grade)

    if save_report:
        out = output_file or f"security_report_{urlparse(url).netloc.replace('.', '_')}.json"
        save_json_report(url, final_url, status_code, findings, score, grade, out)


# ── CLI Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage: python analyzer.py <url> [--save] [--output report.json]")
        print("  --save           Save a JSON report")
        print("  --output <file>  Custom output filename\n")
        sys.exit(1)

    target = sys.argv[1]
    do_save = "--save" in sys.argv
    out_file = None

    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            out_file = sys.argv[idx + 1]

    scan(target, save_report=do_save, output_file=out_file)
