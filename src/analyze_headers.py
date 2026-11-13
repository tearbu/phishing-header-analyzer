#!/usr/bin/env python3
"""
phishing-header-analyzer: score an email's headers for phishing indicators.

Checks performed (headers only, body is never inspected):
  * SPF / DKIM / DMARC results from the Authentication-Results header
  * From domain vs Return-Path domain mismatch
  * Reply-To domain different from the From domain
  * Lookalike domains (e.g. paypa1, micros0ft) and brand names used in the
    display name while the sending domain is unrelated to that brand

Output: a risk score 0-100, a verdict
  (Likely legitimate / Suspicious / Likely phishing) and the reasons.

Usage:
  python3 src/analyze_headers.py data/clean-corporate.eml
  python3 src/analyze_headers.py data/*.eml

Standard library only.
"""

import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

# Brand -> legitimate domain. Used only for lookalike / impersonation checks.
BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "outlook": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "gmail": "google.com",
    "netflix": "netflix.com",
    "chase": "chase.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
}

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                      "7": "t", "@": "a", "$": "s"})


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(">") if "@" in address else ""


def auth_result(msg, mechanism: str):
    """Return the result token (pass/fail/softfail/none/...) or None."""
    for header in msg.get_all("Authentication-Results", []):
        m = re.search(rf"\b{mechanism}\s*=\s*([a-z]+)", str(header), re.I)
        if m:
            return m.group(1).lower()
    return None


def registrable(domain: str) -> str:
    """Last two labels, e.g. mail.acmecorp.com -> acmecorp.com (simplified)."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def looks_like_brand(domain: str):
    """Return the brand a domain appears to imitate, or None."""
    base = registrable(domain).split(".")[0]
    normalized = base.translate(LEET)
    for brand in BRANDS:
        if brand.replace(" ", "") in normalized and domain != BRANDS[brand]:
            return brand
    return None


def analyze(path: Path):
    msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    reasons = []
    score = 0

    def add(points, text):
        nonlocal score
        score += points
        reasons.append(f"(+{points}) {text}")

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = domain_of(from_addr)
    return_path_domain = domain_of(parseaddr(str(msg.get("Return-Path", "")))[1])
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    reply_domain = domain_of(reply_addr)

    # --- Authentication results -------------------------------------------
    dmarc = auth_result(msg, "dmarc")
    if dmarc == "fail":
        add(40, "DMARC check FAILED")
    elif dmarc in (None, "none"):
        add(10, "No DMARC result recorded (policy absent or not evaluated)")

    spf = auth_result(msg, "spf")
    if spf == "fail":
        add(25, "SPF check FAILED (sending IP not authorized for the domain)")
    elif spf == "softfail":
        add(10, "SPF softfail (domain neither confirms nor denies the sender)")
    elif spf in (None, "none"):
        add(10, "No SPF result recorded")

    dkim = auth_result(msg, "dkim")
    if dkim == "fail":
        add(20, "DKIM signature FAILED validation")
    elif dkim in (None, "none"):
        add(10, "No DKIM signature/result present")

    # --- Alignment checks ---------------------------------------------------
    if return_path_domain and from_domain \
            and registrable(return_path_domain) != registrable(from_domain):
        add(15, f"Return-Path domain ({return_path_domain}) does not match "
                f"From domain ({from_domain})")

    if reply_domain and from_domain \
            and registrable(reply_domain) != registrable(from_domain):
        add(20, f"Reply-To domain ({reply_domain}) differs from From domain "
                f"({from_domain}) - replies would go to a different domain")

    # --- Impersonation / lookalike checks ----------------------------------
    brand_in_domain = looks_like_brand(from_domain)
    if brand_in_domain:
        add(30, f"From domain ({from_domain}) looks like a lookalike of "
                f"'{brand_in_domain}' (legitimate: {BRANDS[brand_in_domain]})")

    display = from_name.lower()
    for brand, legit in BRANDS.items():
        if brand in display and registrable(from_domain) != legit \
                and brand_in_domain != brand:
            add(25, f"Display name claims '{from_name}' but the sending "
                    f"domain ({from_domain}) is not {legit}")
            break

    score = min(score, 100)
    if score >= 55:
        verdict = "Likely phishing"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Likely legitimate"

    return {
        "file": path.name,
        "from": str(msg.get("From", "")),
        "subject": str(msg.get("Subject", "")),
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
        "score": score, "verdict": verdict, "reasons": reasons,
    }


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    for name in argv[1:]:
        path = Path(name)
        if not path.is_file():
            print(f"skip: {name} not found")
            continue
        r = analyze(path)
        print(f"=== {r['file']}")
        print(f"From:    {r['from']}")
        print(f"Subject: {r['subject']}")
        print(f"Auth:    SPF={r['spf'] or 'n/a'}  DKIM={r['dkim'] or 'n/a'}  "
              f"DMARC={r['dmarc'] or 'n/a'}")
        print(f"Risk score: {r['score']}/100  ->  Verdict: {r['verdict']}")
        if r["reasons"]:
            print("Reasons:")
            for reason in r["reasons"]:
                print(f"  - {reason}")
        else:
            print("Reasons: none - all checks passed")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
