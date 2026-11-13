# Phishing Header Analyzer

A dependency-free Python tool that scores an email's **headers** for phishing indicators — authentication failures, domain misalignment, and brand impersonation — and returns a 0–100 risk score with a verdict and the reasoning behind it.

## Why it matters

Most phishing triage starts with headers: did SPF/DKIM/DMARC actually pass, does the Reply-To quietly send responses to a different domain, and is the sender domain a lookalike of a brand the display name claims to be? Those checks are quick but tedious to do by hand in an email client. This tool runs them in one pass and shows its work — every point in the score is tied to a specific, listed reason, which is exactly what an analyst needs before escalating or closing a reported phish.

## Checks and scoring

| Signal | Points |
|--------|--------|
| DMARC result is `fail` | +40 |
| SPF result is `fail` | +25 |
| DKIM result is `fail` | +20 |
| Lookalike sending domain (e.g. `paypa1-secure.com` imitating PayPal) | +30 |
| Display name claims a brand the sending domain doesn't belong to | +25 |
| Reply-To domain differs from From domain | +20 |
| Return-Path domain differs from From domain | +15 |
| SPF `softfail`, or missing SPF/DKIM/DMARC result | +10 each |

Verdicts: **0–24** Likely legitimate · **25–54** Suspicious · **55–100** Likely phishing. The score is capped at 100.

Authentication results are read from the message's `Authentication-Results` header (the values a receiving mail server recorded). Lookalike detection compares the sending domain against a small built-in brand list (PayPal, Microsoft, Apple, Amazon, Google, Netflix, major banks) and normalizes common leetspeak substitutions (`0→o`, `1→l`, …) before matching.

## How to run

Python 3.9+, standard library only — nothing to install.

```bash
python3 src/analyze_headers.py data/clean-corporate.eml
python3 src/analyze_headers.py data/clean-corporate.eml data/obvious-phish.eml data/borderline-vendor.eml
```

Pass any `.eml` files as arguments; each is scored and reported in turn.

## Sample output (actual run against the three bundled messages)

```text
=== clean-corporate.eml
From:    Sarah Linden <sarah.linden@acmecorp.com>
Subject: Q4 access review - evidence due Friday
Auth:    SPF=pass  DKIM=pass  DMARC=pass
Risk score: 0/100  ->  Verdict: Likely legitimate
Reasons: none - all checks passed

=== obvious-phish.eml
From:    PayPal Security Team <alert@paypa1-secure.com>
Subject: URGENT: Your account has been limited - verify within 24 hours
Auth:    SPF=fail  DKIM=fail  DMARC=fail
Risk score: 100/100  ->  Verdict: Likely phishing
Reasons:
  - (+40) DMARC check FAILED
  - (+25) SPF check FAILED (sending IP not authorized for the domain)
  - (+20) DKIM signature FAILED validation
  - (+15) Return-Path domain (mailer-784.xyz) does not match From domain (paypa1-secure.com)
  - (+20) Reply-To domain (paypa1-helpdesk.com) differs from From domain (paypa1-secure.com)
  - (+30) From domain (paypa1-secure.com) looks like a lookalike of 'paypal' (legitimate: paypal.com)

=== borderline-vendor.eml
From:    BrightMart Deals <deals@brightmart-promos.com>
Subject: This week at BrightMart: 20% off home essentials
Auth:    SPF=softfail  DKIM=none  DMARC=none
Risk score: 50/100  ->  Verdict: Suspicious
Reasons:
  - (+10) No DMARC result recorded (policy absent or not evaluated)
  - (+10) SPF softfail (domain neither confirms nor denies the sender)
  - (+10) No DKIM signature/result present
  - (+20) Reply-To domain (brightmart-mail.net) differs from From domain (brightmart-promos.com)
```

The three samples were chosen to exercise the full range:

- **clean-corporate.eml** — internal corporate mail; SPF/DKIM/DMARC all pass, all domains aligned → **0, Likely legitimate**.
- **obvious-phish.eml** — a "PayPal" alert from a lookalike domain with failed authentication on every mechanism and both alignment checks tripped → **100, Likely phishing** (raw signals total 150, capped at 100).
- **borderline-vendor.eml** — a marketing email from a third-party sender: SPF softfail, no DKIM, no DMARC result, and an unsubscribe Reply-To on a sibling domain. Nothing proves malice, but nothing vouches for it either → **50, Suspicious**.

## Files

```text
src/analyze_headers.py     the analyzer (parsing, checks, scoring, verdict)
data/clean-corporate.eml   sample: legitimate internal mail
data/obvious-phish.eml     sample: textbook brand-impersonation phish
data/borderline-vendor.eml sample: weakly-authenticated marketing mail
```

## Honest limitations

- **It trusts the `Authentication-Results` header already in the message** — it does not perform live SPF/DKIM/DMARC lookups, so a message that was never stamped by a receiving server scores "missing result" points even if it is genuine.
- **Headers only.** Links, attachments, and body content (urgency language, credential-harvest forms) are out of scope and often carry the strongest phishing signals.
- **Alignment is judged on the registrable domain** using a simplified last-two-labels rule, which is wrong for domains under multi-part public suffixes (e.g. `co.uk`) and doesn't evaluate DMARC organizational-domain policy nuances.
- **The brand list is small and the weights are judgment calls**, not trained or tuned against a labeled corpus. Legitimate bulk senders frequently trip the Return-Path and Reply-To checks.
- **Sample messages are fictional**, written for this demo; scores on real mail will vary and the verdict is a triage aid, not proof.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Araf Abubakar.
