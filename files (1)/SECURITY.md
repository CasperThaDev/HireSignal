# 🔐 HireSignal Security Guide

## What's Protected

| Layer | Protection | Status |
|---|---|---|
| API Keys | `.env` file + `.gitignore` | ✅ |
| Output files | Fernet AES encryption | ✅ |
| Scraper requests | Rate limiting per domain | ✅ |
| User input | Sanitisation + length limits | ✅ |
| Telegram bot | Chat ID auth guard | ✅ |
| Audit trail | Tamper-evident log file | ✅ |
| Data retention | Auto-delete after 30 days | ✅ |
| GitHub Actions | Secrets never printed to logs | ✅ |

---

## Setup Security (5 minutes)

### Step 1 — Protect your secrets
```bash
cp .env.example .env
# Fill in your real values in .env
# .env is already in .gitignore — it will NEVER be committed
```

### Step 2 — Generate encryption key
```bash
python security/keygen.py
# Copy the output line into your .env as ENCRYPTION_KEY=...
```

### Step 3 — Verify everything is safe
```bash
python main.py --security
# Should output: ✅ Security check passed
```

---

## What Each Security Layer Does

### `.env` + `.gitignore`
Your API keys live in `.env` only. The `.gitignore` ensures `.env` and `config/config.json` are never accidentally committed to GitHub.

### Fernet Encryption
All output files (scan results, lead data, outreach drafts) are encrypted using AES-128-CBC via Python's `cryptography` library. Without your `ENCRYPTION_KEY`, the files are unreadable.

### Rate Limiter
Enforces minimum delays between requests to each job board:
- Remotive: 2 seconds
- YC Jobs: 3 seconds
- Wellfound: 4 seconds

This prevents IP bans and respects each site's infrastructure.

### Input Sanitisation
All external data (company names, job titles, URLs) is sanitised before use:
- Strips dangerous characters
- Enforces maximum length limits
- Validates URLs are HTTPS and not internal addresses

### Telegram Auth Guard
Only your authorised `TELEGRAM_CHAT_ID` can receive alerts. Any other chat ID is silently rejected and logged.

### Audit Logging
Every scan, alert, encryption operation, and error is written to `logs/audit_YYYYMM.log` with timestamps. Sensitive values (API keys, tokens) are automatically redacted.

### Data Retention
Scan output files older than 30 days are automatically deleted. Audit logs rotate after 90 days. This keeps you GDPR-compliant by default.

---

## For Enterprise Clients

When a client asks about security, you can truthfully say:

> "HireSignal uses AES-128 encryption for all stored data, environment-based secret management, automated data retention (30-day default), a tamper-evident audit log, and rate-limited scraping that respects each source's infrastructure. All lead data is stored locally on your infrastructure and never sent to third parties except your configured delivery channels."

---

## Reporting a Security Issue

Found a vulnerability? Please email [your-email] rather than opening a public GitHub issue.
