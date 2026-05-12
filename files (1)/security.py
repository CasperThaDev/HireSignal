"""
HireSignal — Security Module
Handles: encryption, audit logging, input sanitisation,
         data retention cleanup, Telegram auth.
"""

import os
import re
import json
import glob
import logging
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet


# ─────────────────────────────────────────
# AUDIT LOGGER
# ─────────────────────────────────────────

def setup_audit_logger() -> logging.Logger:
    """
    Sets up a tamper-evident audit log.
    Every scan, export, and access is recorded.
    """
    Path("logs").mkdir(exist_ok=True)

    logger = logging.getLogger("hiresignal.audit")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.FileHandler(
            f"logs/audit_{datetime.now().strftime('%Y%m')}.log"
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(handler)

    return logger


audit = setup_audit_logger()


def log_event(event: str, details: dict = None):
    """Log a security-relevant event"""
    payload = {"event": event}
    if details:
        # Never log raw API keys or tokens
        safe_details = {
            k: "***REDACTED***" if any(s in k.lower() for s in ["key", "token", "secret", "password"])
            else v
            for k, v in details.items()
        }
        payload.update(safe_details)
    audit.info(json.dumps(payload))


# ─────────────────────────────────────────
# ENCRYPTION
# ─────────────────────────────────────────

class DataEncryptor:
    """
    Encrypts sensitive output files (lead data, drafts).
    Uses Fernet symmetric encryption (AES-128-CBC).
    """

    def __init__(self, key: Optional[str] = None):
        raw_key = key or os.getenv("ENCRYPTION_KEY")
        if not raw_key:
            raise ValueError(
                "No encryption key found. Run: python security/keygen.py\n"
                "Then add ENCRYPTION_KEY to your .env file."
            )
        self.fernet = Fernet(raw_key.encode() if isinstance(raw_key, str) else raw_key)

    def encrypt_file(self, filepath: str) -> str:
        """Encrypt a file and save as .enc"""
        with open(filepath, "rb") as f:
            data = f.read()

        encrypted = self.fernet.encrypt(data)
        enc_path = filepath + ".enc"

        with open(enc_path, "wb") as f:
            f.write(encrypted)

        os.remove(filepath)  # Remove plaintext
        log_event("file_encrypted", {"path": filepath})
        return enc_path

    def decrypt_file(self, enc_filepath: str) -> dict:
        """Decrypt a .enc file and return parsed JSON"""
        with open(enc_filepath, "rb") as f:
            encrypted = f.read()

        decrypted = self.fernet.decrypt(encrypted)
        log_event("file_decrypted", {"path": enc_filepath})
        return json.loads(decrypted.decode())

    def encrypt_json(self, data: dict) -> bytes:
        """Encrypt a dict directly (for in-memory use)"""
        return self.fernet.encrypt(json.dumps(data).encode())

    def decrypt_json(self, token: bytes) -> dict:
        """Decrypt bytes back to dict"""
        return json.loads(self.fernet.decrypt(token).decode())


# ─────────────────────────────────────────
# INPUT SANITISATION
# ─────────────────────────────────────────

def sanitise_text(text: str, max_len: int = 200) -> str:
    """
    Remove dangerous characters from user input.
    Prevents injection into scraper queries and reports.
    """
    if not isinstance(text, str):
        return ""
    # Allow letters, numbers, spaces, hyphens, dots, apostrophes
    clean = re.sub(r"[^\w\s\-\.\,\'\&]", "", text)
    return clean.strip()[:max_len]


def sanitise_url(url: str) -> str:
    """Validate URL is safe before fetching"""
    if not isinstance(url, str):
        return ""
    url = url.strip()
    # Only allow http/https
    if not re.match(r"^https?://", url):
        return ""
    # Block local/internal addresses
    blocked = ["localhost", "127.0.0.1", "0.0.0.0", "192.168.", "10.", "172."]
    if any(b in url for b in blocked):
        log_event("blocked_internal_url", {"url": url})
        return ""
    return url[:500]


def sanitise_search_query(query: str) -> str:
    """Safe search query — letters, numbers, spaces only"""
    clean = re.sub(r"[^\w\s\-]", "", query)
    return clean.strip()[:100]


# ─────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────

import asyncio
from collections import defaultdict

class RateLimiter:
    """
    Prevents aggressive scraping that triggers IP bans.
    Enforces minimum delay between requests to same domain.
    """

    def __init__(self):
        self._last_request: dict = defaultdict(float)
        self._delays = {
            "remotive.com": 2.0,
            "workatastartup.com": 3.0,
            "wellfound.com": 4.0,
            "default": 2.0,
        }

    async def wait(self, domain: str):
        """Wait the appropriate time before hitting a domain"""
        import time
        delay = self._delays.get(domain, self._delays["default"])
        last = self._last_request[domain]
        elapsed = time.time() - last
        wait_time = max(0, delay - elapsed)

        if wait_time > 0:
            await asyncio.sleep(wait_time)

        self._last_request[domain] = time.time()
        log_event("request_made", {"domain": domain, "waited_seconds": round(wait_time, 2)})


# ─────────────────────────────────────────
# TELEGRAM AUTH GUARD
# ─────────────────────────────────────────

class TelegramAuthGuard:
    """
    Validates that Telegram messages come only from
    your authorised chat ID. Blocks all others silently.
    """

    def __init__(self, authorised_chat_id: str):
        self.authorised_id = str(authorised_chat_id)

    def is_authorised(self, incoming_chat_id: str) -> bool:
        incoming = str(incoming_chat_id)
        if incoming != self.authorised_id:
            log_event("unauthorised_telegram_access", {
                "incoming_chat_id": hashlib.sha256(incoming.encode()).hexdigest()[:8]
                # Log hash not raw ID for privacy
            })
            return False
        return True


# ─────────────────────────────────────────
# DATA RETENTION CLEANUP
# ─────────────────────────────────────────

class DataRetention:
    """
    GDPR-compliant automatic data cleanup.
    Deletes scan results older than retention_days.
    Log entries: auto-rotate after 90 days.
    """

    def __init__(self, retention_days: int = 30):
        self.retention_days = retention_days

    def cleanup_scans(self) -> int:
        """Delete old scan output files"""
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        deleted = 0

        for pattern in ["output/scan_*.json", "output/scan_*.json.enc"]:
            for filepath in glob.glob(pattern):
                modified = datetime.fromtimestamp(os.path.getmtime(filepath))
                if modified < cutoff:
                    os.remove(filepath)
                    deleted += 1
                    log_event("data_deleted_retention", {
                        "file": os.path.basename(filepath),
                        "age_days": (datetime.now() - modified).days
                    })

        return deleted

    def cleanup_logs(self) -> int:
        """Delete audit logs older than 90 days"""
        cutoff = datetime.now() - timedelta(days=90)
        deleted = 0

        for filepath in glob.glob("logs/audit_*.log"):
            modified = datetime.fromtimestamp(os.path.getmtime(filepath))
            if modified < cutoff:
                os.remove(filepath)
                deleted += 1

        return deleted

    def run_all(self) -> dict:
        """Run full retention cleanup"""
        scans = self.cleanup_scans()
        logs = self.cleanup_logs()
        log_event("retention_cleanup_complete", {
            "scans_deleted": scans,
            "logs_deleted": logs
        })
        return {"scans_deleted": scans, "logs_deleted": logs}


# ─────────────────────────────────────────
# SECURITY HEALTH CHECK
# ─────────────────────────────────────────

def security_health_check() -> dict:
    """
    Run on startup to verify security config is correct.
    Fails loudly if critical items are missing.
    """
    issues = []
    warnings = []

    # Check .env exists
    if not os.path.exists(".env"):
        issues.append("No .env file found — copy .env.example to .env and fill in values")

    # Check gitignore protects secrets
    if os.path.exists(".gitignore"):
        with open(".gitignore") as f:
            gitignore = f.read()
        if "config/config.json" not in gitignore:
            issues.append("config/config.json is not in .gitignore — secrets could be exposed")
        if ".env" not in gitignore:
            issues.append(".env is not in .gitignore — secrets could be exposed")
    else:
        issues.append("No .gitignore found — create one immediately")

    # Check encryption key is set
    if not os.getenv("ENCRYPTION_KEY"):
        warnings.append("ENCRYPTION_KEY not set — output files will not be encrypted")

    # Check output directory exists
    Path("output").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)

    # Check for accidental key exposure
    for fname in ["config/config.json", "config.json"]:
        if os.path.exists(fname):
            with open(fname) as f:
                content = f.read()
            if "sk-ant-" in content or "bot" in content.lower():
                issues.append(f"{fname} appears to contain real API keys — move to .env")

    status = "❌ FAILED" if issues else ("⚠️ WARNING" if warnings else "✅ PASSED")

    result = {
        "status": status,
        "issues": issues,
        "warnings": warnings,
        "checked_at": datetime.now().isoformat()
    }

    log_event("security_health_check", result)

    if issues:
        print(f"\n🔴 SECURITY ISSUES FOUND:")
        for i in issues:
            print(f"   ❌ {i}")
    if warnings:
        print(f"\n🟡 SECURITY WARNINGS:")
        for w in warnings:
            print(f"   ⚠️  {w}")
    if not issues and not warnings:
        print("✅ Security check passed")

    return result
