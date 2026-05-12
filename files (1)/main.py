"""
HireSignal — Main Runner (Security Patched)
Loads secrets from .env, runs security health check on startup,
encrypts output, runs data retention cleanup automatically.

Usage:
  python main.py --scan          # Scan for new triggers
  python main.py --scan --draft  # Scan + AI outreach drafts
  python main.py --cleanup       # Run data retention cleanup
  python main.py --security      # Run security health check
"""

import asyncio
import argparse
import json
import os
from datetime import datetime
from pathlib import Path

# Load .env FIRST before any other imports
from dotenv import load_dotenv
load_dotenv()

from core.monitor import HireSignalMonitor
from scrapers.job_boards import JobBoardScraper
from ai.outreach import batch_generate
from delivery.notifications import TelegramDelivery
from security.security import (
    security_health_check,
    DataEncryptor,
    DataRetention,
    log_event,
    sanitise_text,
)


def load_config() -> dict:
    """Load config from environment variables only — no plaintext config files"""
    return {
        "telegram_token": os.getenv("TELEGRAM_BOT_TOKEN", ""),
        "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", ""),
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY", ""),
        "encryption_key": os.getenv("ENCRYPTION_KEY", ""),
        "max_days": int(os.getenv("MAX_DAYS", "90")),
        "min_signal": os.getenv("MIN_SIGNAL", "medium"),
        "your_product": sanitise_text(os.getenv("YOUR_PRODUCT", "HireSignal")),
        "your_value_prop": sanitise_text(
            os.getenv("YOUR_VALUE_PROP", "identifies $9k/mo in automation gaps"),
            max_len=300
        ),
    }


async def run_scan(config: dict, generate_drafts: bool = False):
    """Main scan routine with encryption and audit logging"""
    print(f"\n🔍 HireSignal Scan — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 50)

    log_event("scan_started", {"generate_drafts": generate_drafts})

    monitor = HireSignalMonitor(config)
    scraper = JobBoardScraper(monitor)

    print("📡 Scanning job boards...")
    triggers = await scraper.scan_all()
    print(f"   Found {len(triggers)} new signals")

    high = monitor.filter_by_signal("high")
    print(f"   🔴 High signal: {len(high)}")
    print(f"   🟡 Medium signal: {len([t for t in triggers if t.signal_strength == 'medium'])}")

    drafts = {}
    if generate_drafts and triggers:
        print("\n✍️  Generating AI outreach drafts...")
        drafts = await batch_generate(triggers, limit=10)
        print(f"   Generated {len(drafts)} drafts")

    # Save output
    Path("output").mkdir(exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M')
    output_path = f"output/scan_{timestamp}.json"

    output_data = {
        "summary": monitor.summary(),
        "triggers": [t.to_dict() for t in triggers],
        "drafts": drafts
    }

    # Encrypt if key is available
    if config.get("encryption_key"):
        try:
            encryptor = DataEncryptor(config["encryption_key"])
            with open(output_path, "w") as f:
                json.dump(output_data, f, indent=2)
            enc_path = encryptor.encrypt_file(output_path)
            print(f"\n🔐 Encrypted output saved to {enc_path}")
        except Exception as e:
            print(f"\n⚠️  Encryption failed ({e}) — saving plaintext")
            with open(output_path, "w") as f:
                json.dump(output_data, f, indent=2)
    else:
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\n💾 Saved to {output_path}")
        print("   ⚠️  Tip: Set ENCRYPTION_KEY in .env to encrypt output files")

    # Telegram alerts
    if config.get("telegram_token") and config.get("telegram_chat_id"):
        print("\n📱 Sending Telegram alerts...")
        telegram = TelegramDelivery(config["telegram_token"], config["telegram_chat_id"])
        await telegram.send_daily_digest(triggers, monitor.summary())

    # Auto-run retention cleanup
    retention = DataRetention(retention_days=30)
    cleaned = retention.run_all()
    if cleaned["scans_deleted"] > 0:
        print(f"\n🗑️  Retention cleanup: deleted {cleaned['scans_deleted']} old scan(s)")

    log_event("scan_completed", {
        "triggers_found": len(triggers),
        "high_signal": len(high),
        "drafts_generated": len(drafts),
    })

    print("\n✅ Scan complete")
    print(f"   Summary: {json.dumps(monitor.summary(), indent=2)}")
    return triggers, monitor


def print_banner():
    print("""
╔══════════════════════════════════════════╗
║   📡 H I R E S I G N A L               ║
║   RevOps Trigger Monitor v1.1 (Secure)  ║
║   github.com/yourusername/hiresignal    ║
╚══════════════════════════════════════════╝
""")


async def main():
    print_banner()

    parser = argparse.ArgumentParser(description="HireSignal — RevOps Trigger Monitor")
    parser.add_argument("--scan", action="store_true", help="Scan for new hire triggers")
    parser.add_argument("--draft", action="store_true", help="Generate AI outreach drafts")
    parser.add_argument("--cleanup", action="store_true", help="Run data retention cleanup")
    parser.add_argument("--security", action="store_true", help="Run security health check")
    parser.add_argument("--signal", default="medium", choices=["low", "medium", "high"])
    args = parser.parse_args()

    # Always run security check on startup
    print("🔐 Running security health check...")
    health = security_health_check()
    if health["issues"]:
        print("\n⛔ Fix security issues before running scans.\n")
        return

    config = load_config()

    if args.security:
        return

    if args.cleanup:
        retention = DataRetention()
        result = retention.run_all()
        print(f"✅ Cleanup complete: {result}")
        return

    if args.scan:
        await run_scan(config, generate_drafts=args.draft)
    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
