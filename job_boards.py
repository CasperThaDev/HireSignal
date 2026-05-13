"""
HireSignal — Scrapers (Security Patched)
Rate limiting + input sanitisation applied.
"""

import asyncio
import httpx
from datetime import datetime
from typing import Optional
from bs4 import BeautifulSoup
from core.monitor import HireTrigger, HireSignalMonitor
from security.security import RateLimiter, sanitise_text, sanitise_url, log_event
import hashlib

rate_limiter = RateLimiter()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; HireSignalBot/1.0; "
        "+https://github.com/yourusername/hiresignal)"
    )
}


class JobBoardScraper:

    TARGET_KEYWORDS = [
        "revops", "rev ops", "revenue operations",
        "head of growth", "growth lead",
        "sales operations", "marketing operations",
        "chief revenue", "vp of revenue", "director of revenue"
    ]

    def __init__(self, monitor: HireSignalMonitor):
        self.monitor = monitor

    def _is_target_role(self, title: str) -> bool:
        return any(kw in title.lower() for kw in self.TARGET_KEYWORDS)

    def _days_since(self, date_str: str) -> int:
        if not date_str:
            return 30
        try:
            pub_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            return (datetime.now(pub_date.tzinfo) - pub_date).days
        except Exception:
            return 30

    async def scan_remotive(self, role_query: str = "revenue operations") -> list:
        triggers = []
        # Sanitise query before using in URL
        safe_query = sanitise_text(role_query).replace(" ", "+")
        url = f"https://remotive.com/api/remote-jobs?search={safe_query}&limit=50"

        # Rate limit
        await rate_limiter.wait("remotive.com")

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, headers=HEADERS)
                data = resp.json()

                for job in data.get("jobs", []):
                    title = sanitise_text(job.get("title", ""))
                    company = sanitise_text(job.get("company_name", "Unknown"))
                    location = sanitise_text(job.get("candidate_required_location", "Remote"))
                    job_url = sanitise_url(job.get("url", ""))
                    pub_date = job.get("publication_date", "")

                    if not self._is_target_role(title):
                        continue

                    days = self._days_since(pub_date)
                    if days > 90:
                        continue

                    uid = hashlib.md5(f"{company}:{title}".encode()).hexdigest()[:12]
                    if uid in self.monitor.seen_ids:
                        continue

                    trigger = HireTrigger(
                        id=uid,
                        company=company,
                        role=title,
                        person_name=None,
                        location=location,
                        source="Remotive",
                        url=job_url,
                        detected_at=datetime.now().isoformat(),
                        days_in_role=days,
                        company_size=None,
                        funding_stage=None,
                    )
                    trigger.signal_strength = self.monitor._calculate_signal_strength(trigger)
                    triggers.append(trigger)
                    self.monitor.seen_ids.add(uid)

            log_event("scrape_complete", {"source": "remotive", "found": len(triggers)})

        except Exception as e:
            log_event("scrape_error", {"source": "remotive", "error": str(e)})
            print(f"[Remotive] Error: {e}")

        return triggers

    async def scan_ycombinator_jobs(self) -> list:
        triggers = []
        await rate_limiter.wait("workatastartup.com")

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    "https://www.workatastartup.com/jobs?role=operations&remote=true",
                    headers=HEADERS
                )
                soup = BeautifulSoup(resp.text, "html.parser")
                job_cards = soup.select(".job-card, [class*='job']")

                for card in job_cards[:30]:
                    title_el = card.select_one("h3, .job-title, [class*='title']")
                    company_el = card.select_one(".company-name, [class*='company']")

                    if not title_el or not company_el:
                        continue

                    title = sanitise_text(title_el.get_text(strip=True))
                    company = sanitise_text(company_el.get_text(strip=True))

                    if not self._is_target_role(title):
                        continue

                    uid = hashlib.md5(f"yc:{company}:{title}".encode()).hexdigest()[:12]
                    if uid in self.monitor.seen_ids:
                        continue

                    trigger = HireTrigger(
                        id=uid,
                        company=company,
                        role=title,
                        person_name=None,
                        location="Remote / US",
                        source="YC Work at a Startup",
                        url="https://workatastartup.com",
                        detected_at=datetime.now().isoformat(),
                        days_in_role=7,
                        company_size="11-50",
                        funding_stage="Seed / Series A",
                    )
                    trigger.signal_strength = self.monitor._calculate_signal_strength(trigger)
                    triggers.append(trigger)
                    self.monitor.seen_ids.add(uid)

            log_event("scrape_complete", {"source": "yc_jobs", "found": len(triggers)})

        except Exception as e:
            log_event("scrape_error", {"source": "yc_jobs", "error": str(e)})
            print(f"[YC Jobs] Error: {e}")

        return triggers

    async def scan_all(self) -> list:
        results = await asyncio.gather(
            self.scan_remotive("revenue operations"),
            self.scan_remotive("head of growth"),
            self.scan_remotive("sales operations"),
            self.scan_ycombinator_jobs(),
            return_exceptions=True
        )

        all_triggers = []
        for result in results:
            if isinstance(result, list):
                all_triggers.extend(result)

        self.monitor.triggers.extend(all_triggers)
        return all_triggers
