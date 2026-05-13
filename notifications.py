"""
HireSignal — Delivery Layer (Security Patched)
Telegram auth guard applied — only authorised chat ID receives alerts.
"""

import httpx
import json
import os
from core.monitor import HireTrigger
from security.security import TelegramAuthGuard, log_event

SIGNAL_EMOJI = {"high": "🔴", "medium": "🟡", "low": "🟢"}
SIGNAL_LABEL = {"high": "HOT LEAD", "medium": "WARM LEAD", "low": "WATCH"}


class TelegramDelivery:

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        self.auth_guard = TelegramAuthGuard(chat_id)

    async def send_trigger_alert(self, trigger: HireTrigger, drafts: dict = None):
        emoji = SIGNAL_EMOJI.get(trigger.signal_strength, "⚪")
        label = SIGNAL_LABEL.get(trigger.signal_strength, "SIGNAL")

        message = f"""
{emoji} *{label}* — HireSignal

🏢 *Company:* {trigger.company}
👤 *Role:* {trigger.role}
📍 *Location:* {trigger.location}
📅 *Days in Role:* {trigger.days_in_role}
💰 *Funding:* {trigger.funding_stage or "Unknown"}
🔗 *Source:* [{trigger.source}]({trigger.url})
"""
        if drafts and "cold_dm" in drafts:
            message += f"\n─────────────────\n📝 *Cold DM Draft:*\n_{drafts['cold_dm']}_\n"

        await self._send_message(message)
        log_event("alert_sent", {"company": trigger.company, "signal": trigger.signal_strength})

    async def send_daily_digest(self, triggers: list, summary: dict):
        high = summary.get("high_signal", 0)
        total = summary.get("total", 0)

        header = f"""
📊 *HireSignal Daily Digest*
━━━━━━━━━━━━━━━━━━━━
🔴 Hot Leads: {high}
📈 Total Signals: {total}
🕐 Scanned: {summary.get('last_scan', 'now')}
━━━━━━━━━━━━━━━━━━━━
"""
        await self._send_message(header)

        top = [t for t in triggers if t.signal_strength == "high"][:5]
        for trigger in top:
            await self.send_trigger_alert(trigger)

    async def _send_message(self, text: str, incoming_chat_id: str = None):
        """Send message — validates auth if incoming_chat_id provided"""
        # If processing an incoming message, verify it's from authorised chat
        if incoming_chat_id and not self.auth_guard.is_authorised(incoming_chat_id):
            return  # Silently block unauthorised senders

        url = f"{self.base_url}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                log_event("telegram_send_error", {"status": resp.status_code})


class EmailDelivery:

    def __init__(self, sender_email: str, app_password: str, recipient: str):
        self.sender = sender_email
        self.password = app_password
        self.recipient = recipient

    def send_digest(self, triggers: list, summary: dict):
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        html = self._build_html(triggers, summary)
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"HireSignal: {summary.get('high_signal', 0)} Hot Leads Today"
        msg["From"] = self.sender
        msg["To"] = self.recipient
        msg.attach(MIMEText(html, "html"))

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.sender, self.password)
                server.sendmail(self.sender, self.recipient, msg.as_string())
            log_event("email_digest_sent", {"recipient": self.recipient})
        except Exception as e:
            log_event("email_send_error", {"error": str(e)})

    def _build_html(self, triggers: list, summary: dict) -> str:
        rows = ""
        for t in triggers[:20]:
            emoji = SIGNAL_EMOJI.get(t.signal_strength, "⚪")
            rows += f"""
            <tr>
                <td>{emoji} {t.signal_strength.upper()}</td>
                <td><strong>{t.company}</strong></td>
                <td>{t.role}</td>
                <td>{t.days_in_role} days</td>
                <td>{t.funding_stage or "—"}</td>
                <td><a href="{t.url}">View →</a></td>
            </tr>"""

        return f"""
        <html><body style="font-family: monospace; background: #0a0a0a; color: #e0e0e0; padding: 20px;">
        <h2 style="color: #00ff88;">📡 HireSignal Daily Digest</h2>
        <p>Total: <strong>{summary.get('total', 0)}</strong> |
           Hot: <strong style="color:#ff4444">{summary.get('high_signal', 0)}</strong></p>
        <table border="1" style="border-collapse:collapse; width:100%; font-size:13px;">
            <tr style="background:#1a1a1a;">
                <th>Signal</th><th>Company</th><th>Role</th>
                <th>Days</th><th>Funding</th><th>Link</th>
            </tr>{rows}
        </table>
        <p style="color:#666; font-size:11px;">Powered by HireSignal</p>
        </body></html>"""
