import requests
import re
import json
import hashlib
import os
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHANNEL_ID = int(os.getenv("CHANNEL_ID", "-1002325683219"))

SCANNER_URL = "https://raw.githubusercontent.com/new493370/MySccan/refs/heads/main/output/best_ips.txt"
MAX_IPS_PER_POST = 100
MAX_POSTS_PER_RUN = 20
SENT_HISTORY_FILE = "sent_ips.json"

class IPExtractor:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.sent_ips = self.load_sent_history()

    def load_sent_history(self) -> Dict:
        if os.path.exists(SENT_HISTORY_FILE):
            try:
                with open(SENT_HISTORY_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for k, v in data.items():
                        data[k] = datetime.fromisoformat(v)
                    return data
            except:
                return {}
        return {}

    def save_sent_history(self):
        try:
            with open(SENT_HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump({k: v.isoformat() for k, v in self.sent_ips.items()}, f, ensure_ascii=False, indent=2)
        except:
            pass

    def is_ip_sent(self, ip: str) -> bool:
        h = hashlib.md5(ip.encode()).hexdigest()
        if h in self.sent_ips:
            if datetime.now() - self.sent_ips[h] < timedelta(hours=24):
                return True
            else:
                del self.sent_ips[h]
                self.save_sent_history()
        return False

    def mark_as_sent(self, ip: str):
        h = hashlib.md5(ip.encode()).hexdigest()
        self.sent_ips[h] = datetime.now()
        self.save_sent_history()

    def extract_ip_from_line(self, line: str) -> Optional[str]:
        match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+', line.strip())
        if match:
            return match.group(1)
        return None

    def fetch_ips(self) -> List[str]:
        try:
            response = self.session.get(SCANNER_URL, timeout=30)
            if response.status_code == 200:
                ips = []
                for line in response.text.splitlines():
                    ip = self.extract_ip_from_line(line)
                    if ip and not self.is_ip_sent(ip):
                        ips.append(ip)
                return ips
            return []
        except Exception as e:
            logger.error(f"Error fetching IPs: {e}")
            return []

class TelegramSender:
    def __init__(self, token: str, chat_id: int):
        if not token:
            raise ValueError("BOT_TOKEN is required")
        self.api = f"https://api.telegram.org/bot{token}"
        self.chat_id = chat_id

    def send_message(self, text: str, reply_markup=None) -> bool:
        try:
            data = {
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            }
            if reply_markup:
                data["reply_markup"] = json.dumps(reply_markup)
            r = requests.post(self.api + "/sendMessage", data=data, timeout=30)
            return r.status_code == 200
        except Exception as e:
            logger.error(f"Send error: {e}")
            return False

    def format_ips_block(self, ips: List[str]) -> str:
        ips_text = "\n".join(ips)
        return f"<blockquote expandable><code>{ips_text}</code></blockquote>"

    def create_caption(self, ips: List[str]) -> str:
        ips_block = self.format_ips_block(ips)
        return f"""🅰️🆁🅸🆂🆃🅰️ 🅸🅿️
➖➖➖➖➖➖➖➖
{ips_block}
➖➖➖➖➖➖➖➖
👈 اگر به لیست آی‌‌پی متصل هستید بهش دست نزنید ، فقط زمانی‌که آی‌پی شما فیلتر شد یا از کار افتاد سراغ این آی‌پی‌های جدید بیایید و تست کنید.

‼️ <b>جهت جواب‌دهی هرچه بهتر، قبل از استفاده ipها رو کپی و با Vpn خاموش اسکن کنید.</b>

🔹 <a href="https://t.me/aristapnel/34613?single">اسکنر اول</a>
🔹 <a href="https://t.me/aristapnel/34474">اسکنر دوم</a>
🔹 <a href="https://t.me/aristapnel/35602">اسکنر سوم</a>
➖➖➖➖➖➖➖➖
<blockquote>@aristapnel</blockquote>
➖➖➖➖➖➖➖➖
#Arista #ip #clean_ip #ٱی‌پی_تمیز"""

    def send_ips_batch(self, ips: List[str]) -> bool:
        if not ips:
            return False
        return self.send_message(self.create_caption(ips))

class IPScheduler:
    def __init__(self):
        self.extractor = IPExtractor()
        if not BOT_TOKEN:
            raise ValueError("BOT_TOKEN environment variable not set")
        self.sender = TelegramSender(BOT_TOKEN, CHANNEL_ID)

    def run(self):
        all_ips = self.extractor.fetch_ips()
        if not all_ips:
            logger.info("No new IPs found")
            return
        
        logger.info(f"Found {len(all_ips)} new IPs")
        posts_count = 0
        for i in range(0, len(all_ips), MAX_IPS_PER_POST):
            if posts_count >= MAX_POSTS_PER_RUN:
                logger.info(f"Reached max posts limit ({MAX_POSTS_PER_RUN})")
                break
            batch = all_ips[i:i + MAX_IPS_PER_POST]
            if self.sender.send_ips_batch(batch):
                for ip in batch:
                    self.extractor.mark_as_sent(ip)
                posts_count += 1
                logger.info(f"Sent batch {posts_count} with {len(batch)} IPs")
            else:
                logger.error(f"Failed to send batch {posts_count + 1}")

def main():
    try:
        scheduler = IPScheduler()
        scheduler.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
