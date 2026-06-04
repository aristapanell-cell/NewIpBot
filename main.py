import requests
import re
import json
import hashlib
import time
import os
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qs
import logging
from bs4 import BeautifulSoup

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

BOT_TOKEN = "8675979440:AAFh5BMI7tzA-ribwuZDLuqGSlN-BAgkO54"
CHANNEL_ID = -1002325683219

RAW_IPS_URL = "https://raw.githubusercontent.com/new493370/MySccan/refs/heads/main/output/best_ips.txt"

MAX_POSTS_FIRST_RUN = 20
IPS_PER_POST = 100
HISTORY_FILE = "sent_ips_history.json"
IP_PRIORITY_FILE = "ip_priority.json"


class IPExtractor:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.sent_history = self.load_history()
        self.ip_priority = self.load_priority()

    def load_history(self) -> Dict:
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for k, v in data.items():
                        data[k] = datetime.fromisoformat(v)
                    return data
            except:
                return {}
        return {}

    def save_history(self):
        try:
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump({k: v.isoformat() for k, v in self.sent_history.items()}, f, ensure_ascii=False, indent=2)
        except:
            pass

    def load_priority(self) -> Dict:
        if os.path.exists(IP_PRIORITY_FILE):
            try:
                with open(IP_PRIORITY_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for k, v in data.items():
                        data[k] = v
                    return data
            except:
                return {}
        return {}

    def save_priority(self):
        try:
            with open(IP_PRIORITY_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.ip_priority, f, ensure_ascii=False, indent=2)
        except:
            pass

    def fetch_raw_ips(self) -> Optional[str]:
        try:
            r = self.session.get(RAW_IPS_URL, timeout=30)
            return r.text
        except Exception as e:
            logger.error(f"Error fetching IPs: {e}")
            return None

    def extract_ips_from_text(self, text: str) -> List[str]:
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)
        unique_ips = []
        seen = set()
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)
        return unique_ips

    def extract_ping_from_line(self, line: str) -> int:
        match = re.search(r'(\d+)ms', line, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return 9999

    def parse_ips_with_ping(self, raw_text: str) -> List[Tuple[str, int]]:
        lines = raw_text.strip().split('\n')
        ip_ping_list = []
        for line in lines:
            ips = self.extract_ips_from_text(line)
            if ips:
                ip = ips[0]
                ping = self.extract_ping_from_line(line)
                ip_ping_list.append((ip, ping))
        return ip_ping_list

    def is_ip_sent_in_last_24h(self, ip: str) -> bool:
        if ip in self.sent_history:
            if datetime.now() - self.sent_history[ip] < timedelta(hours=24):
                return True
            else:
                del self.sent_history[ip]
                self.save_history()
        return False

    def mark_as_sent(self, ip: str):
        self.sent_history[ip] = datetime.now()
        self.save_history()

    def update_ip_priority(self, ip: str, ping: int):
        if ip not in self.ip_priority:
            self.ip_priority[ip] = []
        self.ip_priority[ip].append({
            'ping': ping,
            'timestamp': datetime.now().isoformat()
        })
        if len(self.ip_priority[ip]) > 10:
            self.ip_priority[ip] = self.ip_priority[ip][-10:]
        self.save_priority()

    def get_average_ping(self, ip: str) -> float:
        if ip not in self.ip_priority or not self.ip_priority[ip]:
            return 9999
        pings = [item['ping'] for item in self.ip_priority[ip]]
        return sum(pings) / len(pings)

    def filter_and_sort_ips(self, ip_ping_list: List[Tuple[str, int]]) -> List[str]:
        filtered = []
        for ip, ping in ip_ping_list:
            if not self.is_ip_sent_in_last_24h(ip):
                self.update_ip_priority(ip, ping)
                filtered.append((ip, ping))
        
        filtered.sort(key=lambda x: (self.get_average_ping(x[0]), x[1]))
        
        return [ip for ip, _ in filtered]

    def get_ips_to_send(self) -> List[str]:
        raw_text = self.fetch_raw_ips()
        if not raw_text:
            logger.error("Failed to fetch IPs")
            return []
        
        ip_ping_list = self.parse_ips_with_ping(raw_text)
        if not ip_ping_list:
            logger.error("No IPs found in response")
            return []
        
        sorted_ips = self.filter_and_sort_ips(ip_ping_list)
        logger.info(f"Found {len(sorted_ips)} new IPs to send")
        return sorted_ips


class TelegramSender:
    def __init__(self, token: str, chat_id: int):
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

    def create_copy_button(self) -> dict:
        return {
            "inline_keyboard": [[
                {"text": "📋 کپی همه آی‌پی‌ها", "copy_text": "{ips}"}
            ]]
        }

    def format_ips_for_copy(self, ips: List[str]) -> str:
        return "\n".join(ips)

    def format_ips_quote(self, ips: List[str]) -> str:
        ips_text = "\n".join(ips)
        return f"<blockquote>{ips_text}</blockquote>"

    def create_caption(self, ips: List[str]) -> str:
        ips_quote = self.format_ips_quote(ips)
        return f"""🅰️🆁🅸🆂🆃🅰️ 🅸🅿️
➖➖➖➖➖➖➖➖
{ips_quote}

👈 اگر به لیست آی‌‌پی متصل هستید بهش دست نزنید ، فقط زمانی‌که آی‌پی شما فیلتر شد یا از کار افتاد سراغ این آی‌پی‌های جدید بیایید و تست کنید.

‼️ <b>جهت جواب‌دهی هرچه بهتر، قبل از استفاده ipها رو کپی و با Vpn خاموش اسکن کنید.</b>

🔹 <a href="https://t.me/aristapnel/34613?single">اسکنر اول</a>
🔹 <a href="https://t.me/aristapnel/34474">اسکنر دوم</a>
🔹 <a href="https://t.me/aristapnel/35602">اسکنر سوم</a>
➖➖➖➖➖➖➖➖
<blockquote>@aristapnel</blockquote>
➖➖➖➖➖➖➖➖
#Arista #ip #clean_ip #ٱی‌پی_تمیز"""

    def send_ips_batch(self, ips: List[str], batch_number: int, total_batches: int) -> bool:
        if not ips:
            return False
        
        caption = self.create_caption(ips)
        
        try:
            copy_text = self.format_ips_for_copy(ips)
            reply_markup = {
                "inline_keyboard": [[
                    {"text": "📋 کپی همه آی‌پی‌ها", "copy_text": copy_text}
                ]]
            }
            
            data = {
                "chat_id": self.chat_id,
                "text": caption,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
                "reply_markup": json.dumps(reply_markup)
            }
            r = requests.post(self.api + "/sendMessage", data=data, timeout=30)
            return r.status_code == 200
        except Exception as e:
            logger.error(f"Send batch error: {e}")
            return False


class IPScheduler:
    def __init__(self):
        self.extractor = IPExtractor()
        self.sender = TelegramSender(BOT_TOKEN, CHANNEL_ID)
        self.is_first_run = not os.path.exists(HISTORY_FILE) or os.path.getsize(HISTORY_FILE) == 0

    async def run_once(self):
        logger.info("Starting IP extraction and sending...")
        
        all_ips = self.extractor.get_ips_to_send()
        
        if not all_ips:
            logger.info("No new IPs to send")
            return
        
        if self.is_first_run:
            max_posts = MAX_POSTS_FIRST_RUN
            logger.info(f"First run - sending up to {max_posts} posts")
        else:
            total_ips = len(all_ips)
            max_posts = (total_ips + IPS_PER_POST - 1) // IPS_PER_POST
            logger.info(f"Regular run - sending {max_posts} posts")
        
        batches = []
        for i in range(0, len(all_ips), IPS_PER_POST):
            batch = all_ips[i:i + IPS_PER_POST]
            batches.append(batch)
            if len(batches) >= max_posts:
                break
        
        logger.info(f"Sending {len(batches)} batches")
        
        for idx, batch in enumerate(batches):
            if self.sender.send_ips_batch(batch, idx + 1, len(batches)):
                for ip in batch:
                    self.extractor.mark_as_sent(ip)
                logger.info(f"Sent batch {idx + 1}/{len(batches)} with {len(batch)} IPs")
            else:
                logger.error(f"Failed to send batch {idx + 1}")
            await asyncio.sleep(2)
        
        self.is_first_run = False
        logger.info("IP extraction and sending completed")


def main():
    asyncio.run(IPScheduler().run_once())


if __name__ == "__main__":
    main()
