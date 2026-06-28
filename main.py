import requests
import re
import json
import hashlib
import os
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging
import time
from collections import Counter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHANNEL_ID = int(os.getenv("CHANNEL_ID", "-1002325683219"))

SCANNER_URL = "https://raw.githubusercontent.com/new493370/NewIp/refs/heads/main/output/best_ips.txt"
MAX_IPS_PER_POST = 300
MAX_POSTS_PER_RUN = 5
SENT_HISTORY_FILE = "sent_ips.json"
CACHE_EXPIRY_HOURS = 168

class IPExtractor:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.sent_ips = {}
        self.history_file = SENT_HISTORY_FILE
        self._dirty = False
        
        self.sent_ips = self.load_sent_history()
        logger.info(f"Loaded {len(self.sent_ips)} IPs from history")
        self.cleanup_old_entries()

    def load_sent_history(self) -> Dict:
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return self._parse_history_data(data)
                    else:
                        logger.warning("Invalid history format, resetting")
                        return {}
            except Exception as e:
                logger.error(f"Error loading history: {e}")
                if os.path.exists(self.history_file + ".backup"):
                    try:
                        with open(self.history_file + ".backup", 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            if isinstance(data, dict):
                                return self._parse_history_data(data)
                    except Exception as e2:
                        logger.error(f"Error loading backup: {e2}")
        return {}

    def _parse_history_data(self, data: Dict) -> Dict:
        converted = {}
        current_time = datetime.now()
        expired_threshold = current_time - timedelta(hours=CACHE_EXPIRY_HOURS)
        
        for k, v in data.items():
            try:
                if isinstance(v, str):
                    try:
                        dt = datetime.fromisoformat(v.replace('Z', '+00:00'))
                        if dt < expired_threshold:
                            continue
                        converted[k] = dt
                    except ValueError:
                        try:
                            dt = datetime.fromtimestamp(float(v))
                            if dt < expired_threshold:
                                continue
                            converted[k] = dt
                        except (ValueError, TypeError):
                            continue
                elif isinstance(v, (int, float)):
                    dt = datetime.fromtimestamp(v)
                    if dt >= expired_threshold:
                        converted[k] = dt
            except (ValueError, TypeError, OverflowError):
                continue
        
        return converted

    def save_sent_history(self):
        if not self._dirty:
            return
            
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    old_data = f.read()
                with open(self.history_file + ".backup", 'w', encoding='utf-8') as f:
                    f.write(old_data)
            
            data = {}
            for k, v in self.sent_ips.items():
                if isinstance(v, datetime):
                    data[k] = v.isoformat()
            
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            self._dirty = False
            logger.debug(f"Saved {len(data)} entries to history")
        except Exception as e:
            logger.error(f"Error saving history: {e}")

    def _get_ip_hash(self, ip: str) -> str:
        return hashlib.md5(ip.encode()).hexdigest()

    def is_ip_sent(self, ip: str) -> bool:
        ip_hash = self._get_ip_hash(ip)
        
        if ip_hash in self.sent_ips:
            time_sent = self.sent_ips[ip_hash]
            if not isinstance(time_sent, datetime):
                del self.sent_ips[ip_hash]
                self._dirty = True
                return False
            
            if datetime.now() - time_sent < timedelta(hours=CACHE_EXPIRY_HOURS):
                return True
            else:
                del self.sent_ips[ip_hash]
                self._dirty = True
                return False
        
        return False

    def mark_batch_as_sent(self, ips: List[Dict]):
        for ip_data in ips:
            ip_hash = self._get_ip_hash(ip_data["ip"])
            self.sent_ips[ip_hash] = datetime.now()
        self._dirty = True

    def cleanup_old_entries(self):
        current_time = datetime.now()
        removed = 0
        
        for ip_hash, sent_time in list(self.sent_ips.items()):
            if not isinstance(sent_time, datetime):
                del self.sent_ips[ip_hash]
                removed += 1
                self._dirty = True
                continue
                
            if current_time - sent_time >= timedelta(hours=CACHE_EXPIRY_HOURS):
                del self.sent_ips[ip_hash]
                removed += 1
                self._dirty = True
        
        if removed > 0:
            self.save_sent_history()
            logger.info(f"Cleaned up {removed} expired IPs")
        
        return removed

    def extract_ip_details(self, line: str) -> Optional[Dict]:
        try:
            line = line.strip()
            if not line:
                return None
            
            ip_match = re.search(r'\[IP:\s*([^\]]+)\]', line)
            if not ip_match:
                return None
            
            ip = ip_match.group(1).strip()
            parts = ip.split('.')
            if len(parts) != 4:
                return None
            try:
                if not all(0 <= int(p) <= 255 for p in parts):
                    return None
            except ValueError:
                return None
            
            score_match = re.search(r'\[SCORE=\s*([^\]]+)\]', line)
            ttfb_match = re.search(r'\[TTFB=\s*([^\]]+)\]', line)
            proto_match = re.search(r'\[PROTO=\s*([^\]]+)\]', line)
            cdn_match = re.search(r'\[CDN=\s*([^\]]+)\]', line)
            country_match = re.search(r'\[Country=\s*([^\]]+)\]', line)
            city_match = re.search(r'\[City=\s*([^\]]+)\]', line)
            provider_match = re.search(r'\[Provider=\s*([^\]]+)\]', line)
            
            return {
                "ip": ip,
                "score": score_match.group(1).strip() if score_match else "0",
                "ttfb": ttfb_match.group(1).strip() if ttfb_match else "-",
                "proto": proto_match.group(1).strip() if proto_match else "-",
                "cdn": cdn_match.group(1).strip() if cdn_match else "-",
                "country": country_match.group(1).strip() if country_match else "Unknown",
                "city": city_match.group(1).strip() if city_match else "-",
                "provider": provider_match.group(1).strip() if provider_match else "Unknown"
            }
        except Exception as e:
            logger.debug(f"Extraction error: {e}")
            return None

    def fetch_ips(self) -> List[Dict]:
        try:
            self.cleanup_old_entries()
            
            logger.info(f"Fetching IPs from scanner")
            response = self.session.get(SCANNER_URL, timeout=30)
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch: status {response.status_code}")
                return []
            
            lines = response.text.splitlines()
            logger.info(f"Received {len(lines)} lines")
            
            new_ips = []
            unique_ips = set()
            
            for line in lines:
                ip_data = self.extract_ip_details(line)
                if not ip_data:
                    continue
                
                ip = ip_data["ip"]
                if ip in unique_ips:
                    continue
                unique_ips.add(ip)
                
                if self.is_ip_sent(ip):
                    continue
                
                new_ips.append(ip_data)
            
            logger.info(f"Found {len(new_ips)} new IPs")
            return new_ips
            
        except Exception as e:
            logger.error(f"Error fetching IPs: {e}")
            return []

    def get_statistics(self) -> Dict:
        total = len(self.sent_ips)
        expired = 0
        for t in self.sent_ips.values():
            if isinstance(t, datetime):
                if datetime.now() - t >= timedelta(hours=CACHE_EXPIRY_HOURS):
                    expired += 1
            else:
                expired += 1
        
        return {
            'total_entries': total,
            'expired_entries': expired,
            'active_entries': total - expired,
            'dirty': self._dirty
        }


class TelegramSender:
    def __init__(self, token: str, chat_id: int):
        if not token:
            raise ValueError("BOT_TOKEN is required")
        self.api = f"https://api.telegram.org/bot{token}"
        self.chat_id = chat_id

    def send_message(self, text: str) -> bool:
        for attempt in range(3):
            try:
                response = requests.post(
                    f"{self.api}/sendMessage",
                    data={
                        "chat_id": self.chat_id,
                        "text": text,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True
                    },
                    timeout=30
                )
                
                if response.status_code == 200:
                    return True
                elif response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 5))
                    time.sleep(retry_after)
                else:
                    time.sleep(5 * (attempt + 1))
                    
            except Exception as e:
                logger.error(f"Send error (attempt {attempt + 1}): {e}")
                time.sleep(5 * (attempt + 1))
        
        return False

    def create_caption(self, ips: List[Dict]) -> str:
        countries = Counter(ip["country"] for ip in ips if ip["country"] != "Unknown")
        cdns = Counter(ip["cdn"] for ip in ips if ip["cdn"] not in ["-", "unknown"])
        
        country_lines = "\n".join(f"📍 {c}: {n}" for c, n in countries.most_common(5))
        cdn_lines = "\n".join(f"🛡️ {c}: {n}" for c, n in cdns.most_common(5))
        
        stats = ""
        if country_lines or cdn_lines:
            parts = []
            if country_lines:
                parts.append(f"🌍 <b>کشورها:</b>\n{country_lines}")
            if cdn_lines:
                parts.append(f"🛡️ <b>CDN:</b>\n{cdn_lines}")
            stats = f"<blockquote expandable>{chr(10).join(parts)}</blockquote>"
        
        ips_text = "\n".join(ip["ip"] for ip in ips)
        
        return f"""🅰️🆁🅸🆂🅰️ 🅸🅿️
<b>🔰 لیست آی‌پی جدید ({len(ips)} IP)</b>
➖➖➖➖➖➖➖➖
<blockquote expandable><code>{ips_text}</code></blockquote>
➖➖➖➖➖➖➖➖
{stats}
👈 اگر به لیست آی‌‌پی متصل هستید بهش دست نزنید ، فقط زمانی‌که آی‌پی شما فیلتر شد یا از کار افتاد سراغ این آی‌پی‌های جدید بیایید و تست کنید.

‼️ <b>جهت جواب‌دهی هرچه بهتر، قبل از استفاده ipها رو کپی و با Vpn خاموش اسکن کنید.</b>

<blockquote><b>🔹 <a href="https://t.me/aristapanel/47250">اسکنر آریستا</a></b></blockquote>
<blockquote><b>🌐 <a href="https://github.com/aristapanell-cell/ARISTA-MATRIX-PIPELINE/tree/main">گیتهاب آی‌پی اسکنر</a></b></blockquote>
<blockquote><b>📊 <a href="https://raw.githubusercontent.com/aristapanell-cell/ARISTA-MATRIX-PIPELINE/refs/heads/main/output/best_ips.txt">مشاهده جزئیات کامل هر آی‌پی</a></b></blockquote>
<blockquote><b>📦 <a href="https://github.com/aristapanell-cell/AriataPanel">گیتهاب آریستا (کانفیگ)</a></b></blockquote>
<blockquote><b>👈 <a href="https://t.me/aristapanel/46625">منابع مناسب اپلیکیشن V2rayNG, Hiddify, NekoBox, ...</a></b></blockquote>
<blockquote><b>👈 <a href="https://t.me/aristapanel/47104">منابع مناسب اپلیکیشن SingBox</a></b></blockquote>
<blockquote><b>👈 <a href="https://t.me/aristapanel/47109">منابع مناسب اپلیکیشن ClashMeta</a></b></blockquote>

➖➖➖➖➖➖➖➖
<blockquote>@aristapanel</blockquote>
➖➖➖➖➖➖➖➖
#Arista #ip #clean_ip #ٱی‌پی_تمیز"""

    def send_ips_batch(self, ips: List[Dict]) -> bool:
        if not ips:
            return False
        return self.send_message(self.create_caption(ips))


class IPScheduler:
    def __init__(self):
        self.extractor = IPExtractor()
        if not BOT_TOKEN:
            raise ValueError("BOT_TOKEN not set")
        self.sender = TelegramSender(BOT_TOKEN, CHANNEL_ID)

    def run(self):
        try:
            logger.info(f"Stats before: {self.extractor.get_statistics()}")
            
            all_ips = self.extractor.fetch_ips()
            if not all_ips:
                logger.info("No new IPs found")
                return
            
            logger.info(f"Found {len(all_ips)} new IPs")
            
            posts = 0
            sent = 0
            
            for i in range(0, len(all_ips), MAX_IPS_PER_POST):
                if posts >= MAX_POSTS_PER_RUN:
                    logger.info(f"Max posts ({MAX_POSTS_PER_RUN}) reached")
                    break
                
                batch = all_ips[i:i + MAX_IPS_PER_POST]
                
                if self.sender.send_ips_batch(batch):
                    self.extractor.mark_batch_as_sent(batch)
                    sent += len(batch)
                    posts += 1
                    self.extractor.save_sent_history()
                    logger.info(f"Batch {posts}: sent {len(batch)} IPs")
                    
                    if i + MAX_IPS_PER_POST < len(all_ips):
                        time.sleep(2)
                else:
                    logger.error(f"Failed to send batch {posts + 1}")
                    break
            
            logger.info(f"Sent {sent} IPs in {posts} posts")
            logger.info(f"Stats after: {self.extractor.get_statistics()}")
            
        except Exception as e:
            logger.error(f"Run error: {e}")
            raise


def main():
    try:
        IPScheduler().run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
