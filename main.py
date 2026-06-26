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

SCANNER_URL = "https://raw.githubusercontent.com/aristapanell-cell/ARISTA-MATRIX-PIPELINE/refs/heads/main/output/best_ips.txt"
MAX_IPS_PER_POST = 100
MAX_POSTS_PER_RUN = 5
SENT_HISTORY_FILE = "sent_ips.json"
CACHE_EXPIRY_HOURS = 48

class IPExtractor:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.sent_ips = {}
        self.current_run_ips = set()
        self.history_file = SENT_HISTORY_FILE
        self.backup_file = SENT_HISTORY_FILE + ".backup"
        
        self.ensure_history_file()
        self.sent_ips = self.load_sent_history()
        logger.info(f"Loaded {len(self.sent_ips)} IPs from history")
        
        self.cleanup_old_entries()

    def ensure_history_file(self):
        if not os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'w', encoding='utf-8') as f:
                    json.dump({}, f, ensure_ascii=False, indent=2)
                logger.info(f"Created new history file: {self.history_file}")
            except Exception as e:
                logger.error(f"Could not create history file: {e}")

    def load_sent_history(self) -> Dict:
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    converted_data = {}
                    for k, v in data.items():
                        try:
                            if isinstance(v, str):
                                converted_data[k] = datetime.fromisoformat(v)
                            elif isinstance(v, dict) and 'timestamp' in v:
                                converted_data[k] = datetime.fromisoformat(v['timestamp'])
                            else:
                                converted_data[k] = datetime.now()
                        except (ValueError, TypeError):
                            converted_data[k] = datetime.now()
                    return converted_data
            except Exception as e:
                logger.error(f"Error loading history file: {e}")
                if os.path.exists(self.backup_file):
                    try:
                        with open(self.backup_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            return {k: datetime.fromisoformat(v) if isinstance(v, str) else datetime.now() 
                                   for k, v in data.items()}
                    except Exception as e2:
                        logger.error(f"Error loading backup file: {e2}")
        
        return {}

    def save_sent_history(self):
        try:
            if os.path.exists(self.history_file):
                try:
                    with open(self.history_file, 'r', encoding='utf-8') as f:
                        old_data = f.read()
                    with open(self.backup_file, 'w', encoding='utf-8') as f:
                        f.write(old_data)
                except Exception as e:
                    logger.warning(f"Could not create backup: {e}")
            
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump({k: v.isoformat() for k, v in self.sent_ips.items()}, 
                         f, ensure_ascii=False, indent=2)
            
            logger.debug(f"Saved {len(self.sent_ips)} IPs to history")
            
        except Exception as e:
            logger.error(f"Error saving history: {e}")

    def _get_ip_hash(self, ip: str) -> str:
        return hashlib.md5(ip.encode()).hexdigest()

    def is_ip_sent(self, ip: str) -> bool:
        ip_hash = self._get_ip_hash(ip)
        
        if ip in self.current_run_ips:
            logger.debug(f"IP {ip} already in current run")
            return True
        
        if ip_hash in self.sent_ips:
            time_sent = self.sent_ips[ip_hash]
            time_diff = datetime.now() - time_sent
            
            if time_diff < timedelta(hours=CACHE_EXPIRY_HOURS):
                remaining = CACHE_EXPIRY_HOURS - time_diff.total_seconds() / 3600
                logger.debug(f"IP {ip} was sent {time_diff.total_seconds()/3600:.1f} hours ago, "
                           f"remaining: {remaining:.1f} hours")
                return True
            else:
                del self.sent_ips[ip_hash]
                self.save_sent_history()
                logger.debug(f"IP {ip} expired from history, can be sent again")
                return False
        
        return False

    def mark_as_sent(self, ip: str):
        ip_hash = self._get_ip_hash(ip)
        self.sent_ips[ip_hash] = datetime.now()
        self.current_run_ips.add(ip)
        self.save_sent_history()
        logger.debug(f"Marked IP {ip} as sent")

    def cleanup_old_entries(self):
        current_time = datetime.now()
        removed_count = 0
        
        for ip_hash, sent_time in list(self.sent_ips.items()):
            if current_time - sent_time >= timedelta(hours=CACHE_EXPIRY_HOURS):
                del self.sent_ips[ip_hash]
                removed_count += 1
        
        if removed_count > 0:
            self.save_sent_history()
            logger.info(f"Cleaned up {removed_count} old IP entries")
        
        return removed_count

    def extract_ip_details(self, line: str) -> Optional[Dict]:
        try:
            line = line.strip()
            if not line:
                return None
            
            ip_match = re.search(r'\[IP:\s*([^\]]+)\]', line)
            score_match = re.search(r'\[SCORE=\s*([^\]]+)\]', line)
            ttfb_match = re.search(r'\[TTFB=\s*([^\]]+)\]', line)
            proto_match = re.search(r'\[PROTO=\s*([^\]]+)\]', line)
            rel_match = re.search(r'\[REL=\s*([^\]]+)\]', line)
            cdn_match = re.search(r'\[CDN=\s*([^\]]+)\]', line)
            type_match = re.search(r'\[TYPE=\s*([^\]]+)\]', line)
            sni_match = re.search(r'\[SNI=\s*([^\]]+)\]', line)
            domain_match = re.search(r'\[DOMAIN=\s*([^\]]+)\]', line)
            city_match = re.search(r'\[City=\s*([^\]]+)\]', line)
            country_match = re.search(r'\[Country=\s*([^\]]+)\]', line)
            provider_match = re.search(r'\[Provider=\s*([^\]]+)\]', line)
            
            if not ip_match:
                return None
            
            ip = ip_match.group(1).strip()
            
            parts_ip = ip.split('.')
            if len(parts_ip) != 4:
                return None
            if not all(0 <= int(p) <= 255 for p in parts_ip):
                return None
            
            return {
                "ip": ip,
                "score": score_match.group(1).strip() if score_match else "0",
                "ttfb": ttfb_match.group(1).strip() if ttfb_match else "-",
                "proto": proto_match.group(1).strip() if proto_match else "-",
                "reliability": rel_match.group(1).strip() if rel_match else "-",
                "cdn": cdn_match.group(1).strip() if cdn_match else "-",
                "type": type_match.group(1).strip() if type_match else "-",
                "sni": sni_match.group(1).strip() if sni_match else "-",
                "domain": domain_match.group(1).strip() if domain_match else "-",
                "city": city_match.group(1).strip() if city_match else "-",
                "country": country_match.group(1).strip() if country_match else "Unknown",
                "provider": provider_match.group(1).strip() if provider_match else "Unknown"
            }
        except Exception as e:
            logger.debug(f"Error extracting IP details from line: {e}")
            return None

    def fetch_ips(self) -> List[Dict]:
        try:
            self.cleanup_old_entries()
            
            self.current_run_ips = set()
            
            logger.info(f"Fetching IPs from: {SCANNER_URL}")
            response = self.session.get(SCANNER_URL, timeout=30)
            
            if response.status_code == 200:
                new_ips = []
                unique_ips = set()
                
                lines = response.text.splitlines()
                logger.info(f"Received {len(lines)} lines from scanner")
                
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
                    self.current_run_ips.add(ip)
                
                logger.info(f"Found {len(new_ips)} new unique IPs out of {len(unique_ips)} total unique")
                return new_ips
            else:
                logger.error(f"Failed to fetch IPs: status {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching IPs: {e}")
            return []

    def get_statistics(self) -> Dict:
        total = len(self.sent_ips)
        expired = 0
        current_time = datetime.now()
        
        for sent_time in self.sent_ips.values():
            if current_time - sent_time >= timedelta(hours=CACHE_EXPIRY_HOURS):
                expired += 1
        
        return {
            'total_entries': total,
            'expired_entries': expired,
            'active_entries': total - expired,
            'file_exists': os.path.exists(self.history_file),
            'backup_exists': os.path.exists(self.backup_file)
        }


class TelegramSender:
    def __init__(self, token: str, chat_id: int):
        if not token:
            raise ValueError("BOT_TOKEN is required")
        self.api = f"https://api.telegram.org/bot{token}"
        self.chat_id = chat_id
        logger.info(f"Telegram sender initialized for chat_id: {chat_id}")

    def send_message(self, text: str, reply_markup=None) -> bool:
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                data = {
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True
                }
                if reply_markup:
                    data["reply_markup"] = json.dumps(reply_markup)
                
                response = requests.post(self.api + "/sendMessage", data=data, timeout=30)
                
                if response.status_code == 200:
                    logger.info("Message sent successfully")
                    return True
                elif response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', retry_delay))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue
                else:
                    logger.error(f"Send failed with status {response.status_code}: {response.text}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay * (attempt + 1))
                    
            except Exception as e:
                logger.error(f"Send error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                else:
                    return False
        
        return False

    def format_ips_block(self, ips: List[Dict]) -> str:
        ips_text = "\n".join([ip["ip"] for ip in ips])
        return f"<blockquote expandable><code>{ips_text}</code></blockquote>"

    def get_country_stats(self, ips: List[Dict]) -> Dict:
        countries = [ip["country"] for ip in ips if ip["country"] != "Unknown"]
        return dict(Counter(countries))

    def get_cdn_stats(self, ips: List[Dict]) -> Dict:
        cdns = [ip["cdn"] for ip in ips if ip["cdn"] != "-" and ip["cdn"] != "unknown"]
        return dict(Counter(cdns))

    def create_caption(self, ips: List[Dict]) -> str:
        country_stats = self.get_country_stats(ips)
        cdn_stats = self.get_cdn_stats(ips)
        
        country_lines = []
        if country_stats:
            for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                country_lines.append(f"📍 {country}: {count}")
        
        cdn_lines = []
        if cdn_stats:
            for cdn, count in sorted(cdn_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                cdn_lines.append(f"🛡️ {cdn}: {count}")
        
        ips_block = self.format_ips_block(ips)
        
        stats_block = ""
        if country_lines or cdn_lines:
            stats_parts = []
            if country_lines:
                stats_parts.append("🌍 <b>کشورها:</b>\n" + "\n".join(country_lines))
            if cdn_lines:
                stats_parts.append("🛡️ <b>CDN:</b>\n" + "\n".join(cdn_lines))
            stats_block = f"<blockquote expandable>{chr(10).join(stats_parts)}</blockquote>"
        
        return f"""🅰️🆁🅸🆂🅰️ 🅸🅿️
<b>🔰 لیست آی‌پی جدید ({len(ips)} IP)</b>
➖➖➖➖➖➖➖➖
{ips_block}
➖➖➖➖➖➖➖➖
{stats_block}
👈 اگر به لیست آی‌‌پی متصل هستید بهش دست نزنید ، فقط زمانی‌که آی‌پی شما فیلتر شد یا از کار افتاد سراغ این آی‌پی‌های جدید بیایید و تست کنید.

‼️ <b>جهت جواب‌دهی هرچه بهتر، قبل از استفاده ipها رو کپی و با Vpn خاموش اسکن کنید.</b>

<blockquote><b>🔹 <a href="https://t.me/aristapanel/47250">اسکنر آریستا</a></b></blockquote>

<blockquote><b>👈 <a href="https://t.me/aristapanel/46625">منابع مناسب اپلیکیشن V2rayNG, Hiddify, NekoBox, ...</a></b></blockquote>

<blockquote><b>👈 <a href="https://t.me/aristapanel/47104">منابع مناسب اپلیکیشن SingBox</a></b></blockquote>

<blockquote><b>👈 <a href="https://t.me/aristapanel/47109">منابع مناسب اپلیکیشن ClashMeta</a></b></blockquote>

<blockquote><b>📂 <a href="https://github.com/aristapanell-cell/ARISTA-MATRIX-PIPELINE">ARISTA MATRIX PIPELINE پروژه</a></b></blockquote>

<blockquote><b>📦 <a href="https://github.com/aristapanell-cell/AriataPanel">پروژه جمع‌آوری کانفیگ و سابسکریپشن</a></b></blockquote>

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
            raise ValueError("BOT_TOKEN environment variable not set")
        self.sender = TelegramSender(BOT_TOKEN, CHANNEL_ID)
        logger.info("IPScheduler initialized successfully")

    def run(self):
        try:
            stats = self.extractor.get_statistics()
            logger.info(f"History stats before run: {stats}")
            
            all_ips = self.extractor.fetch_ips()
            if not all_ips:
                logger.info("No new IPs found to send")
                return
            
            logger.info(f"Found {len(all_ips)} new IPs to send")
            
            posts_count = 0
            sent_count = 0
            
            for i in range(0, len(all_ips), MAX_IPS_PER_POST):
                if posts_count >= MAX_POSTS_PER_RUN:
                    logger.info(f"Reached max posts limit ({MAX_POSTS_PER_RUN})")
                    break
                
                batch = all_ips[i:i + MAX_IPS_PER_POST]
                
                if self.sender.send_ips_batch(batch):
                    for ip_data in batch:
                        self.extractor.mark_as_sent(ip_data["ip"])
                        sent_count += 1
                    
                    posts_count += 1
                    logger.info(f"Sent batch {posts_count} with {len(batch)} IPs")
                    
                    if i + MAX_IPS_PER_POST < len(all_ips):
                        time.sleep(2)
                else:
                    logger.error(f"Failed to send batch {posts_count + 1}")
                    break
            
            logger.info(f"Successfully sent {sent_count} IPs in {posts_count} posts")
            
            stats = self.extractor.get_statistics()
            logger.info(f"History stats after run: {stats}")
            
        except Exception as e:
            logger.error(f"Error in run: {e}")
            raise


def main():
    try:
        scheduler = IPScheduler()
        scheduler.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
