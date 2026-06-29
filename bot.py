import os
import re
import sqlite3
import requests
import logging
from datetime import datetime, timedelta
from telegram import Bot
from telegram.error import TelegramError

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHANNEL_ID = os.environ.get("CHANNEL_ID")

if not BOT_TOKEN or not CHANNEL_ID:
    raise ValueError("BOT_TOKEN and CHANNEL_ID must be set in environment!")

URL = "https://raw.githubusercontent.com/aristapanell-cell/ARISTA-MATRIX-PIPELINE/refs/heads/main/output/best_ips.txt"
MAX_IPS_PER_POST = 150
MAX_POSTS_PER_RUN = 3
KEEP_HOURS = 168

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

DB_PATH = "sent_ips.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS sent_ips (
            ip TEXT PRIMARY KEY,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")

def clean_old_ips():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    cutoff = datetime.now() - timedelta(hours=KEEP_HOURS)
    c.execute("DELETE FROM sent_ips WHERE sent_at < ?", (cutoff,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if deleted:
        logger.info(f"Cleaned {deleted} old IPs.")

def get_sent_ips():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip FROM sent_ips")
    rows = c.fetchall()
    conn.close()
    sent_count = len(rows)
    logger.info(f"Loaded {sent_count} previously sent IPs from database")
    return {row[0] for row in rows}

def mark_as_sent(ips):
    if not ips:
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now()
    data = [(ip, now) for ip in ips]
    c.executemany("INSERT OR IGNORE INTO sent_ips (ip, sent_at) VALUES (?, ?)", data)
    conn.commit()
    conn.close()
    logger.info(f"Marked {len(ips)} IPs as sent.")

def extract_ips_from_text(text):
    pattern = r"\[IP:\s*([\d.]+)\]\s*\[PORT:\s*(\d+)\]"
    matches = re.findall(pattern, text)
    valid_ips = []
    for ip, port in matches:
        parts = ip.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            valid_ips.append(ip)
    return valid_ips

def fetch_ips_from_url():
    try:
        resp = requests.get(URL, timeout=30)
        resp.raise_for_status()
        text = resp.text
        if not text or not text.strip():
            logger.warning("File is empty or contains no data")
            return []
        all_ips = extract_ips_from_text(text)
        logger.info(f"Extracted {len(all_ips)} IPs from file.")
        return all_ips
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.warning("File not found (404). No IPs to fetch.")
        else:
            logger.error(f"HTTP error: {e}")
        return []
    except Exception as e:
        logger.error(f"Error fetching file: {e}")
        return []

def generate_caption(ips):
    ips_text = "\n".join(ips) if ips else "No new IPs found."
    return f"""🅰️🆁🅸🆂🅰️ 🅸🅿️
<b>🔰 لیست آی‌پی جدید ({len(ips)} IP)</b>
➖➖➖➖➖➖➖➖
<blockquote expandable><code>{ips_text}</code></blockquote>
➖➖➖➖➖➖➖➖
👈 اگر به لیست آی‌‌پی متصل هستید بهش دست نزنید ، فقط زمانی‌که آی‌پی شما فیلتر شد یا از کار افتاد سراغ این آی‌پی‌های جدید بیایید و تست کنید.

‼️ <b>جهت جواب‌دهی هرچه بهتر، قبل از استفاده ipها رو کپی و با Vpn خاموش اسکن کنید.</b>

<blockquote><b>🔹 <a href="https://t.me/aristapanel/47250">اسکنر آریستا</a></b></blockquote>
<blockquote><b>🌐 <a href="https://cdn.jsdelivr.net/gh/aristapanell-cell/ARISTA-MATRIX-PIPELINE@refs/heads/main/output/best_ips.txt">گیتهاب آی‌پی اسکنر</a></b></blockquote>
<blockquote><b>📊 <a href="https://raw.githubusercontent.com/aristapanell-cell/ARISTA-MATRIX-PIPELINE/refs/heads/main/output/best_ips.txt">مشاهده جزئیات کامل هر آی‌پی</a></b></blockquote>
<blockquote><b>📦 <a href="https://github.com/aristapanell-cell/AriataPanel">گیتهاب آریستا (کانفیگ)</a></b></blockquote>
<blockquote><b>👈 <a href="https://t.me/aristapanel/46625">منابع مناسب اپلیکیشن V2rayNG, Hiddify, NekoBox, ...</a></b></blockquote>
<blockquote><b>👈 <a href="https://t.me/aristapanel/47104">منابع مناسب اپلیکیشن SingBox</a></b></blockquote>
<blockquote><b>👈 <a href="https://t.me/aristapanel/47109">منابع مناسب اپلیکیشن ClashMeta</a></b></blockquote>

➖➖➖➖➖➖➖➖
<blockquote>@aristapanel</blockquote>
➖➖➖➖➖➖➖➖
#Arista #ip #clean_ip #ٱی‌پی_تمیز"""

def send_ips_to_channel(bot, ips):
    if not ips:
        logger.info("No new IPs to send.")
        return

    total_sent = 0
    posts = 0

    for i in range(0, len(ips), MAX_IPS_PER_POST):
        if posts >= MAX_POSTS_PER_RUN:
            logger.info(f"Reached maximum {MAX_POSTS_PER_RUN} posts per run.")
            break

        chunk = ips[i:i + MAX_IPS_PER_POST]
        caption = generate_caption(chunk)

        try:
            bot.send_message(
                chat_id=CHANNEL_ID,
                text=caption,
                parse_mode="HTML",
                disable_web_page_preview=False
            )
            logger.info(f"Post {posts+1}: sent {len(chunk)} IPs.")
            total_sent += len(chunk)
            posts += 1
        except TelegramError as e:
            logger.error(f"Error sending post: {e}")
            break

    logger.info(f"Total {total_sent} IPs sent in {posts} posts.")
    return total_sent

def main():
    logger.info("Starting bot...")
    init_db()
    clean_old_ips()

    all_ips = fetch_ips_from_url()
    if not all_ips:
        logger.warning("No IPs retrieved from file. Skipping...")
        return

    sent_set = get_sent_ips()
    new_ips = [ip for ip in all_ips if ip not in sent_set]
    logger.info(f"{len(new_ips)} new IPs (from {len(all_ips)} total)")

    if not new_ips:
        logger.info("All IPs already sent.")
        return

    bot = Bot(token=BOT_TOKEN)
    sent_count = send_ips_to_channel(bot, new_ips)

    if sent_count:
        mark_as_sent(new_ips[:sent_count])

    logger.info("Execution finished.")

if __name__ == "__main__":
    main()
