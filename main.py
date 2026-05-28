import os
import requests
import base64
import json
import urllib.parse
import time

# ==========================================
# ⚙️ تنظیمات اصلی
# ==========================================
SRC_FILE = "src.txt"
OUTPUT_FILE = "sub/sub"  # فایل نهایی بدون پسوند ذخیره می‌شود (دیکود شده)
REMARK_TEMPLATE = "{index}. @VPNine1 - {flag}"

# مبدل عمومی برای تبدیل بی‌نقص فایل‌های YAML کلش به لینک‌های استاندارد
SUBCONVERTER_API = "https://sub.v1.mk/sub?target=v2ray&url="

LOCATION_CACHE = {}

# ==========================================
# 🛠 توابع کمکی
# ==========================================

def get_country_flag(ip_or_domain):
    """دریافت پرچم با کش و تاخیر برای جلوگیری از بن شدن توسط API (محدودیت ۴۵ درخواست در دقیقه)"""
    if ip_or_domain in LOCATION_CACHE:
        return LOCATION_CACHE[ip_or_domain]
    
    try:
        time.sleep(1.4) # توقف کوتاه برای جلوگیری از خطای 429 Too Many Requests
        response = requests.get(f"http://ip-api.com/json/{ip_or_domain}?fields=countryCode", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("countryCode"):
                cc = data["countryCode"].upper()
                flag = chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
                LOCATION_CACHE[ip_or_domain] = flag
                return flag
    except:
        pass
    
    LOCATION_CACHE[ip_or_domain] = "🏴"
    return "🏴"

def decode_base64(data):
    data = data.strip()
    padding_needed = len(data) % 4
    if padding_needed:
        data += '=' * (4 - padding_needed)
    try:
        return base64.b64decode(data).decode('utf-8')
    except:
        try:
            return base64.urlsafe_b64decode(data).decode('utf-8')
        except:
            return ""

def encode_base64(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

# ==========================================
# 🔍 استخراج ایمن سرور و پورت بدون تخریب لینک
# ==========================================

def get_server_and_port(uri):
    """استخراج سرور و پورت به عنوان کلید یونیک برای حذف تکرار عمیق"""
    if uri.startswith("vmess://"):
        try:
            data = json.loads(decode_base64(uri[8:]))
            return str(data.get('add')), str(data.get('port'))
        except:
            return None, None
    else:
        try:
            # حذف بخش remark برای پارس کردن دقیق
            base_uri = uri.split('#')[0] if '#' in uri else uri
            parsed = urllib.parse.urlparse(base_uri)
            return parsed.hostname, str(parsed.port)
        except:
            return None, None

def apply_new_remark(uri, index, flag):
    """تغییر نام کانفیگ بدون دستکاری تنظیمات اتصال"""
    new_name = REMARK_TEMPLATE.format(index=index, flag=flag)
    
    if uri.startswith("vmess://"):
        try:
            data = json.loads(decode_base64(uri[8:]))
            data['ps'] = new_name
            # تبدیل مجدد به جیسون و انکود بدون تخریب کاراکترها
            json_str = json.dumps(data, ensure_ascii=False)
            return "vmess://" + encode_base64(json_str)
        except:
            return uri
    else:
        try:
            base_uri = uri.split('#')[0]
            # فقط نام جدید انکود شده و به انتهای لینک متصل می‌شود
            return f"{base_uri}#{urllib.parse.quote(new_name)}"
        except:
            return uri

# ==========================================
# 🚀 هسته اصلی اسکریپت
# ==========================================

def get_sub_links():
    if not os.path.exists(SRC_FILE):
        print(f"❌ فایل {SRC_FILE} یافت نشد!")
        return []
    with open(SRC_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def process_subscriptions():
    sub_links = get_sub_links()
    if not sub_links: return

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    all_raw_uris = []
    
    print("📥 در حال دریافت و استخراج کانفیگ‌ها...")
    
    for link in sub_links:
        try:
            response = requests.get(link, timeout=15)
            text = response.text.strip()
            
            # تشخیص فایل کلش (YAML)
            if "proxies:" in text or text.startswith("port:"):
                print(f"🔄 فایل کلش شناسایی شد، در حال تبدیل استاندارد: {link}")
                # استفاده از API برای تبدیل بی‌نقص فایل کلش به Base64
                encoded_url = urllib.parse.quote(link)
                api_res = requests.get(f"{SUBCONVERTER_API}{encoded_url}", timeout=20)
                decoded = decode_base64(api_res.text.strip())
                all_raw_uris.extend(decoded.splitlines())
            else:
                # پردازش فایل‌های Base64 یا پلین‌تکست معمولی
                decoded = decode_base64(text)
                if decoded and ("vmess://" in decoded or "vless://" in decoded or "trojan://" in decoded):
                    all_raw_uris.extend(decoded.splitlines())
                else:
                    all_raw_uris.extend(text.splitlines())
                print(f"✔️ ساب معمولی دریافت شد: {link}")
        except Exception as e:
            print(f"❌ خطا در دریافت لینک {link}: {e}")

    print(f"\n✅ تعداد کل کانفیگ‌های استخراج شده (قبل از فیلتر): {len(all_raw_uris)}")
    print("🔄 در حال حذف تکرار عمیق (Deep Dedup)...")

    # مرحله اول: استخراج کانفیگ‌های یونیک بر اساس آی‌پی و پورت
    unique_configs = {}
    for uri in all_raw_uris:
        uri = uri.strip()
        if not uri or not uri.startswith(("vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "tuic://")): 
            continue
            
        server, port = get_server_and_port(uri)
        if server and port:
            dedup_key = f"{server}:{port}"
            if dedup_key not in unique_configs:
                unique_configs[dedup_key] = (server, uri)

    print(f"✅ تعداد کانفیگ‌های یونیک یافت شده: {len(unique_configs)}")
    print("🌐 در حال دریافت پرچم کشورها و بازنویسی نام‌ها (این مرحله کمی زمان‌بر است)...")

    final_uris = []
    index = 1
    
    # مرحله دوم: اعمال تغییر نام فقط روی کانفیگ‌های یونیک
    for dedup_key, (server, uri) in unique_configs.items():
        flag = get_country_flag(server)
        new_uri = apply_new_remark(uri, index, flag)
        final_uris.append(new_uri)
        print(f"✔️ پردازش شد: {index}. [{dedup_key}] - {flag}")
        index += 1

    # ذخیره در فایل به صورت خام و دیکود شده (هر لینک در یک خط)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_uris))
        
    print(f"\n🎉 پردازش تمام شد! تعداد نهایی بدون تکرار: {len(final_uris)}")
    print(f"📁 فایل خروجی دیکود شده: {OUTPUT_FILE}")

if __name__ == "__main__":
    process_subscriptions()
