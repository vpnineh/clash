import os
import requests
import base64
import yaml
import json
from urllib.parse import urlparse

# ==========================================
# ⚙️ تنظیمات اصلی
# ==========================================
SRC_FILE = "src.txt"
OUTPUT_FILE = "sub/sub"
REMARK_TEMPLATE = "{index}. @VPNine1 - {flag}"

# ==========================================
# 🛠 توابع کمکی
# ==========================================

def get_country_flag(ip_or_domain):
    """دریافت پرچم کشور بر اساس آی‌پی یا دامنه از طریق API رایگان"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_or_domain}?fields=countryCode", timeout=5)
        data = response.json()
        if data.get("countryCode"):
            cc = data["countryCode"].upper()
            return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    except:
        pass
    return "🏴" 

def decode_base64(data):
    """دی‌کد کردن رشته‌های Base64"""
    data = data.strip()
    padding = '=' * (4 - len(data) % 4)
    try:
        return base64.b64decode(data + padding).decode('utf-8')
    except:
        return ""

def encode_base64(text):
    """انکود کردن رشته به Base64"""
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

# ==========================================
# 🔍 پردازش پروتکل‌ها و نام‌گذاری مجدد
# ==========================================

def parse_and_rename_uri(uri, index):
    """پارس کردن URI، پیدا کردن لوکیشن، و تغییر نام"""
    if uri.startswith("vmess://"):
        try:
            vmess_data = json.loads(decode_base64(uri[8:]))
            server = vmess_data.get('add', '')
            port = vmess_data.get('port', '')
            if not server: return None, None
            
            flag = get_country_flag(server)
            new_name = REMARK_TEMPLATE.format(index=index, flag=flag)
            vmess_data['ps'] = new_name
            
            new_uri = "vmess://" + encode_base64(json.dumps(vmess_data))
            return f"{server}:{port}", new_uri
        except:
            return None, None

    elif uri.startswith(("vless://", "trojan://", "ss://")):
        try:
            parsed = urlparse(uri)
            server = parsed.hostname
            port = parsed.port
            if not server: return None, None
            
            flag = get_country_flag(server)
            new_name = REMARK_TEMPLATE.format(index=index, flag=flag)
            
            # بازسازی URI با نام جدید (Fragment)
            new_uri = uri.split('#')[0] + '#' + requests.utils.quote(new_name)
            return f"{server}:{port}", new_uri
        except:
            return None, None
            
    return None, None

# ==========================================
# 🚀 خواندن ساب‌لینک‌ها از فایل
# ==========================================

def get_sub_links():
    """خواندن لینک‌های ساب از فایل src.txt"""
    if not os.path.exists(SRC_FILE):
        print(f"❌ فایل {SRC_FILE} یافت نشد! لطفاً این فایل را بسازید و لینک‌ها را داخلش قرار دهید.")
        return []
    
    links = []
    with open(SRC_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # خطوط خالی یا خطوطی که با # شروع می‌شوند (کامنت) را نادیده بگیر
            if line and not line.startswith('#'):
                links.append(line)
    return links

# ==========================================
# 🚀 هسته اصلی اسکریپت (Deep Dedup)
# ==========================================

def process_subscriptions():
    sub_links = get_sub_links()
    if not sub_links:
        print("⚠️ هیچ لینکی برای پردازش یافت نشد.")
        return

    # ایجاد پوشه sub در صورت عدم وجود
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    all_configs = []
    unique_keys = set()
    final_uris = []
    
    print("📥 در حال دریافت ساب‌لینک‌ها...")
    
    for link in sub_links:
        try:
            response = requests.get(link, timeout=15)
            text = response.text.strip()
            
            if "proxies:" in text or text.startswith("port:"):
                try:
                    yaml_data = yaml.safe_load(text)
                    print(f"⚠️ فایل کلش شناسایی شد ({link}). لطفاً برای کارکرد بهتر، ابتدا لینک کلش را توسط Subconverter به Base64 تبدیل کنید.")
                except yaml.YAMLError:
                    pass
            else:
                decoded = decode_base64(text)
                if decoded:
                    all_configs.extend(decoded.splitlines())
                else:
                    all_configs.extend(text.splitlines())
        except Exception as e:
            print(f"❌ خطا در دریافت لینک {link}: {e}")

    print(f"✅ تعداد کل کانفیگ‌های خام: {len(all_configs)}")
    print("🔄 در حال پردازش و استخراج پرچم‌ها...")

    index = 1
    for config in all_configs:
        config = config.strip()
        if not config: continue
        
        # استخراج سرور و پورت به عنوان کلید یکتا (Deep Dedup)
        dedup_key, new_uri = parse_and_rename_uri(config, index)
        
        if dedup_key and new_uri:
            if dedup_key not in unique_keys:
                unique_keys.add(dedup_key)
                final_uris.append(new_uri)
                print(f"✔️ پردازش شد: {index}. @VPNine1 [{dedup_key}]")
                index += 1

    # ذخیره در فایل به صورت Base64 
    final_sub_content = encode_base64('\n'.join(final_uris))
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(final_sub_content)
        
    print(f"\n🎉 پردازش تمام شد! تعداد نهایی بدون تکرار: {len(final_uris)}")
    print(f"📁 فایل نهایی خروجی: {OUTPUT_FILE}")

if __name__ == "__main__":
    process_subscriptions()
