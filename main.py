import os
import requests
import base64
import yaml
import json
from urllib.parse import quote

# ==========================================
# ⚙️ تنظیمات اصلی
# ==========================================
SRC_FILE = "src.txt"
OUTPUT_FILE = "sub/sub"  # فایل نهایی بدون پسوند ذخیره می‌شود
REMARK_TEMPLATE = "{index}. @VPNine1 - {flag}"

# کش برای جلوگیری از بن شدن توسط API هنگام چک کردن آی‌پی‌های تکراری
LOCATION_CACHE = {}

# ==========================================
# 🛠 توابع کمکی
# ==========================================

def get_country_flag(ip_or_domain):
    """دریافت پرچم با استفاده از کش"""
    if ip_or_domain in LOCATION_CACHE:
        return LOCATION_CACHE[ip_or_domain]
    
    try:
        # تایم‌اوت کوتاه تا اگر سایتی پینگ نداشت اسکریپت گیر نکند
        response = requests.get(f"http://ip-api.com/json/{ip_or_domain}?fields=countryCode", timeout=2)
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
    padding = '=' * (4 - len(data) % 4)
    try:
        return base64.b64decode(data + padding).decode('utf-8')
    except:
        return ""

def encode_base64(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

# ==========================================
# 🔄 مبدل کلش به V2ray
# ==========================================

def clash_to_uri(proxy):
    """تبدیل فرمت‌های yaml کلش به لینک استاندارد V2ray"""
    try:
        p_type = proxy.get('type')
        server = proxy.get('server')
        port = proxy.get('port')
        name = proxy.get('name', 'Proxy')

        if p_type == 'vmess':
            v_json = {
                "v": "2", "ps": name, "add": server, "port": str(port),
                "id": proxy.get('uuid', ''), "aid": str(proxy.get('alterId', 0)),
                "net": proxy.get('network', 'tcp'), "type": "none",
                "host": "", "path": "", "tls": "", "sni": proxy.get('servername', '')
            }
            if proxy.get('tls'): v_json['tls'] = 'tls'
            if 'ws-opts' in proxy:
                v_json['path'] = proxy['ws-opts'].get('path', '')
                v_json['host'] = proxy['ws-opts'].get('headers', {}).get('Host', '')
            return f"vmess://{encode_base64(json.dumps(v_json))}"

        elif p_type == 'vless':
            uuid = proxy.get('uuid', '')
            params = []
            if proxy.get('network'): params.append(f"type={proxy.get('network')}")
            if proxy.get('tls'): params.append("security=tls")
            if proxy.get('servername'): params.append(f"sni={proxy.get('servername')}")
            
            # پشتیبانی از Reality و WS
            if proxy.get('network') == 'ws' and 'ws-opts' in proxy:
                params.append(f"path={quote(proxy['ws-opts'].get('path', '/'))}")
                if 'headers' in proxy['ws-opts'] and 'Host' in proxy['ws-opts']['headers']:
                    params.append(f"host={proxy['ws-opts']['headers']['Host']}")
            if 'reality-opts' in proxy:
                params.append("security=reality")
                params.append(f"pbk={proxy['reality-opts'].get('public-key', '')}")
                params.append(f"fp={proxy['client-fingerprint', 'chrome']}")
                
            query = "&".join(params)
            return f"vless://{uuid}@{server}:{port}?{query}#{quote(name)}"

        elif p_type == 'trojan':
            password = proxy.get('password', '')
            params = []
            if proxy.get('network'): params.append(f"type={proxy.get('network')}")
            if proxy.get('sni') or proxy.get('servername'): 
                params.append(f"sni={proxy.get('sni', proxy.get('servername'))}")
            query = "&".join(params)
            return f"trojan://{password}@{server}:{port}?{query}#{quote(name)}"
            
    except Exception as e:
        return None
    return None

# ==========================================
# 🔍 پردازش و تغییر نام
# ==========================================

def parse_and_rename_uri(uri, index):
    if uri.startswith("vmess://"):
        try:
            vmess_data = json.loads(decode_base64(uri[8:]))
            server = vmess_data.get('add', '')
            port = vmess_data.get('port', '')
            if not server: return None, None
            
            flag = get_country_flag(server)
            new_name = REMARK_TEMPLATE.format(index=index, flag=flag)
            vmess_data['ps'] = new_name
            return f"{server}:{port}", f"vmess://{encode_base64(json.dumps(vmess_data))}"
        except:
            return None, None

    elif uri.startswith(("vless://", "trojan://", "ss://")):
        try:
            # جدا کردن مشخصات از اسم قبلی
            base_part = uri.split('#')[0]
            # استخراج موقت سرور و پورت برای آی‌پی و حذف تکرار
            server_port_part = base_part.split('@')[1].split('?')[0].split('/')[0]
            server, port = server_port_part.split(':')
            
            flag = get_country_flag(server)
            new_name = REMARK_TEMPLATE.format(index=index, flag=flag)
            new_uri = f"{base_part}#{quote(new_name)}"
            return f"{server}:{port}", new_uri
        except:
            return None, None
            
    return None, None

# ==========================================
# 🚀 هسته اصلی
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
    unique_keys = set()
    final_uris = []
    
    print("📥 در حال دریافت و استخراج کانفیگ‌ها...")
    
    for link in sub_links:
        try:
            response = requests.get(link, timeout=15)
            text = response.text.strip()
            
            # تشخیص اینکه فایل YAML/Clash است یا خیر
            if "proxies:" in text or text.startswith("port:"):
                yaml_data = yaml.safe_load(text)
                for proxy in yaml_data.get('proxies', []):
                    uri = clash_to_uri(proxy)
                    if uri: all_raw_uris.append(uri)
                print(f"✔️ فایل کلش خوانده شد: {link}")
            else:
                # اگر Base64 معمولی است
                decoded = decode_base64(text)
                if decoded and (decoded.startswith('vmess://') or decoded.startswith('vless://')):
                    all_raw_uris.extend(decoded.splitlines())
                else:
                    all_raw_uris.extend(text.splitlines())
                print(f"✔️ فایل معمولی خوانده شد: {link}")
        except Exception as e:
            print(f"❌ خطا در لینک {link}: {e}")

    print(f"\n✅ تعداد کل کانفیگ‌های استخراج شده: {len(all_raw_uris)}")
    print("🔄 در حال پردازش، حذف تکرار و دریافت پرچم‌ها (لطفا صبور باشید)...")

    index = 1
    for uri in all_raw_uris:
        uri = uri.strip()
        if not uri: continue
        
        # استخراج کلید یکتا (سرور و پورت)
        dedup_key, new_uri = parse_and_rename_uri(uri, index)
        
        if dedup_key and new_uri:
            if dedup_key not in unique_keys:
                unique_keys.add(dedup_key)
                final_uris.append(new_uri)
                print(f"✔️ پردازش شد: {index}. [{dedup_key}]")
                index += 1

    # ذخیره در فایل به صورت خام و دیکود شده (هر لینک در یک خط)
    final_sub_content = '\n'.join(final_uris)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(final_sub_content)
        
    print(f"\n🎉 پردازش تمام شد! تعداد نهایی بدون تکرار: {len(final_uris)}")
    print(f"📁 فایل خروجی دیکود شده: {OUTPUT_FILE}")

if __name__ == "__main__":
    process_subscriptions()
