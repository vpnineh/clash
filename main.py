import os
import requests
import base64
import yaml
import json
import urllib.parse
import time

# ==========================================
# ⚙️ تنظیمات اصلی
# ==========================================
SRC_FILE = "src.txt"
OUTPUT_FILE = "sub/sub"
REMARK_TEMPLATE = "{index}. @VPNine1 - {flag}"

LOCATION_CACHE = {}

# ==========================================
# 🛠 توابع کمکی پایه
# ==========================================

def get_country_flag(ip_or_domain):
    """دریافت پرچم با کش و توقف کوتاه برای جلوگیری از لیمیت شدن API"""
    if ip_or_domain in LOCATION_CACHE:
        return LOCATION_CACHE[ip_or_domain]
    
    try:
        time.sleep(1.2) # تاخیر برای جلوگیری از بن شدن توسط API
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
# 🧠 مبدل بومی (Middleware) کلش به V2ray
# ==========================================

def clash_to_uri(proxy):
    """تبدیل دقیق ساختار YAML کلش به لینک‌های استاندارد"""
    try:
        p_type = proxy.get('type')
        name = str(proxy.get('name', 'Proxy'))
        server = str(proxy.get('server', ''))
        port = str(proxy.get('port', ''))
        
        if not server or not port: return None

        # --- پردازش VMESS ---
        if p_type == 'vmess':
            v_json = {
                "v": "2", "ps": name, "add": server, "port": port,
                "id": str(proxy.get('uuid', '')),
                "aid": str(proxy.get('alterId', 0)),
                "scy": proxy.get('cipher', 'auto'),
                "net": proxy.get('network', 'tcp'),
                "type": "none", "host": "", "path": "", "tls": "",
                "sni": proxy.get('servername', '')
            }
            
            if proxy.get('tls'): v_json['tls'] = "tls"
            
            # تنظیمات وب‌سوکت
            if v_json['net'] == 'ws':
                ws_opts = proxy.get('ws-opts', {})
                v_json['path'] = ws_opts.get('path', '/')
                v_json['host'] = ws_opts.get('headers', {}).get('Host', '')
                
            # تنظیمات gRPC
            if v_json['net'] == 'grpc':
                v_json['path'] = proxy.get('grpc-opts', {}).get('grpc-service-name', '')

            return "vmess://" + encode_base64(json.dumps(v_json, separators=(',', ':')))

        # --- پردازش VLESS ---
        elif p_type == 'vless':
            uuid = str(proxy.get('uuid', ''))
            params = {"type": proxy.get('network', 'tcp')}
            
            if proxy.get('servername'): params['sni'] = proxy.get('servername')
            if proxy.get('flow'): params['flow'] = proxy.get('flow')

            # تنظیمات Reality و TLS
            if proxy.get('reality-opts'):
                params['security'] = 'reality'
                ro = proxy.get('reality-opts', {})
                params['pbk'] = ro.get('public-key', '')
                params['fp'] = proxy.get('client-fingerprint', 'chrome')
                if ro.get('short-id'): params['sid'] = ro.get('short-id')
            elif proxy.get('tls'):
                params['security'] = 'tls'
                params['fp'] = proxy.get('client-fingerprint', 'chrome')

            # وب‌سوکت
            if params['type'] == 'ws':
                ws_opts = proxy.get('ws-opts', {})
                params['path'] = ws_opts.get('path', '/')
                if 'headers' in ws_opts and 'Host' in ws_opts['headers']:
                    params['host'] = ws_opts['headers']['Host']

            # gRPC
            if params['type'] == 'grpc':
                params['serviceName'] = proxy.get('grpc-opts', {}).get('grpc-service-name', '')

            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            return f"vless://{uuid}@{server}:{port}?{query}#{urllib.parse.quote(name)}"

        # --- پردازش TROJAN ---
        elif p_type == 'trojan':
            password = str(proxy.get('password', ''))
            params = {"type": proxy.get('network', 'tcp')}
            
            if proxy.get('sni') or proxy.get('servername'):
                params['sni'] = proxy.get('sni', proxy.get('servername'))
                
            if proxy.get('skip-cert-verify') is not None or proxy.get('tls', True):
                params['security'] = 'tls'

            # وب‌سوکت
            if params['type'] == 'ws':
                ws_opts = proxy.get('ws-opts', {})
                params['path'] = ws_opts.get('path', '/')
                if 'headers' in ws_opts and 'Host' in ws_opts['headers']:
                    params['host'] = ws_opts['headers']['Host']

            # gRPC
            if params['type'] == 'grpc':
                params['serviceName'] = proxy.get('grpc-opts', {}).get('grpc-service-name', '')

            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            return f"trojan://{password}@{server}:{port}?{query}#{urllib.parse.quote(name)}"

    except Exception as e:
        print(f"⚠️ خطا در تبدیل یک گره: {e}")
        return None
    return None

# ==========================================
# 🔍 پردازش نهایی و تغییر نام
# ==========================================

def get_server_and_port(uri):
    """استخراج سرور و پورت برای حذف تکرار عمیق"""
    if uri.startswith("vmess://"):
        try:
            data = json.loads(decode_base64(uri[8:]))
            return str(data.get('add')), str(data.get('port'))
        except:
            return None, None
    else:
        try:
            base_uri = uri.split('#')[0] if '#' in uri else uri
            parsed = urllib.parse.urlparse(base_uri)
            return parsed.hostname, str(parsed.port)
        except:
            return None, None

def apply_new_remark(uri, index, flag):
    """تغییر نام گره‌ها"""
    new_name = REMARK_TEMPLATE.format(index=index, flag=flag)
    
    if uri.startswith("vmess://"):
        try:
            data = json.loads(decode_base64(uri[8:]))
            data['ps'] = new_name
            return "vmess://" + encode_base64(json.dumps(data, separators=(',', ':')))
        except:
            return uri
    else:
        try:
            base_uri = uri.split('#')[0]
            return f"{base_uri}#{urllib.parse.quote(new_name)}"
        except:
            return uri

# ==========================================
# 🚀 اجرای برنامه
# ==========================================

def process_subscriptions():
    if not os.path.exists(SRC_FILE):
        print(f"❌ فایل {SRC_FILE} یافت نشد!")
        return
        
    with open(SRC_FILE, 'r', encoding='utf-8') as f:
        sub_links = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not sub_links: return

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    all_raw_uris = []
    
    print("📥 در حال دریافت و استخراج کانفیگ‌ها...")
    
    for link in sub_links:
        try:
            response = requests.get(link, timeout=15)
            text = response.text.strip()
            
            # اگر فایل کلش باشد (YAML)
            if "proxies:" in text or text.startswith("port:"):
                print(f"🔄 در حال ترجمه مستقیم فایل کلش در داخل کد: {link}")
                yaml_data = yaml.safe_load(text)
                for proxy in yaml_data.get('proxies', []):
                    converted_uri = clash_to_uri(proxy)
                    if converted_uri:
                        all_raw_uris.append(converted_uri)
            else:
                # پردازش ساب‌های بیس۶۴ یا معمولی
                decoded = decode_base64(text)
                if decoded and any(proto in decoded for proto in ["vmess://", "vless://", "trojan://"]):
                    all_raw_uris.extend(decoded.splitlines())
                else:
                    all_raw_uris.extend(text.splitlines())
                print(f"✔️ ساب معمولی دریافت شد: {link}")
        except Exception as e:
            print(f"❌ خطا در دریافت لینک {link}: {e}")

    print(f"\n✅ مجموع کانفیگ‌ها استخراج شده: {len(all_raw_uris)}")
    print("🔄 در حال فیلتر و حذف تکراری‌ها (Deep Dedup)...")

    unique_configs = {}
    for uri in all_raw_uris:
        uri = uri.strip()
        if not uri or not uri.startswith(("vmess://", "vless://", "trojan://")): 
            continue
            
        server, port = get_server_and_port(uri)
        if server and port:
            dedup_key = f"{server}:{port}"
            if dedup_key not in unique_configs:
                unique_configs[dedup_key] = (server, uri)

    print(f"✅ تعداد کانفیگ‌های بدون تکرار: {len(unique_configs)}")
    print("🌐 در حال تشخیص پرچم کشورها (کمی زمان‌بر است)...")

    final_uris = []
    index = 1
    
    for dedup_key, (server, uri) in unique_configs.items():
        flag = get_country_flag(server)
        new_uri = apply_new_remark(uri, index, flag)
        final_uris.append(new_uri)
        print(f"✔️ پردازش شد: {index}. [{dedup_key}] - {flag}")
        index += 1

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_uris))
        
    print(f"\n🎉 با موفقیت به پایان رسید! تعداد نهایی: {len(final_uris)}")
    print(f"📁 فایل خروجی دیکود شده در مسیر: {OUTPUT_FILE} ذخیره شد.")

if __name__ == "__main__":
    process_subscriptions()