import os
import requests
import base64
import yaml
import json
import urllib.parse
import time
import sys

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
    if ip_or_domain in LOCATION_CACHE:
        return LOCATION_CACHE[ip_or_domain]
    
    try:
        time.sleep(1.2) # جلوگیری از لیمیت شدن API (ip-api.com)
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
    data = data + '=' * (-len(data) % 4)
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
# 🧠 مبدل بومی کلش به V2ray
# ==========================================

def clash_to_uri(proxy):
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
            if v_json['net'] == 'ws':
                v_json['path'] = proxy.get('ws-opts', {}).get('path', '/')
                v_json['host'] = proxy.get('ws-opts', {}).get('headers', {}).get('Host', '')
            if v_json['net'] == 'grpc':
                v_json['path'] = proxy.get('grpc-opts', {}).get('grpc-service-name', '')

            return "vmess://" + encode_base64(json.dumps(v_json, separators=(',', ':')))

        # --- پردازش VLESS ---
        elif p_type == 'vless':
            uuid = str(proxy.get('uuid', ''))
            params = {"type": proxy.get('network', 'tcp')}
            if proxy.get('servername'): params['sni'] = proxy.get('servername')
            if proxy.get('flow'): params['flow'] = proxy.get('flow')
            
            if proxy.get('reality-opts'):
                params['security'] = 'reality'
                ro = proxy.get('reality-opts', {})
                params['pbk'] = ro.get('public-key', '')
                params['fp'] = proxy.get('client-fingerprint', 'chrome')
                if ro.get('short-id'): params['sid'] = ro.get('short-id')
            elif proxy.get('tls'):
                params['security'] = 'tls'
                params['fp'] = proxy.get('client-fingerprint', 'chrome')

            if params['type'] == 'ws':
                params['path'] = proxy.get('ws-opts', {}).get('path', '/')
                params['host'] = proxy.get('ws-opts', {}).get('headers', {}).get('Host', '')
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

            if params['type'] == 'ws':
                params['path'] = proxy.get('ws-opts', {}).get('path', '/')
                params['host'] = proxy.get('ws-opts', {}).get('headers', {}).get('Host', '')
            if params['type'] == 'grpc':
                params['serviceName'] = proxy.get('grpc-opts', {}).get('grpc-service-name', '')

            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            return f"trojan://{password}@{server}:{port}?{query}#{urllib.parse.quote(name)}"

        # --- پردازش SHADOWSOCKS (SS) ---
        elif p_type == 'ss' or p_type == 'shadowsocks':
            cipher = proxy.get('cipher', 'auto')
            password = str(proxy.get('password', ''))
            
            user_info = f"{cipher}:{password}"
            user_info_b64 = encode_base64(user_info)
            
            plugin_str = ""
            plugin = proxy.get('plugin')
            if plugin:
                plugin_opts = proxy.get('plugin-opts', {})
                opts_list = [f"{k}={v}" for k, v in plugin_opts.items()]
                opts_str = ";".join(opts_list)
                plugin_str = f"/?plugin={urllib.parse.quote(f'{plugin};{opts_str}')}"

            return f"ss://{user_info_b64}@{server}:{port}{plugin_str}#{urllib.parse.quote(name)}"

        # --- پردازش پروکسی‌های نوع HTTP / HTTPS ---
        elif p_type == 'http':
            username = proxy.get('username', '')
            password = proxy.get('password', '')
            
            user_pass_str = ""
            if username or password:
                user_pass_str = encode_base64(f"{username}:{password}") + "@"
                
            scheme = "https" if proxy.get('tls') else "http"
            
            query_params = {}
            if proxy.get('skip-cert-verify'):
                query_params['skipCertVerify'] = 'true'
                
            query_str = ""
            if query_params:
                query_str = "?" + urllib.parse.urlencode(query_params)
                
            return f"{scheme}://{user_pass_str}{server}:{port}{query_str}#{urllib.parse.quote(name)}"

    except Exception as e:
        return None
    return None

# ==========================================
# 🔍 پردازش نهایی و تغییر نام
# ==========================================

def get_server_and_port(uri):
    if uri.startswith("vmess://"):
        try:
            data = json.loads(decode_base64(uri[8:]))
            return str(data.get('add')), str(data.get('port'))
        except:
            return None, None
            
    elif uri.startswith("ss://"):
        try:
            base_part = uri[5:].split('#')[0]
            if '@' not in base_part and '/' not in base_part:
                decoded = decode_base64(urllib.parse.unquote(base_part))
                if '@' in decoded:
                    server_port = decoded.split('@')[-1]
                    server, port = server_port.split(':')
                    return server, port
            parsed = urllib.parse.urlparse(uri if uri.startswith('ss://') else f"ss://{uri}")
            return parsed.hostname, str(parsed.port)
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

    if not sub_links: 
        print("⚠️ هیچ لینکی در فایل منابع یافت نشد.")
        return

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    all_raw_uris = []
    
    print("\n📥 [۱/۳] در حال بررسی و دریافت لینک‌های ساب...")
    total_links = len(sub_links)
    
    for idx, link in enumerate(sub_links, 1):
        # نمایش وضعیت بررسی زنده برای تک‌تک لینک‌ها
        short_link = link if len(link) <= 60 else link[:57] + "..."
        print(f" ⏳ [{idx}/{total_links}] در حال بررسی: {short_link} -> ", end="", flush=True)
        
        try:
            response = requests.get(link, timeout=15)
            if response.status_code != 200:
                print(f"❌ خطا (کد وضعیت: {response.status_code})")
                continue
                
            text = response.text.strip()
            count_before = len(all_raw_uris)
            
            if "proxies:" in text or text.startswith("port:"):
                yaml_data = yaml.safe_load(text)
                for proxy in yaml_data.get('proxies', []):
                    converted_uri = clash_to_uri(proxy)
                    if converted_uri:
                        all_raw_uris.append(converted_uri)
            else:
                decoded = decode_base64(text)
                if decoded and any(proto in decoded for proto in ["vmess://", "vless://", "trojan://", "ss://", "http://", "https://"]):
                    all_raw_uris.extend(decoded.splitlines())
                else:
                    all_raw_uris.extend(text.splitlines())
            
            extracted = len(all_raw_uris) - count_before
            print(f"✅ موفق ({extracted} کانفیگ استخراج شد)")
            
        except Exception as e:
            print(f"❌ خطا در اتصال ({str(e)[:30]})")

    if not all_raw_uris:
        print("\n❌ هیچ کانفیگی یافت نشد عملیات متوقف شد.")
        return

    print(f"\n🔄 [۲/۳] در حال فیلتر و حذف تکراری‌ها (Deep Dedup)...")
    unique_configs = {}
    for uri in all_raw_uris:
        uri = uri.strip()
        if not uri or not uri.startswith(("vmess://", "vless://", "trojan://", "ss://", "http://", "https://")): 
            continue
            
        server, port = get_server_and_port(uri)
        if server and port:
            dedup_key = f"{server}:{port}"
            if dedup_key not in unique_configs:
                unique_configs[dedup_key] = (server, uri)

    total_unique = len(unique_configs)
    print(f" ✅ تعداد کانفیگ‌های بدون تکرار و خالص: {total_unique}")
    
    print("\n🌐 [۳/۳] در حال تشخیص پرچم کشورها (Geolocation)...")
    final_uris = []
    index = 1
    
    for dedup_key, (server, uri) in unique_configs.items():
        # ساخت نوار پیشرفت پویا (Progress Bar)
        percent = int((index / total_unique) * 100)
        bar_length = 30
        filled_length = int(bar_length * index // total_unique)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        # چاپ وضعیت به روز رسانی خط به صورت ریل‌تایم با \r
        sys.stdout.write(f"\r 🔄 پیشرفت عملیات: |{bar}| {percent}% ({index}/{total_unique}) [سرور فعلی: {server[:15]}]")
        sys.stdout.flush()
        
        flag = get_country_flag(server)
        new_uri = apply_new_remark(uri, index, flag)
        final_uris.append(new_uri)
        index += 1

    print("\n ✅ پردازش پرچم‌ها با موفقیت کامل شد.")

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_uris))
        
    print(f"\n🎉 با موفقیت به پایان رسید! تعداد کل کانفیگ‌های نهایی: {len(final_uris)}")
    print(f"📁 فایل خروجی دیکود شده در مسیر: {OUTPUT_FILE} ذخیره شد.\n")

if __name__ == "__main__":
    process_subscriptions()
