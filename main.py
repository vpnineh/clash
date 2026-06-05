import os
import requests
import base64
import yaml
import json
import urllib.parse
import sys
import socket
import geoip2.database
from concurrent.futures import ThreadPoolExecutor

# ==========================================
# ⚙️ تنظیمات اصلی
# ==========================================
SRC_FILE = "src.txt"
OUTPUT_FILE = "sub/sub"
BRAND_NAME = "@VPNine1"
MAX_THREADS = 50

# مسیر فایل‌های دیتابیس آفلاین
CITY_DB_PATH = "GeoLite2-City.mmdb"
ASN_DB_PATH = "GeoLite2-ASN.mmdb"

GEO_CACHE = {}
VALID_PROTOCOLS = ("vmess://", "vless://", "trojan://", "ss://", "http://", "https://", "hysteria://", "hysteria2://", "hy2://")

# ==========================================
# 🛠 توابع پردازش Geo و شبکه
# ==========================================

def clean_isp_name(isp):
    if not isp: return "Unknown"
    remove_words = [' LLC', ' Inc.', ' Ltd.', ' Corporation', ' Corp.', ' GmbH', ' AS', ' PLC', ' OOO', ' S.A.', ' S.R.O.']
    for word in remove_words:
        isp = isp.replace(word, '').replace(word.lower(), '')
    cleaned = isp.split(',')[0].strip()
    return cleaned[:15]

def get_geo_info(server):
    if server in GEO_CACHE:
        return GEO_CACHE[server]
        
    cc = "UN"
    flag = "🏴"
    datacenter = "Unknown"
    
    try:
        ip = socket.gethostbyname(server)
    except:
        GEO_CACHE[server] = (flag, cc, datacenter)
        return flag, cc, datacenter

    if os.path.exists(CITY_DB_PATH):
        try:
            with geoip2.database.Reader(CITY_DB_PATH) as reader:
                response = reader.city(ip)
                if response.country.iso_code:
                    cc = response.country.iso_code
                    flag = chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
        except: pass

    if os.path.exists(ASN_DB_PATH):
        try:
            with geoip2.database.Reader(ASN_DB_PATH) as reader:
                response = reader.asn(ip)
                if response.autonomous_system_organization:
                    datacenter = clean_isp_name(response.autonomous_system_organization)
        except: pass

    result = (flag, cc, datacenter)
    GEO_CACHE[server] = result
    return result

# ==========================================
# 🧠 مبدل بومی تمام پروتکل‌ها به V2ray/Xray URIs
# ==========================================

def decode_base64(data):
    data = data.strip()
    data = data + '=' * (-len(data) % 4)
    try:
        return base64.b64decode(data).decode('utf-8')
    except:
        try:
            return base64.urlsafe_b64decode(data).decode('utf-8')
        except: return ""

def encode_base64(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def clash_to_uri(proxy):
    try:
        p_type = proxy.get('type', '').lower()
        name = str(proxy.get('name', 'Proxy'))
        server = str(proxy.get('server', ''))
        port = str(proxy.get('port', ''))
        
        if not server or not port: return None

        # --- ۱. پردازش VMESS ---
        if p_type == 'vmess':
            v_json = {
                "v": "2", "ps": name, "add": server, "port": port,
                "id": str(proxy.get('uuid', '')), "aid": str(proxy.get('alterId', 0)),
                "scy": proxy.get('cipher', 'auto'), "net": proxy.get('network', 'tcp'),
                "type": "none", "host": "", "path": "", "tls": "", "sni": proxy.get('servername', '')
            }
            if proxy.get('tls'): v_json['tls'] = "tls"
            if v_json['net'] == 'ws':
                v_json['path'] = proxy.get('ws-opts', {}).get('path', '/')
                v_json['host'] = proxy.get('ws-opts', {}).get('headers', {}).get('Host', '')
            if v_json['net'] == 'grpc':
                v_json['path'] = proxy.get('grpc-opts', {}).get('grpc-service-name', '')
            return "vmess://" + encode_base64(json.dumps(v_json, separators=(',', ':')))

        # --- ۲. پردازش VLESS ---
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

        # --- ۳. پردازش TROJAN ---
        elif p_type == 'trojan':
            password = str(proxy.get('password', ''))
            params = {"type": proxy.get('network', 'tcp')}
            if proxy.get('sni') or proxy.get('servername'): params['sni'] = proxy.get('sni', proxy.get('servername'))
            if proxy.get('skip-cert-verify') is not None or proxy.get('tls', True): params['security'] = 'tls'
            if params['type'] == 'ws':
                params['path'] = proxy.get('ws-opts', {}).get('path', '/')
                params['host'] = proxy.get('ws-opts', {}).get('headers', {}).get('Host', '')
            if params['type'] == 'grpc':
                params['serviceName'] = proxy.get('grpc-opts', {}).get('grpc-service-name', '')
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            return f"trojan://{password}@{server}:{port}?{query}#{urllib.parse.quote(name)}"

        # --- ۴. پردازش SHADOWSOCKS ---
        elif p_type in ['ss', 'shadowsocks']:
            cipher = proxy.get('cipher', 'auto')
            password = str(proxy.get('password', ''))
            user_info_b64 = encode_base64(f"{cipher}:{password}")
            plugin_str = ""
            if proxy.get('plugin'):
                plugin_opts = proxy.get('plugin-opts', {})
                opts_str = ";".join([f"{k}={v}" for k, v in plugin_opts.items()])
                plugin_str = f"/?plugin={urllib.parse.quote(f'{proxy.get('plugin')};{opts_str}')}"
            return f"ss://{user_info_b64}@{server}:{port}{plugin_str}#{urllib.parse.quote(name)}"

        # --- ۵. پردازش HTTP / HTTPS ---
        elif p_type == 'http':
            username = proxy.get('username', '')
            password = proxy.get('password', '')
            user_pass_str = encode_base64(f"{username}:{password}") + "@" if username or password else ""
            scheme = "https" if proxy.get('tls') else "http"
            query_str = "?skipCertVerify=true" if proxy.get('skip-cert-verify') else ""
            return f"{scheme}://{user_pass_str}{server}:{port}{query_str}#{urllib.parse.quote(name)}"

        # --- ۶. پردازش HYSTERIA (نسخه ۱) ---
        elif p_type == 'hysteria':
            auth = proxy.get('auth-str', proxy.get('auth_str', ''))
            params = {
                "peer": proxy.get('sni', proxy.get('servername', '')),
                "insecure": "1" if proxy.get('skip-cert-verify') else "0",
                "upmbps": str(proxy.get('up', '')).findall(r'\d+')[0] if proxy.get('up') else "",
                "downmbps": str(proxy.get('down', '')).findall(r'\d+')[0] if proxy.get('down') else "",
                "alpn": proxy.get('alpn', ['hysteria'])[0]
            }
            if auth: params['auth'] = auth
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            return f"hysteria://{server}:{port}?{query}#{urllib.parse.quote(name)}"

        # --- ۷. پردازش HYSTERIA 2 (Hy2) ---
        elif p_type in ['hysteria2', 'hy2']:
            password = proxy.get('password', '')
            params = {
                "sni": proxy.get('sni', proxy.get('servername', '')),
                "insecure": "1" if proxy.get('skip-cert-verify') else "0",
            }
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            return f"hysteria2://{password}@{server}:{port}?{query}#{urllib.parse.quote(name)}"

    except Exception: return None
    return None

def get_server_and_port(uri):
    if uri.startswith("vmess://"):
        try:
            data = json.loads(decode_base64(uri[8:]))
            return str(data.get('add')), str(data.get('port'))
        except: return None, None
    elif uri.startswith("ss://"):
        try:
            base_part = uri[5:].split('#')[0]
            if '@' not in base_part and '/' not in base_part:
                decoded = decode_base64(urllib.parse.unquote(base_part))
                if '@' in decoded: return decoded.split('@')[-1].split(':')
            parsed = urllib.parse.urlparse(uri if uri.startswith('ss://') else f"ss://{uri}")
            return parsed.hostname, str(parsed.port)
        except: return None, None
    else:
        try:
            parsed = urllib.parse.urlparse(uri.split('#')[0] if '#' in uri else uri)
            return parsed.hostname, str(parsed.port)
        except: return None, None

def apply_new_remark(uri, new_name):
    if uri.startswith("vmess://"):
        try:
            data = json.loads(decode_base64(uri[8:]))
            data['ps'] = new_name
            return "vmess://" + encode_base64(json.dumps(data, separators=(',', ':')))
        except: return uri
    else:
        try: return f"{uri.split('#')[0]}#{urllib.parse.quote(new_name)}"
        except: return uri

# ==========================================
# 🚀 اجرای برنامه متمرکز بر سرعت و تنوع پروتکل
# ==========================================

def process_geo_parallel(unique_configs):
    servers = list(set([server for server, uri in unique_configs.values()]))
    total = len(servers)
    print(f"\n⚡️ [۳/۴] استخراج آفلاین دیتاسنتر و لوکیشن ({MAX_THREADS} پردازش همزمان)...")
    completed = 0
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for server in executor.map(lambda s: (s, get_geo_info(s)), servers):
            completed += 1
            percent = int((completed / total) * 100)
            sys.stdout.write(f"\r 🔄 پیشرفت: |{'█' * (percent // 3)}{'░' * (33 - (percent // 3))}| {percent}%")
            sys.stdout.flush()
    print("\n✅ پردازش آفلاین با موفقیت تکمیل شد.")

def process_subscriptions():
    if not os.path.exists(SRC_FILE):
        print(f"❌ فایل {SRC_FILE} یافت نشد!")
        return
        
    with open(SRC_FILE, 'r', encoding='utf-8') as f:
        sub_links = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not sub_links: return

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    all_raw_uris = []
    
    print("\n📥 [۱/۴] دریافت لینک‌های ساب و استخراج محتوا...")
    for idx, link in enumerate(sub_links, 1):
        print(f" ⏳ [{idx}/{len(sub_links)}] بررسی: {link[:50]}... -> ", end="", flush=True)
        try:
            response = requests.get(link, timeout=15)
            if response.status_code != 200:
                print(f"❌ خطا ({response.status_code})")
                continue
            text = response.text.strip()
            count_before = len(all_raw_uris)
            
            if "proxies:" in text or "proxy-providers:" in text or text.startswith("port:"):
                try:
                    yaml_data = yaml.safe_load(text)
                except Exception:
                    print(" ❌ خطا در پارس YAML")
                    continue

                # ۱. استخراج از بخش proxies داخلی فایل
                for proxy in (yaml_data.get('proxies') or []):
                    converted = clash_to_uri(proxy)
                    if converted: all_raw_uris.append(converted)
                
                # ۲. استخراج از لینک‌های proxy-providers (اصلاح‌شده برای پشتیبانی کامل از Base64 و YAML)
                providers = yaml_data.get('proxy-providers', {})
                if isinstance(providers, dict):
                    for p_name, p_data in providers.items():
                        if isinstance(p_data, dict) and p_data.get('type') == 'http' and 'url' in p_data:
                            try:
                                provider_url = p_data['url']
                                p_resp = requests.get(provider_url, timeout=15)
                                if p_resp.status_code == 200:
                                    p_text = p_resp.text.strip()
                                    # بررسی می‌کنیم که آیا محتوای لینک ساب، YAML است یا Base64/URI
                                    if "proxies:" in p_text or p_text.startswith("port:"):
                                        try:
                                            p_yaml = yaml.safe_load(p_text)
                                            for proxy in (p_yaml.get('proxies') or []):
                                                converted = clash_to_uri(proxy)
                                                if converted: all_raw_uris.append(converted)
                                        except: pass
                                    else:
                                        # اگر YAML نبود (مثل لینک WangCai)، اینجا Base64 دیکد می‌شود
                                        decoded = decode_base64(p_text)
                                        if decoded and any(pr in decoded for pr in VALID_PROTOCOLS):
                                            all_raw_uris.extend(decoded.splitlines())
                                        else:
                                            all_raw_uris.extend(p_text.splitlines())
                            except Exception:
                                pass # چشم‌پوشی از خطای تایم‌اوت در پرووایدر خاص
            else:
                decoded = decode_base64(text)
                if decoded and any(p in decoded for p in VALID_PROTOCOLS):
                    all_raw_uris.extend(decoded.splitlines())
                else:
                    all_raw_uris.extend(text.splitlines())
            print(f"✅ ({len(all_raw_uris) - count_before} کانفیگ)")
        except Exception: print("❌ خطا")

    print("\n🔄 [۲/۴] اجرای Deep Dedup (حذف تکراری‌های عمیق)...")
    unique_configs = {}
    for uri in all_raw_uris:
        uri = uri.strip()
        if not uri or not uri.startswith(VALID_PROTOCOLS): continue
        server, port = get_server_and_port(uri)
        if server and port:
            dedup_key = f"{server}:{port}"
            if dedup_key not in unique_configs:
                unique_configs[dedup_key] = (server, uri)
    print(f" ✅ کانفیگ‌های یکتا: {len(unique_configs)}")

    process_geo_parallel(unique_configs)

    print("\n🏷 [۴/۴] فرمت‌بندی و اختصاص شماره یکتا به کشورها...")
    grouped_by_cc = {}
    for dedup_key, (server, uri) in unique_configs.items():
        flag, cc, datacenter = get_geo_info(server)
        if cc not in grouped_by_cc: grouped_by_cc[cc] = []
        grouped_by_cc[cc].append((uri, flag, cc, datacenter))

    final_uris = []
    for cc, items in grouped_by_cc.items():
        for index, (uri, flag, code, datacenter) in enumerate(items, 1):
            # خروجی فوق حرفه‌ای درخواستی شما همراه با برند کانال
            new_name = f"{flag} {code} {datacenter} #{index} {BRAND_NAME}"
            final_uris.append(apply_new_remark(uri, new_name))

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_uris))
        
    print(f"\n🎉 اتمام پردازش! خروجی نهایی: {len(final_uris)} کانفیگ باکیفیت و همه‌جانبه.")
    print(f"📁 ذخیره در: {OUTPUT_FILE}\n")

if __name__ == "__main__":
    process_subscriptions()
