"""
Nexus Vision  –  Tactical Network Intelligence Platform
====================================================
All data displayed is REAL – no simulation, no random values.
Sources:
  - ARP table  (/proc/net/arp  on Linux/Android,  arp -a  on Windows)
  - WiFi AP scan via WifiManager  (Android)
  - Bluetooth paired devices  (Android)
  - TCP connection table  (/proc/net/tcp  +  /proc/net/tcp6)
  - DNS reverse lookup for IP → hostname resolution

What CAN be seen without root:
  - Every device currently on your LAN (MAC + IP + manufacturer)
  - Your own device's active TCP connections + which service each uses
  - On Android hotspot mode: all client device connections route through you

What REQUIRES root or gateway position:
  - Reading other devices' TCP connections
  - Inspecting packet payloads
  - Throttling / blocking other devices at the OS level

Note on E2E-encrypted apps (WhatsApp, Instagram DMs):
  Even with full network access, message CONTENT cannot be read –
  both apps use end-to-end encryption.  What IS visible:
    - "Device X connected to whatsapp.net:443"  → using WhatsApp
    - Bytes transferred, timing, frequency
    - Which service, NOT what was said.
"""

import json, math, os, platform, re, socket, struct, subprocess, threading, time
from datetime import datetime
from pathlib import Path

from kivy.app               import App
from kivy.clock             import Clock
from kivy.core.window       import Window
from kivy.graphics          import Color, Ellipse, Line, Rectangle, RoundedRectangle
from kivy.metrics           import dp, sp
from kivy.uix.boxlayout     import BoxLayout
from kivy.uix.button        import Button
from kivy.uix.label         import Label
from kivy.uix.scrollview    import ScrollView
from kivy.uix.screenmanager import Screen, ScreenManager, FadeTransition
from kivy.uix.widget        import Widget
from kivy.utils             import platform as kivy_platform

# ─── Android bridge ──────────────────────────────────────────────────────────
ANDROID = kivy_platform == 'android'
if ANDROID:
    try:
        from jnius import autoclass
        _PythonActivity  = autoclass('org.kivy.android.PythonActivity')
        _Context         = autoclass('android.content.Context')
        _WifiManager     = autoclass('android.net.wifi.WifiManager')
        _BTAdapter       = autoclass('android.bluetooth.BluetoothAdapter')
        _Build           = autoclass('android.os.Build')
        _Environment     = autoclass('android.os.Environment')
    except Exception:
        ANDROID = False

# ─── Palette ─────────────────────────────────────────────────────────────────
BG   = (0.02, 0.05, 0.02, 1.00)
G1   = (0.22, 1.00, 0.08, 1.00)
G2   = (0.22, 1.00, 0.08, 0.55)
G3   = (0.22, 1.00, 0.08, 0.18)
G4   = (0.22, 1.00, 0.08, 0.07)
RED  = (1.00, 0.20, 0.10, 1.00)
YEL  = (1.00, 0.85, 0.10, 1.00)
CYN  = (0.10, 0.90, 1.00, 1.00)   # camera / smart devices
WHT  = (0.92, 1.00, 0.92, 1.00)   # Apple

# ─── OUI → Manufacturer  (expanded – 200+ entries) ───────────────────────────
_OUI = {
    # Apple
    "00:17:F2":"Apple",  "28:37:37":"Apple",  "3C:15:C2":"Apple",
    "A4:C3:61":"Apple",  "F0:18:98":"Apple",  "18:9E:FC":"Apple",
    "DC:A9:04":"Apple",  "F4:31:C3":"Apple",  "28:6A:B8":"Apple",
    "AC:BC:32":"Apple",  "34:36:3B":"Apple",  "00:F4:B9":"Apple",
    "A8:96:8A":"Apple",  "80:ED:2C":"Apple",  "58:40:4E":"Apple",
    "D0:03:4B":"Apple",  "8C:85:90":"Apple",  "70:EC:E4":"Apple",
    "14:98:77":"Apple",  "F0:99:BF":"Apple",  "04:26:65":"Apple",
    "60:FB:42":"Apple",  "3C:06:30":"Apple",  "98:01:A7":"Apple",
    # Samsung
    "00:07:AB":"Samsung","00:12:FB":"Samsung","00:26:37":"Samsung",
    "50:32:37":"Samsung","78:1F:DB":"Samsung","CC:07:AB":"Samsung",
    "F4:42:8F":"Samsung","8C:77:12":"Samsung","A4:23:05":"Samsung",
    "54:88:0E":"Samsung","2C:54:CF":"Samsung","E8:03:9A":"Samsung",
    "FC:A6:67":"Samsung","4C:BC:A5":"Samsung","88:32:9B":"Samsung",
    "5C:3C:27":"Samsung","18:3A:2D":"Samsung","A0:82:1F":"Samsung",
    "00:16:32":"Samsung","04:18:D6":"Samsung","A8:9C:ED":"Samsung",
    # Google / Pixel
    "54:60:09":"Google", "F4:F5:D8":"Google", "1C:F2:9A":"Google",
    "A4:77:33":"Google", "3C:5A:B4":"Google", "48:D6:D5":"Google",
    "94:EB:2C":"Google", "20:DF:B9":"Google",
    # Huawei
    "00:E0:FC":"Huawei", "04:BD:70":"Huawei", "70:72:3C":"Huawei",
    "A0:08:6F":"Huawei", "D4:6E:5C":"Huawei", "04:F9:38":"Huawei",
    "28:6E:D4":"Huawei", "BC:25:E0":"Huawei", "48:DB:50":"Huawei",
    "9C:28:EF":"Huawei", "D8:C8:E9":"Huawei", "FC:48:EF":"Huawei",
    "2C:AB:00":"Huawei", "08:19:A6":"Huawei", "70:A8:E3":"Huawei",
    # Xiaomi
    "00:9E:C8":"Xiaomi", "28:E3:1F":"Xiaomi", "50:64:2B":"Xiaomi",
    "64:CC:2E":"Xiaomi", "74:23:44":"Xiaomi", "AC:C1:EE":"Xiaomi",
    "18:59:36":"Xiaomi", "34:80:B3":"Xiaomi", "A4:0B:FB":"Xiaomi",
    "58:44:98":"Xiaomi", "10:2A:B3":"Xiaomi", "F4:8B:32":"Xiaomi",
    "78:11:DC":"Xiaomi", "B0:E2:35":"Xiaomi", "20:34:FB":"Xiaomi",
    # OnePlus / OPPO / Vivo / Realme / BBK
    "08:7A:4C":"OnePlus","94:65:2D":"OPPO",   "60:AB:67":"Realme",
    "A4:50:46":"OPPO",   "34:14:5F":"OPPO",   "E4:3C:1A":"Vivo",
    "B8:AD:3E":"Vivo",   "94:87:E0":"Vivo",   "38:BC:01":"Realme",
    "10:1F:74":"Realme", "08:2E:5F":"OnePlus","F4:60:E2":"OnePlus",
    # LG
    "00:1E:75":"LG",     "A8:16:B2":"LG",     "78:5D:C8":"LG",
    "CC:FA:00":"LG",     "00:E0:91":"LG",     "98:93:CC":"LG",
    # Sony
    "00:24:EF":"Sony",   "30:17:C8":"Sony",   "FC:0F:E6":"Sony",
    "00:19:7D":"Sony",   "18:00:2D":"Sony",   "70:2E:D9":"Sony",
    # Motorola
    "B4:AE:2B":"Motorola","00:08:6A":"Motorola","00:16:FE":"Motorola",
    "AC:37:43":"Motorola","58:55:CA":"Motorola","A0:F4:79":"Motorola",
    # Nokia / HMD
    "34:4D:F7":"Nokia",  "00:21:05":"Nokia",  "8C:45:00":"Nokia",
    "E8:F5:E6":"Nokia",  "D4:20:B0":"Nokia",
    # Microsoft
    "00:50:F2":"Microsoft","28:18:78":"Microsoft","70:77:81":"Microsoft",
    "7C:1E:52":"Microsoft","48:50:73":"Microsoft","00:15:5D":"Microsoft",
    # Intel WiFi/BT
    "00:16:EA":"Intel",  "8C:8D:28":"Intel",  "C8:5B:76":"Intel",
    "34:02:86":"Intel",  "A0:36:9F":"Intel",  "B0:6E:BF":"Intel",
    "D0:37:45":"Intel",  "AC:7B:A1":"Intel",  "9C:B6:D0":"Intel",
    # Qualcomm
    "00:02:6F":"Qualcomm","E4:46:DA":"Qualcomm",
    # MediaTek
    "00:0C:E7":"MediaTek",
    # TP-Link
    "00:27:19":"TP-Link","50:C7:BF":"TP-Link","A0:C5:62":"TP-Link",
    "EC:08:6B":"TP-Link","98:DA:C4":"TP-Link","54:A7:03":"TP-Link",
    "AC:15:A2":"TP-Link","50:FA:84":"TP-Link","E8:DE:27":"TP-Link",
    "C4:6E:1F":"TP-Link","30:DE:4B":"TP-Link","18:A6:F7":"TP-Link",
    # Netgear
    "00:14:6C":"Netgear","20:4E:7F":"Netgear","A0:40:A0":"Netgear",
    "C0:FF:D4":"Netgear","28:C6:8E":"Netgear","84:1B:5E":"Netgear",
    # Cisco / Linksys
    "00:00:0C":"Cisco",  "00:1B:D5":"Cisco",  "00:50:56":"Cisco",
    "58:BC:27":"Cisco",  "00:23:04":"Cisco",  "E8:48:B8":"Cisco",
    "C8:9C:1D":"Linksys","00:18:39":"Linksys","00:1C:10":"Linksys",
    # D-Link
    "00:18:8B":"DLink",  "14:D6:4D":"DLink",  "1C:7E:E5":"DLink",
    "28:10:7B":"DLink",  "84:C9:B2":"DLink",  "B0:C5:54":"DLink",
    # Tenda / Mercusys / Xiaomi-WiFi
    "C8:3A:35":"Tenda",  "C8:D7:19":"Tenda",  "CC:B2:55":"Tenda",
    "48:7D:2E":"Mercusys","74:DA:DA":"Edimax", "74:FE:CE":"Edimax",
    # Raspberry Pi
    "B8:27:EB":"RaspberryPi","DC:A6:32":"RaspberryPi","E4:5F:01":"RaspberryPi",
    # Amazon Echo / Kindle / Fire
    "FC:65:DE":"Amazon", "40:B4:CD":"Amazon", "74:C2:46":"Amazon",
    "34:D2:70":"Amazon", "A4:08:01":"Amazon", "00:FC:8B":"Amazon",
    # Asus
    "00:1A:92":"Asus",   "04:D9:F5":"Asus",   "10:BF:48":"Asus",
    "2C:56:DC":"Asus",   "30:85:A9":"Asus",   "50:46:5D":"Asus",
    # Lenovo
    "00:22:FB":"Lenovo", "28:D2:44":"Lenovo", "54:EE:75":"Lenovo",
    "98:FA:9B":"Lenovo", "F8:16:54":"Lenovo",
    # Dell
    "00:14:22":"Dell",   "18:03:73":"Dell",   "F8:DB:88":"Dell",
    "00:26:B9":"Dell",   "B8:85:84":"Dell",
    # HP
    "00:17:A4":"HP",     "3C:D9:2B":"HP",     "70:5A:0F":"HP",
    "9C:8E:99":"HP",
    # Zebra / Honeywell / Datalogic (warehouses)
    "00:A0:F8":"Zebra",  "AC:3F:A4":"Zebra",
    # Bosch / Siemens / Philips (IoT)
    "00:07:B4":"Bosch",  "A4:CF:12":"Espressif",
    "24:6F:28":"Espressif","30:AE:A4":"Espressif",
    "84:F3:EB":"Espressif","B4:E6:2D":"Espressif",
}

# ─── Known TCP services (port + domain fragment → label) ─────────────────────
_PORT_SVC = {
    80:    "HTTP",    443:   "HTTPS",   22:  "SSH",
    21:    "FTP",     25:    "SMTP",    587: "SMTP",
    993:   "IMAP",    995:   "POP3",    53:  "DNS",
    3306:  "MySQL",   5432:  "Postgres",6379:"Redis",
    5222:  "XMPP",    5228:  "GCM/FCM", 1935:"RTMP/Stream",
    8080:  "HTTP-Alt",8443:  "HTTPS-Alt",
    19305: "WebRTC",  3478:  "STUN",    5349:"STUNS",
}

_DOMAIN_SVC = [
    ("whatsapp.net",       "WhatsApp"),
    ("whatsapp.com",       "WhatsApp"),
    ("wa.me",              "WhatsApp"),
    ("instagram.com",      "Instagram"),
    ("cdninstagram.com",   "Instagram"),
    ("fbcdn.net",          "Facebook"),
    ("facebook.com",       "Facebook"),
    ("fb.com",             "Facebook"),
    ("twitter.com",        "Twitter/X"),
    ("twimg.com",          "Twitter/X"),
    ("t.co",               "Twitter/X"),
    ("tiktok.com",         "TikTok"),
    ("byteoversea.com",    "TikTok"),
    ("tiktokcdn.com",      "TikTok"),
    ("youtube.com",        "YouTube"),
    ("googlevideo.com",    "YouTube"),
    ("ytimg.com",          "YouTube"),
    ("netflix.com",        "Netflix"),
    ("nflxvideo.net",      "Netflix"),
    ("telegram.org",       "Telegram"),
    ("snapchat.com",       "Snapchat"),
    ("snap.com",           "Snapchat"),
    ("icloud.com",         "iCloud"),
    ("apple.com",          "Apple"),
    ("mzstatic.com",       "AppStore"),
    ("gstatic.com",        "Google"),
    ("googleapis.com",     "Google"),
    ("google.com",         "Google"),
    ("amazon.com",         "Amazon"),
    ("amazonaws.com",      "AWS/Amazon"),
    ("microsoft.com",      "Microsoft"),
    ("live.com",           "Microsoft"),
    ("office.com",         "Microsoft365"),
    ("spotify.com",        "Spotify"),
    ("akamaized.net",      "Akamai CDN"),
    ("cloudflare.com",     "Cloudflare"),
    ("1.1.1.1",            "Cloudflare DNS"),
    ("8.8.8.8",            "Google DNS"),
]


_OUI_EXT:   dict = {}   # loaded from oui.json at runtime
_OUI_CACHE: dict = {}   # runtime cache for live API lookups
_OUI_CACHE_PATH: str = ""

# ─── Live OUI APIs (tried in order) ──────────────────────────────────────────
_OUI_APIS = [
    "https://api.macvendors.com/{mac}",                  # returns plain text
    "https://api.maclookup.app/v2/macs/{mac}/company/name",  # plain text
]

def _oui_cache_path() -> str:
    global _OUI_CACHE_PATH
    if _OUI_CACHE_PATH:
        return _OUI_CACHE_PATH
    candidates = [os.path.dirname(os.path.abspath(__file__)), os.getcwd()]
    if ANDROID:
        candidates = [
            "/data/data/org.nexus.vision/files",
            os.environ.get("ANDROID_PRIVATE", "/data/data/org.nexus.vision/files"),
        ] + candidates
    for d in candidates:
        try:
            p = os.path.join(d, "oui_cache.json")
            open(p, "a").close()
            _OUI_CACHE_PATH = p
            return p
        except Exception:
            pass
    return ""

def _load_oui_json():
    """Load extended OUI table from oui.json + persisted live cache."""
    global _OUI_EXT, _OUI_CACHE
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.json"),
        os.path.join(os.getcwd(), "oui.json"),
    ]
    if ANDROID:
        candidates += [
            "/data/data/org.nexus.vision/files/oui.json",
            os.path.join(os.environ.get("ANDROID_PRIVATE", ""), "oui.json"),
        ]
    for path in candidates:
        try:
            with open(path, encoding="utf-8") as f:
                _OUI_EXT = json.load(f)
            break
        except Exception:
            pass
    # Load persisted live-lookup cache
    cp = _oui_cache_path()
    if cp:
        try:
            with open(cp, encoding="utf-8") as f:
                _OUI_CACHE = json.load(f)
        except Exception:
            _OUI_CACHE = {}

_load_oui_json()

def _oui_live_lookup(mac: str) -> str:
    """Query live API for unknown MAC prefix (runs in background thread only)."""
    prefix = mac.upper()[:8]
    if prefix in _OUI_CACHE:
        return _OUI_CACHE[prefix]
    # Skip pseudo / broadcast MACs
    if mac.startswith(("FE:FF", "FD:FE", "FF:FF", "00:00")):
        return "Unknown"
    try:
        import urllib.request as _ur
        for api in _OUI_APIS:
            try:
                url = api.format(mac=mac.replace(":", "-")[:8])
                req = _ur.Request(url, headers={"User-Agent": "NexusVision/1.0"})
                with _ur.urlopen(req, timeout=4) as r:
                    vendor = r.read().decode("utf-8", errors="ignore").strip()
                if vendor and len(vendor) < 80 and "error" not in vendor.lower():
                    # Persist to cache
                    _OUI_CACHE[prefix] = vendor
                    cp = _oui_cache_path()
                    if cp:
                        try:
                            with open(cp, "w", encoding="utf-8") as f:
                                json.dump(_OUI_CACHE, f)
                        except Exception:
                            pass
                    return vendor
            except Exception:
                continue
    except Exception:
        pass
    _OUI_CACHE[prefix] = "Unknown"
    return "Unknown"

def _oui(mac: str) -> str:
    """Look up manufacturer from MAC address.
    Priority: inline dict → oui.json → live API cache → 'Unknown'."""
    m = mac.upper()
    # 1. Full 8-char prefix (XX:XX:XX)
    v = _OUI.get(m[:8]) or _OUI_EXT.get(m[:8]) or _OUI_CACHE.get(m[:8])
    if v and v != "Unknown":
        return v
    # 2. Short 5-char prefix (XX:XX) for wildcard entries
    v = _OUI.get(m[:5]) or _OUI_EXT.get(m[:5])
    if v and v != "Unknown":
        return v
    # 3. Check live cache only (never blocks – API call is always async)
    return _OUI_CACHE.get(m[:8], "Unknown")


def _guess_os(mfr: str) -> str:
    if mfr == "Apple":
        return "iOS/macOS"
    if mfr in {"Samsung", "Google", "Huawei", "Xiaomi", "OnePlus", "OPPO",
               "Realme", "LG", "Sony", "Motorola", "Nokia", "Vivo",
               "Infinix", "Tecno", "Itel", "ZTE", "Meizu", "HTC",
               "TCL", "Alcatel", "BlackBerry", "Honor", "Nothing",
               "Fairphone", "Redmi", "POCO"}:
        return "Android"
    if mfr in {"Cisco", "Netgear", "TP-Link", "DLink", "Tenda",
               "Linksys", "Mercusys", "Edimax"}:
        return "Router/AP"
    if mfr in {"Hikvision", "Dahua", "Axis", "Reolink", "Arlo",
               "Nest", "Wyze", "Espressif"}:
        return "Camera/IoT"
    if mfr == "Microsoft":
        return "Windows"
    if mfr in {"Intel", "Realtek", "Dell", "HP"}:
        return "PC/Laptop"
    if mfr in {"RaspberryPi"}:
        return "Linux/Server"
    return "Unknown"


_PHONE_MFRS = {
    # Apple
    "Apple",
    # Samsung
    "Samsung",
    # Xiaomi ecosystem (Redmi / POCO are Xiaomi sub-brands)
    "Xiaomi", "Redmi", "POCO",
    # Infinix / Transsion group
    "Infinix", "Tecno", "Itel",
    # Other major Android OEMs
    "Google", "Huawei", "Honor", "OnePlus", "OPPO", "Realme", "Vivo",
    "LG", "Sony", "Motorola", "Nokia", "ZTE", "Meizu", "HTC",
    "Lenovo", "TCL", "Alcatel", "BlackBerry", "Nothing", "Fairphone",
    "MIUI",
}

_CAMERA_MFRS = {
    "Hikvision", "Dahua", "Axis", "Reolink", "Arlo", "Nest", "Wyze",
    "Foscam", "Amcrest", "Annke", "Swann", "Lorex", "Hanwha",
    "Bosch", "Vivotek", "Uniview",
}

_PC_MFRS = {
    "Intel", "Realtek", "Dell", "HP", "Lenovo", "Microsoft",
    "RaspberryPi", "Broadcom",
}

_ROUTER_MFRS = {
    "Cisco", "Netgear", "TP-Link", "DLink", "Tenda", "Linksys",
    "Asus", "Mercusys", "Edimax", "Ubiquiti", "MikroTik",
    # Note: Huawei intentionally excluded – Huawei phones take priority in _PHONE_MFRS
}


def _is_phone(dev: dict) -> bool:
    mfr   = dev.get("manufacturer", "")
    os_   = dev.get("os", "")
    dtype = dev.get("dtype", "")
    return (mfr in _PHONE_MFRS
            or os_ in ("iOS/macOS", "Android")
            or dtype == "phone")


def _is_camera(dev: dict) -> bool:
    mfr   = dev.get("manufacturer", "")
    dtype = dev.get("dtype", "")
    os_   = dev.get("os", "")
    return mfr in _CAMERA_MFRS or dtype == "camera" or os_ == "Camera/IoT"


def _is_pc(dev: dict) -> bool:
    mfr   = dev.get("manufacturer", "")
    dtype = dev.get("dtype", "")
    os_   = dev.get("os", "")
    return mfr in _PC_MFRS or dtype == "pc" or os_ == "PC/Laptop"


def _dtype_from_mfr(mfr: str) -> str:
    """Derive best-guess dtype from manufacturer name."""
    if mfr in _PHONE_MFRS:
        return "phone"
    if mfr in _CAMERA_MFRS:
        return "camera"
    if mfr in _ROUTER_MFRS:
        return "router"
    if mfr in _PC_MFRS:
        return "pc"
    return "other"


def _classify(dev: dict) -> str:
    if _is_phone(dev):
        return "phone"
    if _is_camera(dev):
        return "camera"
    if _is_pc(dev):
        return "pc"
    return "other"


def _blip_color(dev: dict, threat: bool) -> tuple:
    if threat:
        return RED[:3]
    mfr = dev.get("manufacturer", "")
    if mfr == "Apple":
        return WHT[:3]
    if dev.get("os") in ("Router/AP",):
        return YEL[:3]
    if _classify(dev) == "camera":
        return CYN[:3]
    return G1[:3]


def _hex_to_ip4(h: str) -> str:
    """Convert little-endian 8-char hex to dotted IPv4."""
    try:
        n = int(h, 16)
        return f"{n&0xff}.{(n>>8)&0xff}.{(n>>16)&0xff}.{(n>>24)&0xff}"
    except Exception:
        return h


def _domain_to_service(domain: str) -> str:
    """Map a domain name to a human-readable service label."""
    d = domain.lower()
    _MAP = [
        ('whatsapp',  'WhatsApp'),   ('instagram', 'Instagram'),
        ('facebook',  'Facebook'),   ('tiktok',    'TikTok'),
        ('youtube',   'YouTube'),    ('googlevideo','YouTube'),
        ('netflix',   'Netflix'),    ('snapchat',  'Snapchat'),
        ('spotify',   'Spotify'),    ('twitter',   'Twitter/X'),
        ('x.com',     'Twitter/X'),  ('telegram',  'Telegram'),
        ('icloud',    'iCloud'),     ('apple',     'Apple'),
        ('amazonaws', 'AWS'),        ('google',    'Google'),
        ('gstatic',   'Google'),     ('googleapis','Google'),
        ('microsoft', 'Microsoft'),  ('live.com',  'Microsoft'),
        ('linkedin',  'LinkedIn'),   ('reddit',    'Reddit'),
        ('pinterest', 'Pinterest'),  ('tumblr',    'Tumblr'),
        ('discord',   'Discord'),    ('twitch',    'Twitch'),
        ('zoom',      'Zoom'),       ('teams',     'MS Teams'),
        ('skype',     'Skype'),      ('viber',     'Viber'),
        ('line.me',   'Line'),       ('wechat',    'WeChat'),
        ('amazon',    'Amazon'),     ('ebay',      'eBay'),
        ('paypal',    'PayPal'),     ('alibaba',   'Alibaba'),
        ('shopify',   'Shopify'),    ('gmail',     'Gmail'),
        ('yahoo',     'Yahoo'),      ('bing',      'Bing'),
        ('baidu',     'Baidu'),      ('cloudflare','Cloudflare'),
        ('akamai',    'Akamai CDN'), ('cdn',       'CDN'),
        ('ads',       'Ads'),        ('analytics', 'Analytics'),
        ('doubleclick','Google Ads'),('adnxs',     'AppNexus Ads'),
        ('crashlytics','Firebase'),  ('firebase',  'Firebase'),
        ('goog',      'Google'),     ('1e100',     'Google'),
    ]
    for frag, svc in _MAP:
        if frag in d:
            return svc
    # Return nicest part of domain
    parts = [p for p in d.split('.') if p not in
             ('www','m','api','cdn','static','media','app')]
    return parts[0].capitalize() if parts else domain

def _resolve_full(ip: str, port: int) -> tuple:
    """Return (service_label, hostname) for display."""
    try:
        host = socket.gethostbyaddr(ip)[0].lower()
        for frag, svc in _DOMAIN_SVC:
            if frag in host or frag == ip:
                return svc, host
        return _PORT_SVC.get(port, f":{port}"), host
    except Exception:
        return _PORT_SVC.get(port, f":{port}"), ip

def _resolve_service(ip: str, port: int) -> str:
    return _resolve_full(ip, port)[0]


# ─── Alert System ────────────────────────────────────────────────────────────
class AlertSystem:
    """
    Handles security alerts:
      • Beep sound (generated in-memory, no external files needed)
      • Vibration via plyer / jnius on Android
      • Desktop/Android notification via plyer
    """

    def __init__(self):
        self._sound  = None
        self._last   = {}   # mac → last alert time  (rate-limit)
        self._setup_sound()

    def _setup_sound(self):
        import struct, wave, math
        # Use internal app storage on Android (no permissions needed), temp dir elsewhere
        if ANDROID:
            cache_dir = os.environ.get('ANDROID_PRIVATE',
                                       '/data/data/org.nexus.vision/files')
        else:
            import tempfile
            cache_dir = tempfile.gettempdir()
        self._wav_path = os.path.join(cache_dir, "nexus_alert.wav")
        try:
            sr, dur = 44100, 0.28
            n = int(sr * dur)
            with wave.open(self._wav_path, "wb") as w:
                w.setnchannels(1)
                w.setsampwidth(2)
                w.setframerate(sr)
                for i in range(n):
                    t    = i / sr
                    fade = min(min(i, n - i) / (sr * 0.022), 1.0)
                    v = int(28000 * fade * (
                        0.55 * math.sin(2 * math.pi * 880  * t) +
                        0.45 * math.sin(2 * math.pi * 1320 * t)
                    ))
                    w.writeframes(struct.pack("<h", v))
        except Exception:
            self._wav_path = None

        # Defer sound loading until Kivy audio engine is ready (0.5 s after init)
        Clock.schedule_once(self._load_sound, 0.5)

    def _load_sound(self, dt=None):
        if not self._wav_path:
            return
        try:
            from kivy.core.audio import SoundLoader
            self._sound = SoundLoader.load(self._wav_path)
            if self._sound:
                self._sound.volume = 0.9
        except Exception:
            pass

    def trigger(self, title: str, message: str, mac: str = ""):
        """Fire alert – rate-limited to once per 10 s per device."""
        now = time.time()
        if mac and now - self._last.get(mac, 0) < 10:
            return
        if mac:
            self._last[mac] = now

        # ── sound ────────────────────────────────────────────────────
        try:
            if self._sound:
                self._sound.stop()
                self._sound.play()
        except Exception:
            pass

        # ── vibration (Android) ──────────────────────────────────────
        if ANDROID:
            try:
                from plyer import vibrator   # type: ignore
                vibrator.vibrate(0.5)
            except Exception:
                try:
                    v = _PythonActivity.mActivity.getSystemService(
                        _Context.VIBRATOR_SERVICE)
                    v.vibrate(500)
                except Exception:
                    pass

        # ── notification ─────────────────────────────────────────────
        try:
            from plyer import notification   # type: ignore
            notification.notify(title=title, message=message, timeout=6)
        except Exception:
            pass   # silent fallback – sound already played


# ─── Ping Monitor ────────────────────────────────────────────────────────────
class PingMonitor:
    """
    Background thread that pings every known device every 8 seconds
    and marks them online / offline in the Database.
    Callbacks fire on the Kivy main thread via Clock.
    """

    INTERVAL = 8.0

    def __init__(self, db, on_update=None):
        self.db        = db
        self.on_update = on_update   # callable() – UI refresh hint
        self._run      = False
        self._results  = {}          # ip → True/False (online)

    def start(self):
        self._run = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self._run = False

    def is_online(self, ip: str) -> bool:
        return self._results.get(ip, False)

    @staticmethod
    def _ping_once(ip: str) -> bool:
        """
        Check if device is reachable.
        On Android: uses TCP connect only (no system ping command).
        On Windows/Linux: tries ICMP ping first, then TCP fallback.
        """
        if not ANDROID:
            try:
                sys = platform.system()
                if sys == "Windows":
                    r = subprocess.run(
                        ["ping", "-n", "1", "-w", "500", ip],
                        capture_output=True, timeout=3
                    )
                else:
                    r = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", ip],
                        capture_output=True, timeout=3
                    )
                if r.returncode == 0:
                    return True
            except Exception:
                pass
        # TCP connect fallback (works everywhere including Android)
        for port in (80, 443, 8080, 22, 53, 5000, 8888):
            try:
                with socket.create_connection((ip, port), timeout=0.7):
                    return True
            except Exception:
                pass
        return False

    def _loop(self):
        while self._run:
            devices = self.db.all()
            ips     = [d.get('ip') for d in devices if d.get('ip')]
            for ip in ips:
                if not self._run:
                    break
                online = self._ping_once(ip)
                self._results[ip] = online
                # update db device record
                for d in self.db.all():
                    if d.get('ip') == ip:
                        d['online'] = online
            if self.on_update:
                Clock.schedule_once(lambda dt: self.on_update(), 0)
            time.sleep(self.INTERVAL)


# ─── Speed Test ──────────────────────────────────────────────────────────────
class SpeedTest:
    """
    Multi-connection speed test using Cloudflare endpoints.
    Download: 4 parallel streams → accurate for high-speed connections.
    Upload: 4 parallel streams.
    Ping: 6 samples to 1.1.1.1:80 → lowest latency reported.
    """
    # Cloudflare speed test CDN — fastest public endpoint
    DL_URL  = "https://speed.cloudflare.com/__down?bytes=25000000"  # 25 MB
    UL_URL  = "https://speed.cloudflare.com/__up"
    STREAMS = 4   # parallel connections

    def run(self, on_ping, on_download, on_upload, on_done):
        threading.Thread(
            target=self._measure,
            args=(on_ping, on_download, on_upload, on_done),
            daemon=True
        ).start()

    def _measure(self, on_ping, on_dl, on_ul, on_done):
        ping_ms = self._ping()
        Clock.schedule_once(lambda dt: on_ping(ping_ms), 0)
        dl_mbps = self._download_parallel()
        Clock.schedule_once(lambda dt: on_dl(dl_mbps), 0)
        ul_mbps = self._upload_parallel()
        Clock.schedule_once(lambda dt: on_ul(ul_mbps), 0)
        Clock.schedule_once(lambda dt: on_done(), 0)

    # ── Ping: 6 samples, pick minimum ─────────────────────────────────
    def _ping(self) -> float:
        HOST = ("1.1.1.1", 80)
        times = []
        for _ in range(6):
            try:
                t0 = time.perf_counter()
                s  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect(HOST)
                s.close()
                times.append((time.perf_counter() - t0) * 1000)
            except Exception:
                pass
            time.sleep(0.05)
        return round(min(times), 1) if times else -1.0

    # ── Download: N parallel streams ──────────────────────────────────
    def _download_parallel(self) -> float:
        import urllib.request
        results = []
        lock    = threading.Lock()
        TEST_S  = 8   # seconds per stream

        def _stream():
            try:
                req = urllib.request.Request(
                    self.DL_URL,
                    headers={"User-Agent": "NexusVision/2.0",
                             "Cache-Control": "no-cache"}
                )
                total = 0
                start = time.perf_counter()
                with urllib.request.urlopen(req, timeout=TEST_S + 3) as resp:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if time.perf_counter() - start >= TEST_S:
                            break
                elapsed = time.perf_counter() - start
                if elapsed > 0:
                    with lock:
                        results.append(total / elapsed)
            except Exception:
                pass

        threads = [threading.Thread(target=_stream, daemon=True)
                   for _ in range(self.STREAMS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=TEST_S + 5)

        if not results:
            return 0.0
        total_bps = sum(results)   # parallel streams sum to total bandwidth
        return round((total_bps * 8) / 1_000_000, 2)

    # ── Upload: N parallel streams ────────────────────────────────────
    def _upload_parallel(self) -> float:
        import urllib.request
        results = []
        lock    = threading.Lock()
        CHUNK   = 512 * 1024   # 512 KB per request
        TEST_S  = 6

        def _stream():
            try:
                data  = b"\x00" * CHUNK
                total = 0
                start = time.perf_counter()
                while time.perf_counter() - start < TEST_S:
                    req = urllib.request.Request(
                        self.UL_URL, data=data, method="POST",
                        headers={"Content-Type": "application/octet-stream",
                                 "User-Agent": "NexusVision/2.0"}
                    )
                    try:
                        urllib.request.urlopen(req, timeout=8)
                        total += CHUNK
                    except Exception:
                        break
                elapsed = time.perf_counter() - start
                if elapsed > 0:
                    with lock:
                        results.append(total / elapsed)
            except Exception:
                pass

        threads = [threading.Thread(target=_stream, daemon=True)
                   for _ in range(self.STREAMS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=TEST_S + 8)

        if not results:
            return 0.0
        return round((sum(results) * 8) / 1_000_000, 2)


# ─── Database ────────────────────────────────────────────────────────────────
class Database:
    def __init__(self):
        base = None
        if ANDROID:
            # Priority 1: p4a internal private storage (never needs permissions)
            priv = os.environ.get('ANDROID_PRIVATE', '')
            if priv:
                base = Path(priv)
            else:
                # Priority 2: android.storage API
                try:
                    from android.storage import app_storage_path  # type: ignore
                    base = Path(app_storage_path())
                except Exception:
                    pass
            if base is None:
                base = Path('/data/data/org.nexus.vision/files')
        else:
            base = Path(os.path.expanduser("~")) / ".nexus_vision"

        # Always wrap mkdir — permission errors must not crash the app
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Last-resort fallback: system temp dir
            import tempfile
            base = Path(tempfile.gettempdir()) / "nexus_vision"
            try:
                base.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

        self.path = base / "db.json"
        self._d = {
            "devices":  {},
            "log":      [],
            "traffic":  [],
            "dns_log":  [],
            "settings": {
                "alert_unknown":    True,
                "alert_new_device": True,
                "scan_interval":    15,
                "service_analysis": True,
                "save_log":         True,
                "save_traffic":     True,
                "blocked":          [],
                "whitelist":        [],   # trusted MACs
                "whitelist_active": False,
            }
        }
        self._dirty     = False
        self._save_lock = threading.Lock()
        self._load()

    def _load(self):
        try:
            if self.path.exists():
                with open(self.path) as f:
                    loaded = json.load(f)
                    self._d.update(loaded)
        except Exception:
            pass
        # Ensure all top-level keys exist (migration safety)
        for k in ("devices", "log", "traffic", "dns_log"):
            self._d.setdefault(k, [] if k != "devices" else {})
        self._d.setdefault("settings", {})

    def save(self):
        """Thread-safe save; skips if nothing changed."""
        self._dirty = True
        with self._save_lock:
            if not self._dirty:
                return
            try:
                with open(self.path, "w") as f:
                    json.dump(self._d, f, indent=2, default=str)
                self._dirty = False
            except Exception:
                pass

    def clear_all(self):
        self._d["devices"] = {}
        self._d["log"]     = []
        self._d["traffic"] = []
        self._d["dns_log"] = []
        # Clear per-device dns_visits too
        try:
            if self.path.exists():
                self.path.unlink()
        except Exception:
            pass
        self.save()
        self.log("INFO", "Database cleared — fresh start")

    def set_setting(self, key, value):
        self._d["settings"][key] = value
        self.save()

    # ── devices ──────────────────────────────────────────────────────────
    def upsert(self, mac, **kw):
        if mac not in self._d["devices"]:
            self._d["devices"][mac] = {
                "mac":          mac,
                "ip":           "",
                "name":         "Unknown",
                "manufacturer": "Unknown",
                "os":           "Unknown",
                "dtype":        "phone",
                "first_seen":   str(datetime.now()),
                "last_seen":    str(datetime.now()),
                "signal":       -80,
                "trusted":      False,
                "blocked":      False,
                "services":     [],
                "open_ports":   [],
            }
        dev = self._d["devices"][mac]
        dev.update(kw)
        dev["last_seen"] = str(datetime.now())
        return dev

    def get(self, mac):
        return self._d["devices"].get(mac)

    def all(self):
        return list(self._d["devices"].values())

    def active(self, window=120):
        cutoff = time.time() - window
        out = []
        for d in self._d["devices"].values():
            try:
                ts = datetime.fromisoformat(str(d["last_seen"])).timestamp()
                if ts > cutoff:
                    out.append(d)
            except Exception:
                out.append(d)
        return out

    # ── log ──────────────────────────────────────────────────────────────
    def log(self, level, msg):
        e = {
            "time":  datetime.now().strftime("%H:%M:%S"),
            "date":  datetime.now().strftime("%Y-%m-%d"),
            "level": level,
            "msg":   msg,
        }
        self._d["log"].insert(0, e)
        if len(self._d["log"]) > 800:
            self._d["log"] = self._d["log"][:800]
        return e

    # ── traffic ──────────────────────────────────────────────────────────
    def add_traffic(self, ip_src, service, direction="OUT",
                    remote_ip="", port=0, detail="", hostname=""):
        e = {
            "time":      datetime.now().strftime("%H:%M:%S"),
            "date":      datetime.now().strftime("%Y-%m-%d"),
            "src":       ip_src,
            "remote":    remote_ip,
            "hostname":  hostname or remote_ip,
            "port":      port,
            "service":   service,
            "direction": direction,
            "detail":    detail,
        }
        if self.setting("save_traffic", True):
            self._d["traffic"].insert(0, e)
            if len(self._d["traffic"]) > 1000:
                self._d["traffic"] = self._d["traffic"][:1000]
        # also log per-device phone_log
        dev = self._find_by_ip(ip_src)
        if dev:
            pl = dev.setdefault("phone_log", [])
            pl.insert(0, e)
            if len(pl) > 200:
                dev["phone_log"] = pl[:200]

    def _find_by_ip(self, ip):
        for d in self._d["devices"].values():
            if d.get("ip") == ip:
                return d
        return None

    def add_dns_event(self, src_ip: str, domain: str, qtype: str = "A"):
        """Record a DNS query (domain lookup) seen from a device."""
        if not domain or domain.endswith(('.local', '.arpa')):
            return   # skip mDNS noise
        e = {
            "time":   datetime.now().strftime("%H:%M:%S"),
            "date":   datetime.now().strftime("%Y-%m-%d"),
            "src":    src_ip,
            "domain": domain,
            "qtype":  qtype,
        }
        self._d["dns_log"].insert(0, e)
        if len(self._d["dns_log"]) > 2000:
            self._d["dns_log"] = self._d["dns_log"][:2000]
        # Also attach to device phone_log / dns_visits
        dev = self._find_by_ip(src_ip)
        if dev:
            visits = dev.setdefault("dns_visits", [])
            if domain not in visits:
                visits.insert(0, domain)
            if len(visits) > 500:
                dev["dns_visits"] = visits[:500]
            # Add to phone_log as a traffic event
            ev = {
                "time":      e["time"],
                "src":       src_ip,
                "hostname":  domain,
                "service":   _domain_to_service(domain),
                "direction": "OUT",
                "detail":    f"DNS lookup: {domain}",
                "port":      53,
            }
            pl = dev.setdefault("phone_log", [])
            pl.insert(0, ev)
            if len(pl) > 300:
                dev["phone_log"] = pl[:300]

    def add_phone_event(self, mac, direction, service, remote_ip, port, detail=""):
        """Add a traffic event directly to a phone by MAC."""
        dev = self.get(mac)
        if not dev:
            return
        e = {
            "time":      datetime.now().strftime("%H:%M:%S"),
            "date":      datetime.now().strftime("%Y-%m-%d"),
            "src":       dev.get("ip", ""),
            "remote":    remote_ip,
            "port":      port,
            "service":   service,
            "direction": direction,
            "detail":    detail,
        }
        pl = dev.setdefault("phone_log", [])
        pl.insert(0, e)
        if len(pl) > 200:
            dev["phone_log"] = pl[:200]
        self._d["traffic"].insert(0, e)
        if len(self._d["traffic"]) > 1000:
            self._d["traffic"] = self._d["traffic"][:1000]

    # ── settings ─────────────────────────────────────────────────────────
    def setting(self, key, default=None):
        return self._d["settings"].get(key, default)

    def is_blocked(self, mac):
        return mac in self._d["settings"].get("blocked", [])

    def toggle_block(self, mac):
        bl = self._d["settings"].setdefault("blocked", [])
        dev = self.get(mac)
        name = dev.get("name", mac) if dev else mac
        if mac in bl:
            bl.remove(mac)
            self.log("INFO", f"Unblocked: {name}  [{mac}]")
        else:
            bl.append(mac)
            self.log("WARN", f"Blocked:   {name}  [{mac}]")
        self.save()

    # ── whitelist ─────────────────────────────────────────────────────
    def is_trusted(self, mac: str) -> bool:
        return mac in self._d["settings"].get("whitelist", [])

    def is_intruder(self, mac: str) -> bool:
        """Phone not in whitelist while whitelist is active."""
        return (
            self._d["settings"].get("whitelist_active", False)
            and mac not in self._d["settings"].get("whitelist", [])
        )

    def trust(self, mac: str):
        wl = self._d["settings"].setdefault("whitelist", [])
        if mac not in wl:
            wl.append(mac)
            dev  = self.get(mac)
            name = dev.get("name", mac) if dev else mac
            self.log("INFO", f"Trusted: {name}  [{mac}]")
        self.save()

    def untrust(self, mac: str):
        wl = self._d["settings"].setdefault("whitelist", [])
        if mac in wl:
            wl.remove(mac)
            dev  = self.get(mac)
            name = dev.get("name", mac) if dev else mac
            self.log("WARN", f"Untrusted: {name}  [{mac}]")
        self.save()


# ─── Scanner ─────────────────────────────────────────────────────────────────
class Scanner:
    """
    Real network scanner.
    NO fake/demo data is generated anywhere in this class.
    """

    def __init__(self, db: Database, on_device, on_traffic,
                 alert: "AlertSystem" = None):
        self.db         = db
        self.on_device  = on_device
        self.on_traffic = on_traffic
        self.alert      = alert
        self._run       = False
        self._seen_conns = set()
        # cache WiFi RSSI per IP (Android)
        self._rssi_cache:      dict = {}   # ip → signal_dbm
        # mDNS device name + type cache
        self._mdns_cache:      dict = {}   # ip → {name, os, type}
        # mDNS hostname cache (ip → hostname from mDNS)
        self._rssi_name_cache: dict = {}   # ip → friendly name

    def start(self):
        self._run = True
        threading.Thread(target=self._loop_arp,       daemon=True).start()
        threading.Thread(target=self._loop_traffic,   daemon=True).start()
        threading.Thread(target=self._loop_mdns,      daemon=True).start()
        threading.Thread(target=self._loop_ssdp,      daemon=True).start()
        threading.Thread(target=self._dns_sniffer_loop, daemon=True).start()

    def stop(self):
        self._run = False

    # ── Access control ────────────────────────────────────────────────────
    def kick_device(self, ip: str) -> str:
        """
        Attempt to block a device from the network.
        Requires: root on Linux/Android  OR  admin on Windows.
        Returns status message.
        """
        sys = platform.system()
        try:
            if sys == "Windows":
                # Block via Windows Firewall (requires admin)
                name = f"NexusBlock_{ip.replace('.','_')}"
                r = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={name}", "dir=in", "action=block",
                     f"remoteip={ip}"],
                    capture_output=True, text=True, timeout=5
                )
                if r.returncode == 0:
                    return f"BLOCKED via Firewall: {ip}"
                return f"FAILED (run as Admin): {r.stderr.strip()[:60]}"
            else:
                # Try iptables (requires root)
                r = subprocess.run(
                    ["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True, timeout=5
                )
                if r.returncode == 0:
                    return f"BLOCKED via iptables: {ip}"
                # Try nftables
                r2 = subprocess.run(
                    ["nft", "add", "rule", "inet", "filter", "forward",
                     "ip", "saddr", ip, "drop"],
                    capture_output=True, text=True, timeout=5
                )
                if r2.returncode == 0:
                    return f"BLOCKED via nftables: {ip}"
                return "REQUIRES ROOT – run with sudo/root"
        except Exception as ex:
            return f"ERROR: {ex}"

    def unkick_device(self, ip: str) -> str:
        """Remove block rule."""
        sys = platform.system()
        try:
            if sys == "Windows":
                name = f"NexusBlock_{ip.replace('.','_')}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={name}"],
                    capture_output=True, timeout=5
                )
                return f"UNBLOCKED: {ip}"
            else:
                subprocess.run(
                    ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
                return f"UNBLOCKED: {ip}"
        except Exception as ex:
            return f"ERROR: {ex}"

    def throttle_device(self, ip: str, kbps: int) -> str:
        """
        Limit device bandwidth (Linux/Android root required).
        kbps = 0 means remove limit.
        """
        try:
            iface = self._default_iface()
            if platform.system() != "Windows" and iface:
                # Remove any existing qdisc
                subprocess.run(
                    ["tc", "qdisc", "del", "dev", iface, "root"],
                    capture_output=True, timeout=5
                )
                if kbps > 0:
                    rate = f"{kbps}kbit"
                    cmds = [
                        ["tc", "qdisc", "add", "dev", iface,
                         "root", "handle", "1:", "htb"],
                        ["tc", "class", "add", "dev", iface,
                         "parent", "1:", "classid", "1:1",
                         "htb", "rate", rate],
                        ["tc", "filter", "add", "dev", iface,
                         "parent", "1:", "protocol", "ip",
                         "prio", "1", "u32",
                         "match", "ip", "dst", ip,
                         "flowid", "1:1"],
                    ]
                    for cmd in cmds:
                        subprocess.run(cmd, capture_output=True, timeout=5)
                    return f"LIMITED to {kbps} Kbps: {ip}"
                return f"LIMIT REMOVED: {ip}"
            return "REQUIRES ROOT + Linux/Android"
        except Exception as ex:
            return f"ERROR: {ex}"

    def _default_iface(self):
        try:
            out = subprocess.check_output(
                "ip route | grep default | awk '{print $5}'",
                shell=True, stderr=subprocess.DEVNULL
            ).decode().strip().splitlines()
            return out[0] if out else None
        except Exception:
            return None

    @staticmethod
    def gateway_ip() -> str:
        """Return the default gateway (router) IP address."""
        # Android: use WifiManager DhcpInfo
        if ANDROID:
            try:
                act  = _PythonActivity.mActivity
                wm   = act.getSystemService(_Context.WIFI_SERVICE)
                dhcp = wm.getDhcpInfo()
                gw   = dhcp.gateway
                # DhcpInfo stores as little-endian int
                return "%d.%d.%d.%d" % (gw & 0xFF,
                                         (gw >> 8)  & 0xFF,
                                         (gw >> 16) & 0xFF,
                                         (gw >> 24) & 0xFF)
            except Exception:
                pass
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["ipconfig"], stderr=subprocess.DEVNULL
                ).decode(errors='ignore')
                for line in out.splitlines():
                    if "Default Gateway" in line or "默认网关" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            gw = parts[-1].strip()
                            if re.match(r'\d+\.\d+\.\d+\.\d+', gw):
                                return gw
            else:
                out = subprocess.check_output(
                    "ip route | grep default | awk '{print $3}'",
                    shell=True, stderr=subprocess.DEVNULL
                ).decode().strip().splitlines()
                if out:
                    return out[0]
        except Exception:
            pass
        # Method 3: ip route (Linux/Android)
        try:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                stderr=subprocess.DEVNULL, timeout=3
            ).decode()
            m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', out)
            if m:
                return m.group(1)
        except Exception:
            pass
        # Method 4: derive from own IP (fallback)
        try:
            my_ip = Scanner.my_ip()
            if my_ip != "Unknown":
                return ".".join(my_ip.split(".")[:3]) + ".1"
        except Exception:
            pass
        return "Unknown"

    @staticmethod
    def my_ip() -> str:
        """Return this device's LAN IP – 4 fallback methods."""
        # Method 1: UDP socket trick (most reliable, no data sent)
        for host in ("8.8.8.8", "1.1.1.1", "208.67.222.222"):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.connect((host, 80))
                ip = s.getsockname()[0]
                s.close()
                if ip and not ip.startswith("127."):
                    return ip
            except Exception:
                pass
        # Method 2: Android WifiManager
        if ANDROID:
            try:
                act  = _PythonActivity.mActivity
                wm   = act.getSystemService(_Context.WIFI_SERVICE)
                info = wm.getConnectionInfo()
                raw  = info.getIpAddress()
                if raw:
                    return "%d.%d.%d.%d" % (
                        raw & 0xFF, (raw >> 8) & 0xFF,
                        (raw >> 16) & 0xFF, (raw >> 24) & 0xFF)
            except Exception:
                pass
        # Method 3: hostname -I (Linux/Android)
        try:
            out = subprocess.check_output(
                ["hostname", "-I"], stderr=subprocess.DEVNULL, timeout=3
            ).decode().strip().split()
            for ip in out:
                if re.match(r'(\d+\.){3}\d+', ip) and not ip.startswith("127."):
                    return ip
        except Exception:
            pass
        # Method 4: ip addr show
        try:
            out = subprocess.check_output(
                ["ip", "addr", "show"], stderr=subprocess.DEVNULL, timeout=3
            ).decode()
            for m in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)', out):
                ip = m.group(1)
                if not ip.startswith("127."):
                    return ip
        except Exception:
            pass
        return "Unknown"

    @staticmethod
    def wifi_ssid() -> str:
        """Return the name of the current WiFi network – 4 fallback methods."""
        # Method 1: Android WifiManager (most accurate on Android)
        if ANDROID:
            try:
                act  = _PythonActivity.mActivity
                wm   = act.getSystemService(_Context.WIFI_SERVICE)
                info = wm.getConnectionInfo()
                ssid = str(info.getSSID()).strip('"')
                if ssid and ssid != "<unknown ssid>":
                    return ssid
            except Exception:
                pass
        # Method 2: Windows netsh
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "interfaces"],
                    stderr=subprocess.DEVNULL, timeout=5
                ).decode(errors="ignore")
                for line in out.splitlines():
                    if "SSID" in line and "BSSID" not in line:
                        p = line.split(":", 1)
                        if len(p) == 2 and p[1].strip():
                            return p[1].strip()
        except Exception:
            pass
        # Method 3: Linux iwgetid
        try:
            out = subprocess.check_output(
                ["iwgetid", "-r"], stderr=subprocess.DEVNULL, timeout=3
            ).decode().strip()
            if out:
                return out
        except Exception:
            pass
        # Method 4: Linux nmcli
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                stderr=subprocess.DEVNULL, timeout=3
            ).decode()
            for line in out.splitlines():
                if line.startswith("yes:"):
                    return line[4:].strip()
        except Exception:
            pass
        return "Unknown"

    @staticmethod
    def wifi_password(ssid: str) -> str:
        """
        Return saved WiFi password FOR THIS DEVICE'S OWN NETWORK.
        Windows: netsh wlan show profile key=clear (no special rights needed).
        Android: requires root to read WifiConfigStore.xml.
        """
        if not ssid or ssid == "Unknown":
            return "N/A"
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "profile",
                     f"name={ssid}", "key=clear"],
                    stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                for line in out.splitlines():
                    if "Key Content" in line or "المحتوى الرئيسي" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            pw = parts[1].strip()
                            return pw if pw else "N/A"
                return "N/A (profile not found)"
            elif platform.system() == "Linux":
                # NetworkManager stores profiles here (root may be needed)
                import glob
                for f in glob.glob("/etc/NetworkManager/system-connections/*.nmconnection"):
                    try:
                        content = open(f).read()
                        if ssid in content:
                            for line in content.splitlines():
                                if line.startswith("psk="):
                                    return line.split("=", 1)[1].strip()
                    except Exception:
                        pass
                return "Root required"
        except Exception as e:
            return f"Error: {e}"
        # Android: check WifiConfigStore.xml (requires root)
        if ANDROID:
            try:
                cfg = "/data/misc/wifi/WifiConfigStore.xml"
                content = open(cfg).read()
                m = re.search(r'PreSharedKey.*?value="(.*?)"', content)
                if m:
                    return m.group(1)
            except Exception:
                pass
            return "Root required"
        return "Not supported"

    @staticmethod
    def isp_info() -> str:
        """
        Detect ISP / carrier name via reverse DNS of the public IP.
        Uses standard socket + optional nslookup — fully offline fallback.
        """
        # Method 1: nslookup via OpenDNS (Windows/Linux, NOT Android usually)
        if not ANDROID:
            try:
                pub_ip = subprocess.check_output(
                    ["nslookup", "myip.opendns.com", "resolver1.opendns.com"],
                    stderr=subprocess.DEVNULL, timeout=5
                ).decode(errors="ignore")
                for line in pub_ip.splitlines():
                    if "Address" in line and "#" not in line and ":" not in line:
                        ip = line.split(":")[-1].strip()
                        if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                            try:
                                return socket.gethostbyaddr(ip)[0]
                            except Exception:
                                return ip
            except Exception:
                pass

        # Method 2: connect to Google DNS, reverse-lookup the public IP via socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.connect(("8.8.8.8", 80))
            pub_ip = s.getsockname()[0]
            s.close()
            try:
                return socket.gethostbyaddr(pub_ip)[0]
            except Exception:
                return pub_ip
        except Exception:
            pass

        # Android: try to read network operator name via telephony
        if ANDROID:
            try:
                tm = _PythonActivity.mActivity.getSystemService(
                    _Context.TELEPHONY_SERVICE)
                name = str(tm.getNetworkOperatorName())
                if name:
                    return name
            except Exception:
                pass

        return "Unknown"

    # ── ARP loop (all methods) ───────────────────────────────────────────
    def _loop_arp(self):
        while self._run:
            try:
                # Step 1: TCP sweep – forces ARP cache population
                live_ips = self._tcp_sweep()
                # CRITICAL: wait 1 s for the OS to populate ARP after TCP probes
                time.sleep(1.0)
                # Step 2: read ARP (now populated) + register all devices
                self._scan_arp(live_ips)
                # Step 3: Android-specific extras
                if ANDROID:
                    self._scan_wifi()
                    self._scan_bt()
                    self._scan_hotspot_clients()
                    self._scan_nsd()
            except Exception:
                pass
            time.sleep(self.db.setting("scan_interval", 15))

    # ─── Method 1: TCP sweep – works on ALL platforms without root ────────
    def _tcp_sweep(self) -> set:
        """
        Probe all 254 hosts in the local subnet via TCP connect.
        Returns set of IPs that responded (alive).
        Works on Android without root.
        All 254 probes run in parallel, max wait = 2 s total.
        """
        my_ip = Scanner.my_ip()
        if my_ip in ("Unknown", ""):
            return set()
        parts = my_ip.split(".")
        if len(parts) != 4:
            return set()
        subnet = ".".join(parts[:3])

        live = set()
        lock = threading.Lock()
        # Ports commonly open on phones, routers, PCs
        PROBE_PORTS = (80, 443, 8080, 7000, 5353, 22, 8888, 5555,
                       62078, 7100, 3689, 9090, 445, 139, 135)

        def _probe(ip):
            for port in PROBE_PORTS:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.6)
                    if s.connect_ex((ip, port)) == 0:
                        s.close()
                        with lock:
                            live.add(ip)
                        return
                    s.close()
                except Exception:
                    pass
            # ICMP ping fallback for non-Android
            if not ANDROID:
                try:
                    sys_name = platform.system()
                    flag  = ["-n", "1"] if sys_name == "Windows" else ["-c", "1"]
                    wflag = ["-w", "300"] if sys_name == "Windows" else ["-W", "1"]
                    r = subprocess.run(["ping"] + flag + wflag + [ip],
                                       capture_output=True, timeout=1.2)
                    if r.returncode == 0:
                        with lock:
                            live.add(ip)
                except Exception:
                    pass

        threads = []
        for i in range(1, 255):
            ip = f"{subnet}.{i}"
            if ip == my_ip:
                with lock:
                    live.add(ip)
                continue
            t = threading.Thread(target=_probe, args=(ip,), daemon=True)
            threads.append(t)
            t.start()

        # Wait for all (max 2 s total)
        deadline = time.time() + 2.0
        for t in threads:
            remaining = max(0, deadline - time.time())
            t.join(timeout=remaining)

        return live

    @staticmethod
    def _is_real_device(ip: str, mac: str) -> bool:
        """
        Return True only for real unicast LAN devices.
        Filters out:
          - Multicast  (224.0.0.0 / 8)
          - Broadcast  (255.255.255.255, x.x.x.255)
          - APIPA      (169.254.x.x)
          - Loopback   (127.x.x.x)
          - Zero / broadcast MACs
        """
        if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return False
        try:
            parts = list(map(int, ip.split(".")))
            first = parts[0]
            # multicast block 224-239
            if 224 <= first <= 239:
                return False
            # broadcast / limited
            if first == 255 or parts[-1] == 255:
                return False
            # loopback
            if first == 127:
                return False
            # APIPA (link-local autoconfiguration)
            if first == 169 and parts[1] == 254:
                return False
            # must be a private LAN range
            if first in (10, 172, 192):
                return True
            # allow any other unicast just in case
            return True
        except Exception:
            return False

    def _scan_arp(self, live_ips: set = None):
        """
        Register ALL discovered LAN devices.
        Sources: ARP table + live_ips from TCP sweep + mDNS cache.
        ALL responding devices are shown; phones are highlighted on radar.
        """
        # Build merged map: ip → mac
        discovered = {}   # ip → mac

        # From ARP table (has MAC info)
        for ip, mac in self._read_arp():
            if self._is_real_device(ip, mac):
                discovered[ip] = mac

        # From TCP sweep (live_ips) — assign MAC from ARP or pseudo-MAC
        if live_ips:
            for ip in live_ips:
                if ip not in discovered and self._is_real_device(ip, "AA:00:00:00:00:01"):
                    # Try to get real MAC from ARP one more time
                    real_mac = self._ip_to_mac(ip)
                    if real_mac:
                        discovered[ip] = real_mac
                    else:
                        # Pseudo-MAC: deterministic from IP so device stays stable
                        parts = ip.split(".")
                        discovered[ip] = "FE:FF:{:02X}:{:02X}:{:02X}:{:02X}".format(
                            int(parts[0]) if len(parts) > 0 else 0,
                            int(parts[1]) if len(parts) > 1 else 0,
                            int(parts[2]) if len(parts) > 2 else 0,
                            int(parts[3]) if len(parts) > 3 else 0,
                        )

        # From mDNS cache (may have additional IPs)
        for ip, info in list(self._mdns_cache.items()):
            if ip not in discovered and self._is_real_device(ip, "AA:00:00:00:00:02"):
                real_mac = self._ip_to_mac(ip)
                parts = ip.split(".")
                discovered[ip] = real_mac or "FD:FE:{:02X}:{:02X}:{:02X}:{:02X}".format(
                    int(parts[0]) if len(parts) > 0 else 0,
                    int(parts[1]) if len(parts) > 1 else 0,
                    int(parts[2]) if len(parts) > 2 else 0,
                    int(parts[3]) if len(parts) > 3 else 0,
                )

        for ip, mac in discovered.items():
            mfr  = _oui(mac)
            os_  = _guess_os(mfr)

            # ── Enrich from mDNS cache ────────────────────────────────────
            mdns_info = self._mdns_cache.get(ip, {})
            if mdns_info.get("name"):
                name = mdns_info["name"].split(".")[0]
            else:
                name = (self._rssi_name_cache.get(ip)
                        or self._hostname(ip)
                        or f"Device-{ip.split('.')[-1]}")
            if mdns_info.get("os"):
                os_ = mdns_info["os"]

            # ── Classify device type ──────────────────────────────────────
            dev_stub = {"manufacturer": mfr, "os": os_, "name": name}
            if mdns_info.get("type") == "phone":
                dtype = "phone"
            elif _is_phone(dev_stub):
                dtype = "phone"
            elif _is_camera(dev_stub):
                dtype = "camera"
            elif _is_pc(dev_stub):
                dtype = "pc"
            elif mfr in _ROUTER_MFRS:
                dtype = "router"
            else:
                # Unknown – use OUI-derived guess, then background port scan
                dtype = _dtype_from_mfr(mfr) if mfr != "Unknown" else "other"

            # Clean up display name for unknown-MAC phones
            if mfr == "Unknown" and dtype == "phone":
                mfr = "Phone"

            is_new = self.db.get(mac) is None
            signal = self._rssi_cache.get(ip, -55)
            dev = self.db.upsert(
                mac, ip=ip, name=name, manufacturer=mfr,
                os=os_, signal=signal, dtype=dtype
            )

            if is_new:
                level = ("ALERT" if dtype == "phone"
                                    and self.db.setting("alert_new_device")
                         else "INFO")
                self.db.log(level,
                            f"Device: {name}  [{mfr}/{os_}]  IP:{ip}  MAC:{mac}")
                if self.alert and dtype == "phone" and self.db.setting("alert_new_device"):
                    is_intruder = self.db.is_intruder(mac)
                    title   = "INTRUDER" if is_intruder else "New Phone"
                    message = f"{name} [{mfr}] IP:{ip}"
                    self.alert.trigger(title, message, mac)
                # Background port scan + fingerprint for unknown devices
                threading.Thread(
                    target=self._classify_and_scan, args=(ip, mac, dtype),
                    daemon=True
                ).start()

            Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)
        self.db.save()

    def _classify_and_scan(self, ip: str, mac: str, current_dtype: str):
        """
        Background worker: refine device classification + scan ports.
        Runs after device is already registered/shown on radar.
        """
        # 1. Active multi-method device identification (name, model, OS)
        self._full_identify(ip, mac)

        # 2. Live OUI lookup for unknown manufacturer
        dev = self.db.get(mac)
        if dev and dev.get("manufacturer", "Unknown") == "Unknown":
            if not mac.startswith(("FE:FF", "FD:FE", "FF:FF")):
                vendor = _oui_live_lookup(mac)
                if vendor and vendor != "Unknown":
                    dev["manufacturer"] = vendor
                    dev["os"]           = _guess_os(vendor)
                    new_dtype           = _dtype_from_mfr(vendor)
                    if new_dtype != "other":
                        dev["dtype"]    = new_dtype
                        current_dtype   = new_dtype
                    self.db.save()
                    Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)

        # 3. Port fingerprint for still-unknown devices
        if current_dtype == "other":
            if self._port_fingerprint_is_phone(ip):
                dev = self.db.get(mac)
                if dev:
                    dev["dtype"] = "phone"
                    if dev.get("manufacturer") in ("Unknown", "Phone", ""):
                        dev["manufacturer"] = "Phone"
                    if dev.get("os") == "Unknown":
                        dev["os"] = "Android"
                    self.db.save()
                    Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)
                    return
        # 4. Full port scan
        self._port_scan(ip, mac)

    def _port_fingerprint_is_phone(self, ip: str) -> bool:
        """
        Quick port check: if device has any phone-typical open port, treat as phone.
        Runs with very short timeout to not slow down discovery.
        Phone-typical ports: 5353 (mDNS), 62078 (iPhone), 7000 (AirPlay),
                             5555 (ADB), 8080, 8888 (Android hotspot).
        """
        PHONE_PORTS = (5353, 62078, 7000, 5555, 8888, 7100, 3689)
        for port in PHONE_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.25)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return True
                s.close()
            except Exception:
                pass
        return False

    # ── Port scanner ─────────────────────────────────────────────────
    # Common ports found open on phones
    _SCAN_PORTS = [
        21, 22, 23, 25, 53, 80, 135, 139, 143, 443, 445,
        548, 554, 8080, 8443, 8888, 5000, 5353, 5555,
        62078,   # iPhone sync (iTunes / Finder)
        7000,    # AirPlay
        7100,    # Font server (iOS)
        49152,   # Windows / dynamic
        3689,    # iTunes DAAP
        9090,    # Android Debug Proxy
    ]

    def _port_scan(self, ip: str, mac: str):
        """Scan common ports on the target phone IP."""
        open_ports = []
        for port in self._SCAN_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.4)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    svc = _PORT_SVC.get(port, str(port))
                    open_ports.append(f"{port}/{svc}")
            except Exception:
                pass

        if open_ports:
            dev = self.db.get(mac)
            if dev:
                dev["open_ports"] = open_ports
                self.db.log("INFO",
                            f"Ports on {dev.get('name','?')} [{ip}]: "
                            f"{', '.join(open_ports)}")
                self.db.save()
                Clock.schedule_once(
                    lambda dt, d=dev: self.on_device(d), 0)

    def _read_arp(self):
        """
        Read ARP cache using 3 methods in parallel for maximum coverage.
        Method A: /proc/net/arp  (Linux / Android)
        Method B: ip neigh show  (Linux / Android, may have more entries)
        Method C: arp -a         (Windows / macOS / some Android)
        """
        seen = {}  # ip → mac  (deduplicated)

        # ── Method A: /proc/net/arp ──────────────────────────────────
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 4 and p[3] not in ("00:00:00:00:00:00", ""):
                        seen[p[0]] = p[3].upper()
        except Exception:
            pass

        # ── Method B: ip neigh show ──────────────────────────────────
        try:
            out = subprocess.check_output(
                ["ip", "neigh", "show"],
                stderr=subprocess.DEVNULL, timeout=3
            ).decode(errors="ignore")
            for line in out.splitlines():
                # format: <ip> dev <iface> lladdr <mac> <state>
                m = re.search(
                    r'(\d+\.\d+\.\d+\.\d+).*lladdr\s+([\da-f:]{17})', line, re.I)
                if m:
                    ip, mac = m.group(1), m.group(2).upper()
                    if mac != "00:00:00:00:00:00":
                        seen[ip] = mac
        except Exception:
            pass

        # ── Method C: arp -a ─────────────────────────────────────────
        try:
            out = subprocess.check_output(
                "arp -a", shell=True, stderr=subprocess.DEVNULL, timeout=4
            ).decode(errors="ignore")
            for line in out.splitlines():
                m = re.search(
                    r'(\d+\.\d+\.\d+\.\d+)\s+([\da-f\-:]{17})', line, re.I)
                if m:
                    ip  = m.group(1)
                    mac = m.group(2).replace("-", ":").upper()
                    if mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                        seen.setdefault(ip, mac)
        except Exception:
            pass

        return list(seen.items())

    def _hostname(self, ip: str):
        try:
            return socket.gethostbyaddr(ip)[0].split(".")[0]
        except Exception:
            return None

    # ── Active device-name discovery (no OUI DB needed) ──────────────────────

    def _netbios_name(self, ip: str, timeout: float = 0.8) -> str:
        """
        Query NetBIOS node status (UDP 137).
        Works on Windows PCs, Android (some), and network printers.
        """
        try:
            # NBSTAT request: transaction ID 0xABCD, flags 0x0000, 1 question
            req = (b'\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                   b'\x20'
                   b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                   b'\x00\x00\x21\x00\x01')
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(req, (ip, 137))
            data = sock.recv(1024)
            sock.close()
            if len(data) > 57:
                num  = data[56]
                if num > 0:
                    raw  = data[57:57 + 15].decode('ascii', errors='ignore').strip()
                    name = raw.split('\x00')[0].strip()
                    if name and not name.startswith('*'):
                        return name
        except Exception:
            pass
        return ""

    def _mdns_device_info(self, ip: str, timeout: float = 1.0) -> dict:
        """
        Send targeted mDNS queries to a specific host to get:
          - device name (_device-info._tcp.local → TXT → model)
          - Apple model (records in cache)
          - hostname from PTR
        Returns dict with keys: name, model, os
        """
        result = {}
        try:
            import struct as _s
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            # Query: PTR _device-info._tcp.local
            def _mdns_query(qname: str) -> bytes:
                parts = qname.encode().split(b'.')
                labels = b''.join(bytes([len(p)]) + p for p in parts) + b'\x00'
                return b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + labels + b'\x00\x0c\x00\x01'
            sock.sendto(_mdns_query('_device-info._tcp.local'),
                        ('224.0.0.251', 5353))
            try:
                data, addr = sock.recvfrom(4096)
                if addr[0] == ip and len(data) > 12:
                    txt = data[12:].decode('utf-8', errors='ignore')
                    if 'model=' in txt.lower():
                        idx = txt.lower().index('model=') + 6
                        model = txt[idx:idx+40].split('\x00')[0].strip()
                        if model:
                            result['model'] = model
            except Exception:
                pass
            sock.close()
        except Exception:
            pass
        return result

    def _http_identify(self, ip: str, timeout: float = 1.5) -> dict:
        """
        Grab HTTP Server header + HTML title from port 80 / 8080 / 8888.
        Many routers, IP cameras, smart TVs, and Android debug servers
        expose device info this way.
        """
        result = {}
        for port in (80, 8080, 8888, 7080):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(
                    f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
                )
                raw = s.recv(3072).decode('utf-8', errors='ignore')
                s.close()
                for line in raw.split('\r\n'):
                    ll = line.lower()
                    if ll.startswith('server:'):
                        result['server'] = line[7:].strip()
                    if ll.startswith('x-device-name:') or ll.startswith('x-model:'):
                        key = ll.split(':')[0].replace('x-','').replace('-','_')
                        result[key] = line.split(':',1)[1].strip()
                # Try HTML <title>
                if '<title>' in raw.lower():
                    start = raw.lower().index('<title>') + 7
                    end   = raw.lower().index('</title>', start) if '</title>' in raw.lower() else start+60
                    title = raw[start:end].strip()[:50]
                    if title and not any(x in title.lower() for x in
                                         ('error','404','403','index','welcome','default')):
                        result['title'] = title
                if result:
                    result['port'] = port
                    break
            except Exception:
                pass
        return result

    def _snmp_sysname(self, ip: str, timeout: float = 0.8) -> str:
        """
        SNMP v1 GET for sysDescr (OID 1.3.6.1.2.1.1.1.0) and
        sysName (OID 1.3.6.1.2.1.1.5.0).
        Works on routers, some Android devices, printers.
        """
        def _build_get(oid_bytes: bytes) -> bytes:
            # Minimal SNMPv1 GetRequest
            oid    = b'\x06' + bytes([len(oid_bytes)]) + oid_bytes
            varbind= b'\x30' + bytes([len(oid)+2]) + oid + b'\x05\x00'
            varlist= b'\x30' + bytes([len(varbind)]) + varbind
            pdu    = b'\xa0' + bytes([4+len(varlist)]) + b'\x02\x01\x00\x02\x01\x00' + varlist
            community= b'\x04\x06public'
            msg    = community + b'\x02\x01\x00' + pdu
            return  b'\x30' + bytes([len(msg)]) + msg
        _SYSDESCR = b'\x2b\x06\x01\x02\x01\x01\x01\x00'
        _SYSNAME  = b'\x2b\x06\x01\x02\x01\x01\x05\x00'
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(_build_get(_SYSNAME), (ip, 161))
            data = sock.recv(512)
            sock.close()
            raw = data.decode('latin-1', errors='replace')
            # Find printable string after the OID
            for i in range(len(raw)-2, 0, -1):
                if raw[i] == '\x04':
                    slen = ord(raw[i+1])
                    name = raw[i+2:i+2+slen].strip()
                    if name and all(31 < ord(c) < 127 for c in name[:10]):
                        return name[:40]
        except Exception:
            pass
        return ""

    def _dhcp_hostname(self, ip: str) -> str:
        """
        Check common DHCP lease files for hostname associated with IP.
        Works on Linux, OpenWRT, and Android hotspot mode.
        """
        lease_files = [
            '/var/lib/misc/dnsmasq.leases',
            '/data/misc/dhcp/dnsmasq.leases',
            '/tmp/dhcp.leases',
            '/var/lib/dhcp/dhcpd.leases',
            '/tmp/dnsmasq.leases',
        ]
        for path in lease_files:
            try:
                with open(path, 'r', errors='ignore') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[2] == ip:
                            name = parts[3].strip()
                            if name and name != '*':
                                return name
            except Exception:
                pass
        return ""

    def _full_identify(self, ip: str, mac: str):
        """
        Run all identification methods in parallel for a single device.
        Updates the device record with the best available name/model/os.
        Called from _classify_and_scan background thread.
        """
        import concurrent.futures as _cf

        dev = self.db.get(mac)
        if not dev:
            return

        current_name = dev.get('name', '')
        # Skip if already well-identified
        if (current_name and
                not current_name.startswith('Device-') and
                current_name not in ('Unknown', '', 'Phone')):
            return

        results = {}
        with _cf.ThreadPoolExecutor(max_workers=5) as ex:
            f_nb   = ex.submit(self._netbios_name,    ip)
            f_dhcp = ex.submit(self._dhcp_hostname,   ip)
            f_http = ex.submit(self._http_identify,   ip)
            f_mdns = ex.submit(self._mdns_device_info,ip)
            f_snmp = ex.submit(self._snmp_sysname,    ip)

            results['netbios'] = f_nb.result()
            results['dhcp']    = f_dhcp.result()
            results['http']    = f_http.result()
            results['mdns']    = f_mdns.result()
            results['snmp']    = f_snmp.result()

        # ── Pick best name ────────────────────────────────────────
        best_name  = ""
        best_model = ""
        best_os    = ""

        if results['netbios']:
            best_name = results['netbios']

        if results['dhcp'] and not best_name:
            best_name = results['dhcp']

        if results['snmp'] and not best_name:
            best_name = results['snmp']

        http = results['http']
        if http:
            if http.get('title') and not best_name:
                best_name = http['title']
            if http.get('server'):
                srv = http['server']
                # Try to infer manufacturer from server string
                for brand in ('Hikvision','Dahua','Axis','TP-Link','Huawei',
                              'Samsung','Sony','Canon','Epson','Cisco'):
                    if brand.lower() in srv.lower():
                        if dev.get('manufacturer','Unknown') == 'Unknown':
                            dev['manufacturer'] = brand
                            dev['os']           = _guess_os(brand)
                            dev['dtype']        = _dtype_from_mfr(brand)
                        break

        mdns = results['mdns']
        if mdns.get('model'):
            best_model = mdns['model']
            # Map Apple model codes → human names
            _apple_models = {
                'iPhone': 'iPhone', 'iPad': 'iPad', 'MacBook': 'MacBook',
                'iMac': 'iMac', 'AppleTV': 'Apple TV', 'HomePod': 'HomePod',
                'Watch': 'Apple Watch', 'iPod': 'iPod',
            }
            for code, human in _apple_models.items():
                if code.lower() in best_model.lower():
                    best_os = 'iOS/macOS'
                    if dev.get('manufacturer','Unknown') == 'Unknown':
                        dev['manufacturer'] = 'Apple'
                    if not best_name:
                        best_name = human
                    break

        # ── Apply updates to DB ───────────────────────────────────
        changed = False
        if best_name and (not dev.get('name') or
                          dev['name'].startswith('Device-')):
            dev['name'] = best_name
            changed = True
        if best_model:
            dev['model'] = best_model
            changed = True
        if best_os and dev.get('os','Unknown') == 'Unknown':
            dev['os'] = best_os
            changed = True

        if changed:
            self.db.save()
            Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)

    def _scan_wifi(self):
        """
        Android WiFi scan — discovers nearby APs.
        Uses the BSSID list to cross-reference with ARP table results.
        Records RSSI for accurate radar distance.
        """
        try:
            act = _PythonActivity.mActivity
            wm  = act.getSystemService(_Context.WIFI_SERVICE)
            wm.startScan()
            for ap in wm.getScanResults().toArray():
                mac  = str(ap.BSSID).upper()
                ssid = str(ap.SSID) or "Hidden-AP"
                sig  = int(ap.level)
                mfr  = _oui(mac)
                # Update existing device RSSI
                dev_in_db = self.db.get(mac)
                if dev_in_db:
                    dev_in_db["signal"] = sig
                    ip = dev_in_db.get("ip", "")
                    if ip:
                        self._rssi_cache[ip] = sig
                    Clock.schedule_once(
                        lambda dt, d=dev_in_db: self.on_device(d), 0)
        except Exception:
            pass

        # Extra: get current connection info for own IP RSSI
        try:
            act  = _PythonActivity.mActivity
            wm   = act.getSystemService(_Context.WIFI_SERVICE)
            info = wm.getConnectionInfo()
            rssi = int(info.getRssi())
            my_ip = Scanner.my_ip()
            if my_ip not in ("Unknown", ""):
                self._rssi_cache[my_ip] = rssi
        except Exception:
            pass

    def _scan_hotspot_clients(self):
        """
        Detect phones connected to THIS device's WiFi hotspot.
        Reads /proc/net/arp (populated by Android when hotspot is active)
        and /data/misc/dhcp/dnsmasq.leases (root) or
        /data/misc/apf/dnsmasq.leases (newer Android).
        No root: still gets entries from ARP + /proc/net/arp which Android
        populates automatically for hotspot clients.
        """
        # Method A: Read DHCP lease files (may work on some Android versions)
        lease_files = [
            "/data/misc/dhcp/dnsmasq.leases",
            "/data/misc/apf/dnsmasq.leases",
            "/data/misc/dhcp/dnsmasq-l2t.leases",
        ]
        for lf in lease_files:
            try:
                with open(lf) as f:
                    for line in f:
                        # format: <timestamp> <mac> <ip> <hostname> *
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            mac  = parts[1].upper()
                            ip   = parts[2]
                            name = parts[3] if len(parts) > 3 else f"Device-{ip.split('.')[-1]}"
                            if name == "*":
                                name = f"Device-{ip.split('.')[-1]}"
                            if not self._is_real_device(ip, mac):
                                continue
                            mfr  = _oui(mac)
                            os_  = _guess_os(mfr)
                            dev  = self.db.upsert(
                                mac, ip=ip, name=name, manufacturer=mfr,
                                os=os_, signal=-60, dtype="phone" if _is_phone(
                                    {"manufacturer": mfr, "os": os_}) else "other"
                            )
                            Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)
            except Exception:
                pass

        # Method B: /proc/net/arp entries with src_ip in hotspot subnet (192.168.43.x)
        # Android hotspot default subnet is 192.168.43.0/24
        try:
            my_ip = Scanner.my_ip()
            if my_ip.startswith("192.168.43."):
                # This device IS a hotspot; all ARP entries are clients
                for ip, mac in self._read_arp():
                    if ip == my_ip:
                        continue
                    if ip.startswith("192.168.43.") and self._is_real_device(ip, mac):
                        mfr = _oui(mac)
                        os_ = _guess_os(mfr)
                        dev = self.db.upsert(
                            mac, ip=ip,
                            name=self._hostname(ip) or f"Hotspot-Client-{ip.split('.')[-1]}",
                            manufacturer=mfr, os=os_, signal=-50, dtype="phone"
                        )
                        Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)
        except Exception:
            pass

    def _scan_nsd(self):
        """
        Android NSD (Network Service Discovery) – discovers services on LAN.
        Runs a quick mDNS multicast query directly via UDP socket.
        Works without root on Android 6+.
        """
        try:
            self._scan_mdns()
        except Exception:
            pass

    def _scan_bt(self):
        try:
            adapter = _BTAdapter.getDefaultAdapter()
            if adapter and adapter.isEnabled():
                for btdev in adapter.getBondedDevices().toArray():
                    mac  = str(btdev.getAddress()).upper()
                    name = str(btdev.getName()) or mac
                    mfr  = _oui(mac)
                    new  = self.db.get(mac) is None
                    dev  = self.db.upsert(
                        mac, name=name, manufacturer=mfr,
                        os="Bluetooth", signal=-70, dtype="bluetooth"
                    )
                    if new:
                        self.db.log("INFO",
                                    f"Bluetooth: {name}  MAC:{mac}")
                    Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)
        except Exception:
            pass

    # ─── Method 3: mDNS / Bonjour discovery ──────────────────────────────
    def _loop_mdns(self):
        """
        Continuously sends mDNS queries every 20 s.
        iPhones announce as 'iPhone.local', Android phones as '<model>.local'.
        No root needed — uses UDP multicast on port 5353.
        """
        while self._run:
            try:
                self._scan_mdns()
            except Exception:
                pass
            time.sleep(20)

    def _scan_mdns(self):
        """
        Send mDNS PTR query to 224.0.0.251:5353.
        Parse responses for A/AAAA records → map hostname → IP.
        """
        MDNS_ADDR = "224.0.0.251"
        MDNS_PORT = 5353
        # Minimal mDNS query: PTR "_services._dns-sd._udp.local"
        # Transaction ID=0, FLAGS=0 (standard query)
        # Question: _services._dns-sd._udp.local PTR IN
        query = (
            b'\x00\x00'   # transaction ID
            b'\x00\x00'   # flags: standard query
            b'\x00\x01'   # 1 question
            b'\x00\x00\x00\x00\x00\x00'  # 0 answers/auth/additional
            b'\x09_services\x07_dns-sd\x04_udp\x05local\x00'
            b'\x00\x0c'   # type PTR
            b'\x00\x01'   # class IN
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(3.0)
            # Set multicast TTL
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(query, (MDNS_ADDR, MDNS_PORT))

            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    if not self._is_real_device(ip, "AA:BB:CC:DD:EE:FF"):
                        continue
                    # Parse the hostname from mDNS response
                    hostname = self._parse_mdns_name(data)
                    if hostname:
                        self._rssi_name_cache[ip] = hostname
                        # Detect phone type from hostname
                        hn_lower = hostname.lower()
                        entry = {"name": hostname, "type": "unknown", "os": "Unknown"}
                        if any(kw in hn_lower for kw in
                               ("iphone", "ipad", "macbook", "apple")):
                            entry.update({"type": "phone", "os": "iOS/macOS"})
                        elif any(kw in hn_lower for kw in
                                 ("android", "phone", "samsung", "xiaomi",
                                  "redmi", "huawei", "oppo", "vivo", "pixel",
                                  "galaxy", "note", "poco", "realme")):
                            entry.update({"type": "phone", "os": "Android"})
                        self._mdns_cache[ip] = entry

                        # If we know the IP, update or create device entry
                        self._register_mdns_device(ip, hostname,
                                                   entry.get("os", "Unknown"))
                except socket.timeout:
                    break
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    @staticmethod
    def _parse_mdns_name(data: bytes) -> str:
        """Extract first DNS name label from mDNS packet (simple parser)."""
        try:
            # Skip header (12 bytes), parse first question/answer name
            pos = 12
            labels = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                if length >= 0xC0:   # pointer
                    ptr = ((length & 0x3F) << 8) | data[pos + 1]
                    pos = ptr
                    continue
                pos += 1
                label = data[pos:pos + length].decode("utf-8", errors="ignore")
                labels.append(label)
                pos += length
            return ".".join(labels) if labels else ""
        except Exception:
            return ""

    def _register_mdns_device(self, ip: str, hostname: str, os_: str):
        """Register or update a device discovered via mDNS."""
        # Try to find MAC from ARP
        mac = self._ip_to_mac(ip)
        if not mac:
            # Generate pseudo-MAC from IP (unique but deterministic)
            parts = ip.split(".")
            mac = "FE:FE:{:02X}:{:02X}:{:02X}:{:02X}".format(
                int(parts[0]) if len(parts) > 0 else 0,
                int(parts[1]) if len(parts) > 1 else 0,
                int(parts[2]) if len(parts) > 2 else 0,
                int(parts[3]) if len(parts) > 3 else 0,
            )
        mfr = _oui(mac)
        if mfr == "Unknown":
            # Infer from hostname
            hn = hostname.lower()
            if "iphone" in hn or "ipad" in hn:
                mfr, os_ = "Apple", "iOS/macOS"
            elif "samsung" in hn:
                mfr, os_ = "Samsung", "Android"
            elif "xiaomi" in hn or "redmi" in hn or "poco" in hn:
                mfr, os_ = "Xiaomi", "Android"
            elif "huawei" in hn or "honor" in hn:
                mfr, os_ = "Huawei", "Android"
            elif "pixel" in hn:
                mfr, os_ = "Google", "Android"
            else:
                mfr = "Phone"
        name     = hostname.split(".")[0] or hostname
        signal   = self._rssi_cache.get(ip, -60)
        is_new   = self.db.get(mac) is None
        dev = self.db.upsert(mac, ip=ip, name=name, manufacturer=mfr,
                              os=os_, signal=signal, dtype="phone")
        if is_new:
            self.db.log("INFO",
                        f"mDNS device: {name}  [{mfr}]  IP:{ip}")
            if self.alert and self.db.setting("alert_new_device"):
                self.alert.trigger("New Device", f"{name} [{mfr}]", mac)
            threading.Thread(
                target=self._port_scan, args=(ip, mac), daemon=True).start()
        Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)

    def _ip_to_mac(self, ip: str) -> str:
        """Look up MAC for a given IP from ARP table."""
        for arp_ip, arp_mac in self._read_arp():
            if arp_ip == ip:
                return arp_mac
        return ""

    # ─── Method 4: SSDP / UPnP discovery ─────────────────────────────────
    def _loop_ssdp(self):
        """
        Sends SSDP M-SEARCH every 30 s.
        Many Android phones and smart devices respond.
        No root needed.
        """
        while self._run:
            try:
                self._scan_ssdp()
            except Exception:
                pass
            time.sleep(30)

    def _scan_ssdp(self):
        """
        Send SSDP M-SEARCH multicast and parse responses.
        Extracts IP and device description from Location header.
        """
        SSDP_ADDR = "239.255.255.250"
        SSDP_PORT = 1900
        SSDP_MSG  = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(4.0)
            sock.sendto(SSDP_MSG, (SSDP_ADDR, SSDP_PORT))

            deadline = time.time() + 4.0
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(1024)
                    ip = addr[0]
                    if not self._is_real_device(ip, "AA:BB:CC:DD:EE:FF"):
                        continue
                    text     = data.decode("utf-8", errors="ignore")
                    server   = ""
                    location = ""
                    for line in text.splitlines():
                        ll = line.lower()
                        if ll.startswith("server:"):
                            server = line.split(":", 1)[1].strip()
                        elif ll.startswith("location:"):
                            location = line.split(":", 1)[1].strip()

                    # Guess device type from Server header
                    sl  = server.lower()
                    is_p = any(kw in sl for kw in
                               ("android", "samsung", "xiaomi", "redmi",
                                "huawei", "iphone", "apple", "lg ", "sony",
                                "oppo", "vivo", "google", "pixel"))
                    if is_p or ip not in self._mdns_cache:
                        mac  = self._ip_to_mac(ip) or ""
                        mfr  = _oui(mac) if mac else "Unknown"
                        if mfr == "Unknown" and server:
                            mfr = "Phone" if is_p else "Unknown"
                        if not mac:
                            parts = ip.split(".")
                            mac = "FD:FD:{:02X}:{:02X}:{:02X}:{:02X}".format(
                                int(parts[0]) if len(parts) > 0 else 0,
                                int(parts[1]) if len(parts) > 1 else 0,
                                int(parts[2]) if len(parts) > 2 else 0,
                                int(parts[3]) if len(parts) > 3 else 0,
                            )
                        name   = (server[:30] if server else f"Device-{ip.split('.')[-1]}")
                        os_    = "Android" if "android" in sl else (
                                 "iOS/macOS" if "apple" in sl else "Unknown")
                        signal = self._rssi_cache.get(ip, -65)
                        is_new = self.db.get(mac) is None
                        if not is_p and not is_new:
                            continue   # only add new non-phone SSDP devices if they respond
                        dev = self.db.upsert(mac, ip=ip, name=name,
                                              manufacturer=mfr, os=os_,
                                              signal=signal, dtype="phone" if is_p else "other")
                        if is_new:
                            self.db.log("INFO",
                                        f"SSDP device: {name}  IP:{ip}  [{server[:40]}]")
                        Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)
                except socket.timeout:
                    break
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ── TCP traffic loop ─────────────────────────────────────────────────
    # ── DNS monitoring (passive sniffer + active proxy) ──────────────────────

    @staticmethod
    def _parse_dns_packet(data: bytes) -> tuple:
        """
        Parse a raw DNS UDP packet.
        Returns (src_is_query: bool, questions: list[str], answers: list[str])
        """
        questions, answers = [], []
        try:
            if len(data) < 12:
                return False, [], []
            flags    = (data[2] << 8) | data[3]
            is_query = (flags & 0x8000) == 0
            qdcount  = (data[4] << 8) | data[5]
            ancount  = (data[6] << 8) | data[7]

            def _read_name(buf: bytes, off: int) -> tuple:
                labels, visited = [], set()
                while off < len(buf):
                    if off in visited:
                        break
                    visited.add(off)
                    ln = buf[off]
                    if ln == 0:
                        off += 1
                        break
                    if (ln & 0xC0) == 0xC0:   # pointer
                        ptr = ((ln & 0x3F) << 8) | buf[off + 1]
                        name_part, _ = _read_name(buf, ptr)
                        labels.append(name_part)
                        off += 2
                        break
                    off += 1
                    labels.append(buf[off:off + ln].decode('ascii', errors='ignore'))
                    off += ln
                return '.'.join(labels), off

            off = 12
            for _ in range(qdcount):
                name, off = _read_name(data, off)
                off += 4   # skip QTYPE + QCLASS
                if name:
                    questions.append(name)

            for _ in range(ancount):
                _, off = _read_name(data, off)
                rtype  = (data[off] << 8) | data[off + 1]
                off   += 8   # type + class + TTL
                rdlen  = (data[off] << 8) | data[off + 1]
                off   += 2
                if rtype == 1 and rdlen == 4:   # A record
                    ip_str = '.'.join(str(b) for b in data[off:off + 4])
                    answers.append(ip_str)
                elif rtype == 5:                # CNAME
                    cname, _ = _read_name(data, off)
                    answers.append(cname)
                off += rdlen
        except Exception:
            pass
        return not is_query if 'is_query' in dir() else False, questions, answers

    def _dns_sniffer_loop(self):
        """
        Passive DNS capture — two complementary methods:

        Method A (mDNS multicast 224.0.0.251:5353) — no root, no config needed.
          Captures all .local lookups + inter-device mDNS queries.

        Method B (DNS proxy on port 5300 or 53) — optional.
          When the router's DHCP is set to give out our IP as DNS server,
          ALL DNS queries from ALL devices flow through here and are logged.
          Falls back to port 5300 if port 53 is in use.
        """
        import struct as _st

        # ── Method A: mDNS multicast listener ──────────────────────
        def _mdns_listen():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                     socket.IPPROTO_UDP)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.setsockopt(socket.SOL_SOCKET,
                                    socket.SO_REUSEPORT, 1)
                except AttributeError:
                    pass
                sock.bind(('', 5353))
                mreq = _st.pack('4sL',
                                socket.inet_aton('224.0.0.251'),
                                socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP,
                                socket.IP_ADD_MEMBERSHIP, mreq)
                sock.settimeout(2.0)
                while self._run:
                    try:
                        data, addr = sock.recvfrom(4096)
                        src_ip = addr[0]
                        _, questions, _ = self._parse_dns_packet(data)
                        for q in questions:
                            self.db.add_dns_event(src_ip, q, 'mDNS')
                    except socket.timeout:
                        pass
                    except Exception:
                        pass
                sock.close()
            except Exception:
                pass

        # ── Method B: DNS proxy server ──────────────────────────────
        def _dns_proxy():
            upstream = ('8.8.8.8', 53)
            for port in (53, 5353, 5300):
                try:
                    srv = socket.socket(socket.AF_INET,
                                        socket.SOCK_DGRAM)
                    srv.setsockopt(socket.SOL_SOCKET,
                                   socket.SO_REUSEADDR, 1)
                    srv.bind(('', port))
                    self._dns_proxy_port = port
                    self.db.log("INFO",
                                f"DNS proxy active on port {port} — "
                                "point devices to this IP for full DNS logging")
                    srv.settimeout(2.0)
                    break
                except Exception:
                    srv = None
                    continue

            if not srv:
                return

            fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fwd.settimeout(3.0)

            while self._run:
                try:
                    data, client = srv.recvfrom(4096)
                    src_ip = client[0]
                    # Parse query
                    _, questions, _ = self._parse_dns_packet(data)
                    for q in questions:
                        if q:
                            svc = _domain_to_service(q)
                            self.db.add_dns_event(src_ip, q, 'DNS')
                            # Also tag matching device
                            dev = self.db._find_by_ip(src_ip)
                            if dev and _is_phone(dev):
                                svcs = dev.setdefault('services', [])
                                if svc not in svcs:
                                    svcs.insert(0, svc)
                                    if len(svcs) > 30:
                                        dev['services'] = svcs[:30]
                    # Forward to real DNS
                    try:
                        fwd.sendto(data, upstream)
                        resp, _ = fwd.recvfrom(4096)
                        srv.sendto(resp, client)
                    except Exception:
                        pass
                except socket.timeout:
                    pass
                except Exception:
                    pass
            srv.close()
            fwd.close()

        threading.Thread(target=_mdns_listen, daemon=True).start()
        threading.Thread(target=_dns_proxy,   daemon=True).start()

    def _loop_traffic(self):
        while self._run:
            try:
                conns = self._read_tcp()
                new_events = []
                for local_ip, remote_ip, remote_port, direction in conns:
                    key = (local_ip, remote_ip, remote_port)
                    if key not in self._seen_conns:
                        self._seen_conns.add(key)
                        if not self.db.setting("service_analysis", True):
                            continue
                        svc, hostname = _resolve_full(remote_ip, remote_port)
                        detail = self._classify_traffic(svc, direction,
                                                        remote_port)
                        self.db.add_traffic(
                            local_ip, svc, direction,
                            remote_ip=remote_ip,
                            port=remote_port,
                            detail=detail
                        )
                        ev = {
                            "time":      datetime.now().strftime("%H:%M:%S"),
                            "src":       local_ip,
                            "dst":       remote_ip,
                            "hostname":  hostname,
                            "port":      remote_port,
                            "service":   svc,
                            "direction": direction,
                            "detail":    detail,
                        }
                        new_events.append(ev)
                        # tag service on matching phone
                        for dev in self.db.all():
                            if dev.get("ip") == local_ip and _is_phone(dev):
                                svcs = dev.setdefault("services", [])
                                if svc not in svcs:
                                    svcs.insert(0, svc)
                                    if len(svcs) > 20:
                                        dev["services"] = svcs[:20]
                if new_events:
                    Clock.schedule_once(
                        lambda dt, ev=new_events: self.on_traffic(ev), 0)
                if len(self._seen_conns) > 2000:
                    self._seen_conns = set(list(self._seen_conns)[-1000:])
            except Exception:
                pass
            time.sleep(3)

    @staticmethod
    def _classify_traffic(svc: str, direction: str, port: int) -> str:
        """Return human-readable description of what's happening."""
        media_svcs  = {"Instagram", "TikTok", "YouTube", "Snapchat",
                       "Netflix", "Spotify"}
        msg_svcs    = {"WhatsApp", "Telegram", "Facebook", "Twitter/X"}
        upload_port = {443, 80, 8080}
        if svc in media_svcs:
            if direction == "OUT":
                return f"Uploading/Streaming on {svc}"
            return f"Downloading media from {svc}"
        if svc in msg_svcs:
            if direction == "OUT":
                return f"Sending message/media via {svc}"
            return f"Receiving message/media via {svc}"
        if svc in ("iCloud", "Apple", "AWS/Amazon", "Google"):
            if direction == "OUT":
                return f"Uploading to {svc}"
            return f"Syncing from {svc}"
        if port == 443:
            return "Encrypted HTTPS connection"
        if port == 80:
            return "HTTP request"
        return f"Connection on port {port}"

    def _read_tcp(self):
        """Read ESTABLISHED TCP connections – 2 methods for max coverage."""
        rows = []

        # ── Method A: /proc/net/tcp  (Linux / Android) ───────────────
        for fname in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(fname) as f:
                    for line in f.readlines()[1:]:
                        p = line.split()
                        if len(p) < 4:
                            continue
                        state = int(p[3], 16)
                        if state != 1:   # 1 = ESTABLISHED
                            continue
                        local_hex   = p[1]
                        remote_hex  = p[2]
                        local_ip    = _hex_to_ip4(local_hex.split(":")[0])
                        local_port  = int(local_hex.split(":")[1], 16)
                        remote_ip   = _hex_to_ip4(remote_hex.split(":")[0])
                        remote_port = int(remote_hex.split(":")[1], 16)
                        if remote_ip in ("0.0.0.0", "127.0.0.1"):
                            continue
                        direction = ("OUT" if remote_port < 1024
                                             or remote_port in
                                             (5222, 5228, 5353, 8080, 8443, 19305)
                                     else ("IN" if local_port < 1024 else "OUT"))
                        rows.append((local_ip, remote_ip, remote_port, direction))
            except Exception:
                pass

        # ── Method B: netstat -ano  (Windows) ────────────────────────
        if platform.system() == "Windows" and not rows:
            try:
                out = subprocess.check_output(
                    ["netstat", "-ano"], stderr=subprocess.DEVNULL, timeout=5
                ).decode(errors="ignore")
                for line in out.splitlines():
                    p = line.split()
                    if len(p) < 4:
                        continue
                    if "ESTABLISHED" not in p:
                        continue
                    local_addr  = p[1]
                    remote_addr = p[2]
                    # addr format: ip:port
                    def _split(addr):
                        parts = addr.rsplit(":", 1)
                        return (parts[0].strip("[]"), int(parts[1])) if len(parts) == 2 else ("", 0)
                    local_ip, local_port   = _split(local_addr)
                    remote_ip, remote_port = _split(remote_addr)
                    if not remote_ip or remote_ip in ("0.0.0.0", "127.0.0.1", "::1"):
                        continue
                    direction = "OUT" if remote_port < 1024 else "OUT"
                    rows.append((local_ip, remote_ip, remote_port, direction))
            except Exception:
                pass

        return rows


# ─── Radar Widget ─────────────────────────────────────────────────────────────
class RadarWidget(Widget):
    """
    Radar with:
     - Sweep-based fade: blips brighten when hit by beam, dim as beam moves away
     - Glow rings: 3-layer phosphor glow around each blip
     - Device-type canvas icons
     - Intruder blips in red
    """

    RINGS = 4
    SWEEP = 68.0    # deg / sec
    PULSE = 0.30    # cycles / sec
    MAX_B = 24      # max simultaneous blips

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._angle = 0.0
        self._phase = 0.0
        # mac → (angle, dist, rgb3, dtype, is_intruder)
        self._blips = {}

        with self.canvas.before:
            Color(*G4)
            self._bg = Rectangle(pos=self.pos, size=self.size)

        with self.canvas:
            # ── static grid ───────────────────────────────────────────
            Color(*G3)
            self._gh = [Line(points=[0]*4, width=dp(.4)) for _ in range(6)]
            self._gv = [Line(points=[0]*4, width=dp(.4)) for _ in range(6)]
            Color(*G3)
            self._d1 = Line(points=[0]*4, width=dp(.4))
            self._d2 = Line(points=[0]*4, width=dp(.4))
            # ── range rings ───────────────────────────────────────────
            Color(*G2)
            self._rngs  = [Line(circle=(0,0,1), width=dp(.7))
                           for _ in range(self.RINGS)]
            Color(*G1)
            self._outer = Line(circle=(0,0,1), width=dp(1.4))
            # ── crosshair ────────────────────────────────────────────
            Color(*G2)
            self._chh = Line(points=[0]*4, width=dp(.7))
            self._chv = Line(points=[0]*4, width=dp(.7))
            # ── sweep + 22-step phosphor fade sector ──────────────────
            self._sc = Color(*G1[:3], .95)
            self._sl = Line(points=[0]*4, width=dp(2.4), cap='round')
            self._fd = []
            for _ in range(22):
                fc = Color(*G1[:3], 0.0)
                fl = Line(points=[0]*4, width=dp(1.0))
                self._fd.append((fc, fl))
            # ── pulse ring ────────────────────────────────────────────
            self._pc = Color(*G1[:3], 0.0)
            self._pr = Line(circle=(0,0,1), width=dp(.9))
            # ── blip slots: glow_outer / glow_mid / dot / icon lines ──
            self._bs = []
            for _ in range(self.MAX_B):
                # outer glow
                cgo = Color(0, 0, 0, 0)
                ego = Ellipse(pos=(0,0), size=(dp(22), dp(22)))
                # mid glow
                cgm = Color(0, 0, 0, 0)
                egm = Ellipse(pos=(0,0), size=(dp(13), dp(13)))
                # core dot
                c_dot = Color(0, 0, 0, 0)
                e_dot = Ellipse(pos=(0,0), size=(dp(7),  dp(7)))
                # icon lines
                c_icon = Color(0, 0, 0, 0)
                l_a = Line(points=[0,0,0,0], width=dp(0.8))
                l_b = Line(points=[0,0,0,0], width=dp(0.8))
                l_c = Line(points=[0,0,0,0], width=dp(0.7))
                self._bs.append((cgo, ego, cgm, egm,
                                  c_dot, e_dot, c_icon, l_a, l_b, l_c))

        self.bind(pos=self._layout, size=self._layout)
        Clock.schedule_interval(self._tick, 0)

    # ── geometry ─────────────────────────────────────────────────────────
    def _geo(self):
        w, h = self.width, self.height
        if w <= 0 or h <= 0:
            return None
        r = min(w, h) * 0.43
        return self.x + w/2, self.y + h/2, r

    def _pt(self, cx, cy, r, a, d=1.0):
        rad = math.radians(a)
        return cx + r*d*math.cos(rad), cy + r*d*math.sin(rad)

    def _layout(self, *_):
        g = self._geo()
        if not g:
            return
        cx, cy, r = g
        self._bg.pos  = self.pos
        self._bg.size = self.size
        n = len(self._gh)
        for i, ln in enumerate(self._gh):
            y = self.y + self.height*(i+1)/(n+1)
            ln.points = [self.x, y, self.x+self.width, y]
        for i, ln in enumerate(self._gv):
            x = self.x + self.width*(i+1)/(n+1)
            ln.points = [x, self.y, x, self.y+self.height]
        self._d1.points = [cx-r, cy-r, cx+r, cy+r]
        self._d2.points = [cx-r, cy+r, cx+r, cy-r]
        for i, rn in enumerate(self._rngs):
            rn.circle = (cx, cy, r*(i+1)/self.RINGS)
        self._outer.circle = (cx, cy, r)
        self._chh.points = [cx-r, cy, cx+r, cy]
        self._chv.points = [cx, cy-r, cx, cy+r]
        self._draw_sweep(cx, cy, r)
        self._draw_pulse(cx, cy, r)
        self._draw_blips(cx, cy, r)

    def _draw_sweep(self, cx, cy, r):
        x2, y2 = self._pt(cx, cy, r, self._angle)
        self._sl.points = [cx, cy, x2, y2]
        for i, (fc, fl) in enumerate(self._fd):
            off = (i+1) * (72.0/len(self._fd))
            fc.rgba = (*G1[:3], 0.24*(1 - i/len(self._fd)))
            xf, yf  = self._pt(cx, cy, r, self._angle - off)
            fl.points = [cx, cy, xf, yf]

    def _draw_pulse(self, cx, cy, r):
        pr = r*(0.10 + 0.90*self._phase)
        self._pc.rgba   = (*G1[:3], max(0, 0.45*(1-self._phase)))
        self._pr.circle = (cx, cy, pr)

    @staticmethod
    def _sweep_alpha(sweep_angle: float, blip_angle: float) -> float:
        """
        Returns 0.30–1.00 based on how recently the sweep passed the blip.
        Full brightness (1.0) right after sweep, fades to 0.30 after full rotation.
        """
        delta = (sweep_angle - blip_angle) % 360.0
        return 1.0 - (delta / 360.0) * 0.70

    def _draw_blips(self, cx, cy, r):
        blips = list(self._blips.values())
        for i, slot in enumerate(self._bs):
            cgo, ego, cgm, egm, c_dot, e_dot, c_icon, l_a, l_b, l_c = slot

            if i >= len(blips):
                cgo.rgba = cgm.rgba = c_dot.rgba = c_icon.rgba = (0,0,0,0)
                continue

            angle, dist, col, dtype, is_intruder = blips[i]
            bx, by = self._pt(cx, cy, r, angle, dist)

            # ── sweep-based fade alpha ────────────────────────────────
            alpha = self._sweep_alpha(self._angle, angle)

            # intruders pulse red more aggressively
            if is_intruder:
                pulse = 0.5 + 0.5 * math.sin(time.time() * 6)
                alpha = max(alpha, pulse)
                col   = RED[:3]

            # Size multiplier: phones/routers bigger, others smaller
            sz_mult = 1.0 if dtype == "phone" else (0.8 if dtype == "router" else 0.6)

            # ── outer glow ───────────────────────────────────────────
            sg = dp(22) * sz_mult
            cgo.rgba = (*col, alpha * (0.18 if dtype == "phone" else 0.10))
            ego.pos  = (bx - sg/2, by - sg/2)
            ego.size = (sg, sg)

            # ── mid glow ─────────────────────────────────────────────
            sm = dp(14) * sz_mult
            cgm.rgba = (*col, alpha * (0.38 if dtype == "phone" else 0.22))
            egm.pos  = (bx - sm/2, by - sm/2)
            egm.size = (sm, sm)

            # ── core dot ─────────────────────────────────────────────
            sd = dp(8) * sz_mult if dtype == "phone" else dp(5)
            c_dot.rgba = (*col, min(1.0, alpha + (0.20 if dtype == "phone" else 0.05)))
            e_dot.pos  = (bx - sd/2, by - sd/2)
            e_dot.size = (sd, sd)

            # ── device icon ───────────────────────────────────────────
            c_icon.rgba = (*col, alpha * 0.90)
            self._icon(dtype, bx, by, dp(11), l_a, l_b, l_c)

    def _icon(self, dtype, bx, by, s, l_a, l_b, l_c):
        """Draw device-type icon using pre-allocated Line instructions."""
        if dtype == 'phone':
            w, h = s*0.40, s*0.75
            # portrait body
            l_a.rectangle = (bx - w, by - h, w*2, h*2)
            # home "button" dash at bottom
            l_b.points = [bx - w*0.35, by - h - dp(2.5),
                          bx + w*0.35, by - h - dp(2.5)]
            l_c.points = [0, 0, 0, 0]

        elif dtype == 'router':
            # Three WiFi arcs (ellipse partial arcs)
            l_a.ellipse = (bx - s*0.55, by - s*0.1, s*1.1, s*0.9, 30, 150)
            l_b.ellipse = (bx - s*0.35, by - s*0.0, s*0.7,  s*0.6, 30, 150)
            l_c.points  = [bx - s*0.15, by - s*0.35,
                           bx + s*0.15, by - s*0.35]

        elif dtype == 'laptop':
            w, h = s*0.65, s*0.45
            # screen rectangle
            l_a.rectangle = (bx - w, by - h*0.2, w*2, h)
            # base wider line
            l_b.points = [bx - w*1.2, by - h*0.2,
                          bx + w*1.2, by - h*0.2]
            l_c.points = [0, 0, 0, 0]

        elif dtype == 'camera':
            # outer circle
            l_a.circle = (bx, by, s*0.55)
            # inner lens
            l_b.circle = (bx, by, s*0.28)
            l_c.points = [0, 0, 0, 0]

        elif dtype == 'tv':
            w, h = s*0.75, s*0.5
            # wide screen
            l_a.rectangle = (bx - w, by - h*0.4, w*2, h)
            # stand
            l_b.points = [bx - s*0.25, by - h*0.4 - dp(3),
                          bx + s*0.25, by - h*0.4 - dp(3)]
            l_c.points = [bx, by - h*0.4,
                          bx, by - h*0.4 - dp(3)]

        elif dtype == 'server':
            # square with lines across
            l_a.rectangle = (bx - s*0.5, by - s*0.5, s, s)
            l_b.points = [bx - s*0.5, by,
                          bx + s*0.5, by]
            l_c.points = [bx - s*0.5, by - s*0.25,
                          bx + s*0.5, by - s*0.25]

        elif dtype == 'bluetooth':
            # diamond shape
            l_a.points = [bx,       by + s*0.5,
                          bx + s*0.4, by,
                          bx,       by - s*0.5,
                          bx - s*0.4, by,
                          bx,       by + s*0.5]
            l_b.points = [0, 0, 0, 0]
            l_c.points = [0, 0, 0, 0]

        else:   # unknown – cross
            l_a.points = [bx - s*0.4, by, bx + s*0.4, by]
            l_b.points = [bx, by - s*0.4, bx, by + s*0.4]
            l_c.points = [0, 0, 0, 0]

    def _tick(self, dt):
        self._angle = (self._angle + self.SWEEP*dt) % 360.0
        self._phase = (self._phase + self.PULSE*dt) % 1.0
        g = self._geo()
        if g:
            cx, cy, r = g
            self._draw_sweep(cx, cy, r)
            self._draw_pulse(cx, cy, r)
            self._draw_blips(cx, cy, r)   # live fade every frame

    def set_device(self, dev: dict, threat: bool = False,
                   is_intruder: bool = False):
        mac   = dev['mac']
        sig   = dev.get('signal', -60)
        dtype = dev.get('dtype', _classify(dev))
        # angle deterministic from MAC hash
        angle = (int(mac.replace(":", ""), 16) % 3600) / 10.0
        # distance: real RSSI → [-90..-30] → [0.92..0.15]
        # Better mapping: -30 = very close (0.10), -90 = far (0.95)
        dist = max(0.10, min(0.95, (abs(sig) - 30) / 65.0))
        col  = _blip_color(dev, threat or is_intruder)
        self._blips[mac] = (angle, dist, col, dtype, is_intruder)
        g = self._geo()
        if g:
            self._draw_blips(*g)


# ─── Shared UI helpers ────────────────────────────────────────────────────────
def _signal_bars(rssi) -> str:
    """Convert RSSI dBm to visual bar string."""
    try:
        v = int(rssi)
    except (TypeError, ValueError):
        return "----"
    if v >= -50:  return "[||||]"
    if v >= -60:  return "[|||·]"
    if v >= -70:  return "[||··]"
    if v >= -80:  return "[|···]"
    return                "[····]"

def _signal_color(rssi) -> tuple:
    try:
        v = int(rssi)
    except (TypeError, ValueError):
        return G3
    if v >= -55: return G1
    if v >= -70: return YEL
    return RED

def _brand_sym(mfr: str, dtype: str) -> tuple:
    """Return (symbol, color, label) for a manufacturer/dtype."""
    m = {
        "Apple":   ("[A]",   WHT, "iPhone"),
        "Samsung": ("[S]",   (0.20,0.55,1.00,1), "Samsung"),
        "Xiaomi":  ("[Mi]",  (1.00,0.35,0.05,1), "Xiaomi"),
        "Redmi":   ("[Mi]",  (1.00,0.35,0.05,1), "Redmi"),
        "POCO":    ("[Mi]",  (1.00,0.35,0.05,1), "POCO"),
        "Infinix": ("[IX]",  (0.20,0.80,0.40,1), "Infinix"),
        "Tecno":   ("[TC]",  (0.20,0.80,0.40,1), "Tecno"),
        "Itel":    ("[IT]",  (0.20,0.80,0.40,1), "Itel"),
        "Huawei":  ("[HW]",  (0.80,0.10,0.10,1), "Huawei"),
        "Honor":   ("[H]",   (0.80,0.10,0.10,1), "Honor"),
        "OnePlus": ("[1+]",  (1.00,0.30,0.05,1), "OnePlus"),
        "OPPO":    ("[OP]",  (0.00,0.70,0.60,1), "OPPO"),
        "Realme":  ("[RL]",  (1.00,0.55,0.00,1), "Realme"),
        "Vivo":    ("[V]",   (0.20,0.40,1.00,1), "Vivo"),
        "Google":  ("[G]",   (0.20,0.55,1.00,1), "Pixel"),
        "Nokia":   ("[N]",   (0.00,0.50,0.80,1), "Nokia"),
        "Motorola":("[Mo]",  (0.70,0.20,0.80,1), "Motorola"),
        "LG":      ("[LG]",  (0.80,0.05,0.20,1), "LG"),
        "Sony":    ("[So]",  (0.05,0.10,0.60,1), "Sony"),
        "Lenovo":  ("[Le]",  (0.80,0.10,0.10,1), "Lenovo"),
    }.get(mfr)
    if m:
        return m
    if dtype == "phone":   return ("[D]",  G1,  "Android")
    if dtype == "camera":  return ("[CAM]",CYN, "Camera")
    if dtype == "pc":      return ("[PC]", (0.60,0.80,1.00,1), "PC")
    if dtype == "router":  return ("[RT]", YEL, "Router")
    return ("[?]", G3, "Device")

def _lbl(text, size=11, color=G2, bold=False, halign='left', **kwargs):
    lb = Label(text=str(text), font_size=sp(size), color=color,
               bold=bold, halign=halign, valign='middle', **kwargs)
    lb.bind(size=lb.setter('text_size'))
    return lb


def _card(widget, radius=dp(5)):
    with widget.canvas.before:
        Color(*G4)
        rb = RoundedRectangle(pos=widget.pos, size=widget.size, radius=[radius])
        Color(*G3)
        lb = Line(rounded_rectangle=(widget.x, widget.y,
                                     widget.width, widget.height, radius),
                  width=dp(0.5))
    widget.bind(
        pos =lambda w, v: (setattr(rb, 'pos', v),
                           setattr(lb, 'rounded_rectangle',
                                   (v[0], v[1], w.width, w.height, radius))),
        size=lambda w, v: (setattr(rb, 'size', v),
                           setattr(lb, 'rounded_rectangle',
                                   (w.x, w.y, v[0], v[1], radius))),
    )


def _topline(widget):
    with widget.canvas.before:
        Color(*G3)
        ln = Line(points=[0]*4, width=dp(0.6))
    widget.bind(
        pos =lambda w, v: setattr(ln, 'points',
                                  [v[0], v[1]+w.height,
                                   v[0]+w.width, v[1]+w.height]),
        size=lambda w, v: setattr(ln, 'points',
                                  [w.x, w.y+v[1],
                                   w.x+v[0], w.y+v[1]]),
    )


# ─── Base Screen ─────────────────────────────────────────────────────────────
class BaseScreen(Screen):
    def __init__(self, db, **kwargs):
        super().__init__(**kwargs)
        self.db   = db
        self.root_box = BoxLayout(orientation='vertical',
                                  spacing=0, padding=0)
        self.add_widget(self.root_box)

    def _header(self, title, sub=""):
        h = dp(58) if sub else dp(42)
        hdr = BoxLayout(orientation='vertical',
                        size_hint_y=None, height=h,
                        padding=[dp(14), dp(5)])
        _topline(hdr)
        with hdr.canvas.before:
            Color(*G4)
            rb = Rectangle(pos=hdr.pos, size=hdr.size)
            hdr.bind(pos=lambda w, v: setattr(rb, 'pos', v),
                     size=lambda w, v: setattr(rb, 'size', v))
        hdr.add_widget(_lbl(title, size=16, color=G1, bold=True))
        if sub:
            hdr.add_widget(_lbl(sub, size=9, color=G3))
        return hdr


# ─── Radar Screen ─────────────────────────────────────────────────────────────
class RadarScreen(BaseScreen):
    def __init__(self, db, **kwargs):
        super().__init__(db, name='radar', **kwargs)
        self.root_box.add_widget(
            self._header("[ NEXUS VISION ]",
                         "TACTICAL NETWORK RADAR  v1.0"))
        self.radar = RadarWidget(size_hint=(1, 1))
        self.root_box.add_widget(self.radar)

        self._hud = _lbl(
            "DEVICES: 0  |  NO DATA YET  |  SCAN ACTIVE",
            size=10, color=G2, halign='center')
        hud_row = BoxLayout(size_hint_y=None, height=dp(26),
                            padding=[dp(8), dp(2)])
        hud_row.add_widget(self._hud)
        self.root_box.add_widget(hud_row)

    def on_pre_enter(self, *args):
        """Re-request permissions every time radar screen is opened."""
        if ANDROID:
            _request_android_permissions()

    def on_device(self, dev):
        # Only show PHONES on radar
        mac    = dev['mac']
        is_phn = _is_phone(dev)
        if is_phn:
            self.radar.set_device(
                dev,
                threat      = self.db.is_blocked(mac),
                is_intruder = self.db.is_intruder(mac)
            )
        phones    = [d for d in self.db.active() if _is_phone(d)]
        intruders = [d for d in phones if self.db.is_intruder(d['mac'])]
        mfr = dev.get('manufacturer', '?')
        sig = dev.get('signal', '?')
        alert_txt = f"  !! {len(intruders)} INTRUDER" if intruders else ""
        self._hud.text = (
            f"PHONES: {len(phones)}  "
            f"LAST: {dev.get('name','?')} [{mfr}] {sig}dBm"
            f"{alert_txt}"
        )
        self._hud.color = RED if intruders else G2


# ─── Devices Screen ───────────────────────────────────────────────────────────
class DeviceRow(BoxLayout):
    def __init__(self, dev, db, on_block, on_trust=None, on_tap=None, **kwargs):
        super().__init__(orientation='horizontal', size_hint_y=None,
                         spacing=dp(8), padding=[dp(10), dp(8)], **kwargs)
        _card(self)
        self._dev    = dev
        self._on_tap = on_tap
        mac      = dev['mac']
        mfr      = dev.get('manufacturer', 'Unknown')
        os_      = dev.get('os', 'Unknown')
        blocked  = db.is_blocked(mac)
        trusted  = db.is_trusted(mac)
        intruder = db.is_intruder(mac)

        # dynamic height: base + ports row if any
        ports = dev.get('open_ports', [])
        svcs  = dev.get('services',   [])
        h = dp(108) + (dp(20) if ports else 0) + (dp(18) if svcs else 0)
        self.size_hint_y = None
        self.height      = h

        dtype      = dev.get('dtype', 'other')
        ip         = dev.get('ip', '?')
        sig        = dev.get('signal', None)
        last_seen  = str(dev.get('last_seen', ''))[:16]
        sym, sym_col, type_lbl = _brand_sym(mfr, dtype)

        # ── dynamic card height ───────────────────────────────────────
        n_rows = 3 + (1 if ports or svcs else 0)
        h = dp(16) * n_rows + dp(32)
        self.size_hint_y = None
        self.height = max(h, dp(88))

        # ── LEFT: brand icon block ────────────────────────────────────
        icon_col = BoxLayout(orientation='vertical',
                             size_hint_x=None, width=dp(52),
                             padding=[dp(2), dp(6)], spacing=dp(2))
        sym_lbl = _lbl(sym, size=15, color=sym_col, bold=True, halign='center')
        type_lb = _lbl(type_lbl, size=7, color=sym_col, halign='center')
        icon_col.add_widget(sym_lbl)
        icon_col.add_widget(type_lb)

        if trusted:
            icon_col.add_widget(_lbl("[OK]", size=8, color=G1,
                                     halign='center', bold=True))
        elif intruder:
            icon_col.add_widget(_lbl("[!!]", size=8, color=RED,
                                     halign='center', bold=True))

        # ── CENTER: info block ────────────────────────────────────────
        info = BoxLayout(orientation='vertical', spacing=dp(1),
                         padding=[0, dp(6), 0, dp(4)])

        # Row 1: device name + status dot
        name_row = BoxLayout(size_hint_y=None, height=dp(22))
        name_str  = dev.get('name', 'Unknown')
        if intruder:   name_str = "[!] " + name_str
        elif blocked:  name_str = "[X] " + name_str
        name_col = (RED if (blocked or intruder) else G1)
        name_row.add_widget(_lbl(name_str, size=13, color=name_col, bold=True))
        info.add_widget(name_row)

        # Row 2: brand / model / OS
        model_str = dev.get('model', '')
        row2_txt  = f"{mfr}  ·  {model_str}" if model_str else f"{mfr}  ·  {os_}"
        info.add_widget(_lbl(row2_txt, size=9, color=G2))

        # Row 3: IP · Signal bars · last seen
        bars = _signal_bars(sig)
        bar_col = _signal_color(sig)
        net_row = BoxLayout(size_hint_y=None, height=dp(16), spacing=dp(4))
        net_row.add_widget(_lbl(f"IP: {ip}", size=9, color=G2))
        net_row.add_widget(_lbl(bars, size=9, color=bar_col, bold=True))
        info.add_widget(net_row)

        # Row 4: ports / services (compact)
        if ports:
            info.add_widget(_lbl(
                f"Ports: {', '.join(str(p) for p in ports[:8])}",
                size=8, color=YEL))
        elif svcs:
            info.add_widget(_lbl(
                f"Svc: {', '.join(svcs[:5])}",
                size=8, color=CYN))

        # ── RIGHT: action buttons ─────────────────────────────────────
        btn_col = BoxLayout(orientation='vertical',
                            size_hint_x=None, width=dp(68),
                            spacing=dp(5), padding=[dp(2), dp(8)])

        def _mk_btn(txt, col):
            b = Button(text=txt, font_size=sp(9), color=col, bold=True,
                       background_color=(0, 0, 0, 0), background_normal='',
                       size_hint_y=None, height=dp(26))
            with b.canvas.before:
                Color(col[0], col[1], col[2], 0.12)
                rb = RoundedRectangle(pos=b.pos, size=b.size, radius=[dp(4)])
                b.bind(pos=lambda w, v: setattr(rb, 'pos', v),
                       size=lambda w, v: setattr(rb, 'size', v))
            return b

        btn_block = _mk_btn(
            "UNBLOCK" if blocked else "BLOCK",
            YEL if blocked else RED)
        btn_block.bind(on_release=lambda *_: on_block(mac))

        btn_trust = _mk_btn(
            "UNTRUST" if trusted else "TRUST",
            G3 if trusted else G1)
        if on_trust:
            btn_trust.bind(on_release=lambda *_: on_trust(mac))

        btn_col.add_widget(btn_block)
        btn_col.add_widget(btn_trust)

        self.add_widget(icon_col)
        self.add_widget(info)
        self.add_widget(btn_col)

        if on_tap:
            self.bind(on_touch_down=self._check_tap)

    def _check_tap(self, widget, touch):
        if self.collide_point(*touch.pos) and self._on_tap:
            self._on_tap(self._dev)
            return True


# ─── Device Detail Screen ────────────────────────────────────────────────────
class DeviceDetailScreen(Screen):
    """Full-screen detail panel opened when tapping a device card."""

    def __init__(self, db, scanner_ref, ping_mon, sm_ref, **kwargs):
        super().__init__(name='device_detail', **kwargs)
        self.db       = db
        self.scanner  = scanner_ref
        self.ping_mon = ping_mon
        self.sm       = sm_ref      # ScreenManager reference
        self._dev     = None

        root = BoxLayout(orientation='vertical', spacing=0, padding=0)
        with root.canvas.before:
            Color(*BG)
            bg = Rectangle(pos=root.pos, size=root.size)
            root.bind(pos=lambda w, v: setattr(bg, 'pos', v),
                      size=lambda w, v: setattr(bg, 'size', v))

        # ── top bar: back button + title ─────────────────────────────
        top = BoxLayout(size_hint_y=None, height=dp(48),
                        padding=[dp(6), dp(4)], spacing=dp(6))
        with top.canvas.before:
            Color(0, 0, 0, 0.6)
            tb = Rectangle(pos=top.pos, size=top.size)
            top.bind(pos=lambda w, v: setattr(tb, 'pos', v),
                     size=lambda w, v: setattr(tb, 'size', v))
        back = Button(text="[< BACK]", font_size=sp(11), color=G1, bold=True,
                      background_color=(0, 0, 0, 0), background_normal='',
                      size_hint_x=None, width=dp(80))
        back.bind(on_release=lambda *_: self._go_back())
        self._title = _lbl("Device Details", size=13, color=G1, bold=True,
                           halign='center')
        top.add_widget(back)
        top.add_widget(self._title)
        root.add_widget(top)

        # ── scroll content ───────────────────────────────────────────
        sv = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self._inner = BoxLayout(orientation='vertical', size_hint_y=None,
                                spacing=dp(8), padding=[dp(10), dp(8)])
        self._inner.bind(minimum_height=self._inner.setter('height'))
        sv.add_widget(self._inner)
        root.add_widget(sv)

        # ── status bar at bottom ─────────────────────────────────────
        self._status = _lbl("", size=9, color=G2, halign='center')
        sb = BoxLayout(size_hint_y=None, height=dp(24), padding=[dp(6), dp(2)])
        sb.add_widget(self._status)
        root.add_widget(sb)

        self.add_widget(root)

    def _go_back(self):
        self.sm.transition.direction = 'right'
        self.sm.current = 'devices'

    def load(self, dev: dict):
        self._dev = dev
        self._inner.clear_widgets()
        mac  = dev['mac']
        ip   = dev.get('ip', 'Unknown')
        name = dev.get('name', mac)
        mfr  = dev.get('manufacturer', 'Unknown')
        os_  = dev.get('os', 'Unknown')
        sig  = dev.get('signal', '?')
        dtype = dev.get('dtype', 'other')
        blocked = self.db.is_blocked(mac)
        trusted = self.db.is_trusted(mac)
        ports   = dev.get('open_ports', [])
        svcs    = dev.get('services', [])
        logs    = dev.get('phone_log', [])

        sym, sym_col, type_lbl = _brand_sym(mfr, dtype)
        self._title.text = f"{sym}  {name}"

        # ── HEADER CARD: icon + name + status ─────────────────────
        hdr = BoxLayout(orientation='horizontal', size_hint_y=None,
                        height=dp(100), padding=[dp(14), dp(10)],
                        spacing=dp(12))
        _card(hdr, radius=dp(8))

        # left: big brand symbol
        sym_col2 = BoxLayout(orientation='vertical', size_hint_x=None,
                             width=dp(58))
        sym_col2.add_widget(_lbl(sym, size=22, color=sym_col,
                                 bold=True, halign='center'))
        sym_col2.add_widget(_lbl(type_lbl, size=8, color=sym_col,
                                 halign='center'))
        hdr.add_widget(sym_col2)

        # right: name block
        info_col = BoxLayout(orientation='vertical', spacing=dp(3))

        # online/offline badge
        ping_online = (self.ping_mon.is_online(ip)
                       if self.ping_mon else False)
        status_txt = "● ONLINE NOW" if ping_online else "○ OFFLINE"
        status_col = G1 if ping_online else G3
        s_row = BoxLayout(size_hint_y=None, height=dp(18))
        s_row.add_widget(_lbl(status_txt, size=9, color=status_col, bold=True))
        if trusted:
            s_row.add_widget(_lbl("[ TRUSTED ]", size=9, color=G1, bold=True,
                                  halign='right'))
        elif blocked:
            s_row.add_widget(_lbl("[ BLOCKED ]", size=9, color=RED, bold=True,
                                  halign='right'))
        info_col.add_widget(s_row)

        info_col.add_widget(_lbl(name, size=15, color=G1, bold=True))
        model_str = dev.get('model', '')
        detail_row2 = f"{mfr}  ·  {model_str}" if model_str else f"{mfr}  ·  {os_}"
        info_col.add_widget(_lbl(detail_row2, size=10, color=G2))
        if model_str:
            info_col.add_widget(_lbl(os_, size=9, color=G3))
        bars = _signal_bars(sig)
        bar_col = _signal_color(sig)
        info_col.add_widget(_lbl(f"{bars}  {sig} dBm", size=9, color=bar_col))
        hdr.add_widget(info_col)
        self._inner.add_widget(hdr)

        # ── SECTION HELPER ────────────────────────────────────────
        def _section(title, col=G1):
            hb = BoxLayout(size_hint_y=None, height=dp(28),
                           padding=[dp(4), dp(4), 0, 0])
            hb.add_widget(_lbl(title, size=10, color=col, bold=True))
            self._inner.add_widget(hb)

        def _info_row(label, value, val_col=G1):
            r = BoxLayout(orientation='horizontal', size_hint_y=None,
                          height=dp(32), padding=[dp(12), dp(2)])
            _card(r)
            r.add_widget(_lbl(label, size=10, color=G3))
            r.add_widget(_lbl(str(value), size=10, color=val_col,
                               bold=True, halign='right'))
            self._inner.add_widget(r)

        # ── NETWORK INFO ──────────────────────────────────────────
        _section("  NETWORK INFO")
        _info_row("IP Address",     ip)
        _info_row("MAC Address",    mac,  G2)
        _info_row("Manufacturer",   mfr,  G1)
        if dev.get('model'):
            _info_row("Model",      dev['model'],  G1)
        _info_row("OS / Platform",  os_,  G2)
        _info_row("Signal (RSSI)",  f"{sig} dBm  {_signal_bars(sig)}",
                  _signal_color(sig))
        _info_row("First Seen",     str(dev.get('first_seen',''))[:19], G3)
        _info_row("Last Seen",      str(dev.get('last_seen', ''))[:19], G2)
        if dev.get('hostname') and dev['hostname'] != name:
            _info_row("Hostname", dev['hostname'], G2)

        # ── OPEN PORTS ────────────────────────────────────────────
        if ports:
            _section("  OPEN PORTS", YEL)
            p_row = BoxLayout(size_hint_y=None, height=dp(36),
                              padding=[dp(12), dp(4)], spacing=dp(6))
            _card(p_row)
            for p in ports[:14]:
                pb = BoxLayout(size_hint_x=None, width=dp(40),
                               size_hint_y=None, height=dp(28))
                _card(pb, radius=dp(4))
                pb.add_widget(_lbl(str(p), size=9, color=YEL,
                                   bold=True, halign='center'))
                p_row.add_widget(pb)
            self._inner.add_widget(p_row)

        # ── SERVICES ──────────────────────────────────────────────
        if svcs:
            _section("  DETECTED SERVICES", CYN)
            s_row = BoxLayout(size_hint_y=None, height=dp(32),
                              padding=[dp(12), dp(4)])
            _card(s_row)
            s_row.add_widget(_lbl("  ".join(svcs[:10]), size=9, color=CYN))
            self._inner.add_widget(s_row)

        # ── ACTION GRID ───────────────────────────────────────────
        _section("  DEVICE MANAGEMENT")

        def _action_btn(label, sub, col, cb):
            """Rounded action button with label + subtitle."""
            b = Button(
                text=f"{label}\n{sub}",
                font_size=sp(9), color=col, bold=True,
                halign='center', valign='middle',
                background_color=(0,0,0,0), background_normal='',
                size_hint_y=None, height=dp(58))
            b.bind(size=b.setter('text_size'))
            with b.canvas.before:
                Color(col[0], col[1], col[2], 0.15)
                rb = RoundedRectangle(pos=b.pos, size=b.size, radius=[dp(10)])
                Color(col[0], col[1], col[2], 0.40)
                lb = Line(rounded_rectangle=(b.x, b.y, b.width, b.height, dp(10)),
                          width=dp(1))
                b.bind(
                    pos=lambda w, v, r=rb, l=lb: [
                        setattr(r, 'pos', v),
                        setattr(l, 'rounded_rectangle',
                                (v[0], v[1], w.width, w.height, dp(10)))],
                    size=lambda w, v, r=rb, l=lb: [
                        setattr(r, 'size', v),
                        setattr(l, 'rounded_rectangle',
                                (w.x, w.y, v[0], v[1], dp(10)))])
            b.bind(on_release=cb)
            return b

        act_defs = [
            ("BLOCK" if not blocked else "UNBLOCK",
             "حجب الجهاز" if not blocked else "رفع الحجب",
             RED if not blocked else YEL,
             lambda *_: self._kick(mac, ip)),
            ("PAUSE",
             "إيقاف مؤقت",
             (1.0, 0.5, 0.0, 1.0),
             lambda *_: self._throttle(ip, 256)),
            ("TRUST" if not trusted else "UNTRUST",
             "موثوق" if not trusted else "إلغاء الثقة",
             G1 if not trusted else G3,
             lambda *_: self._toggle_trust(mac)),
            ("PING",
             "فحص الاتصال",
             CYN,
             lambda *_: self._ping(ip)),
            ("PORT SCAN",
             "فحص المنافذ",
             YEL,
             lambda *_: self._rescan(ip, mac)),
            ("TRACEROUTE",
             "تتبع المسار",
             (0.80, 0.50, 1.00, 1.00),
             lambda *_: self._traceroute(ip)),
        ]

        # 3 per row
        for i in range(0, len(act_defs), 3):
            row = BoxLayout(size_hint_y=None, height=dp(58),
                            spacing=dp(6), padding=[dp(6), 0])
            for lbl_t, sub, col, cb in act_defs[i:i+3]:
                row.add_widget(_action_btn(lbl_t, sub, col, cb))
            self._inner.add_widget(row)

        # ── SPEED LIMIT ───────────────────────────────────────────
        _section("  SPEED LIMIT")
        spd_row = BoxLayout(size_hint_y=None, height=dp(44),
                            spacing=dp(5), padding=[dp(6), dp(4)])
        for lbl_t, kbps in [("256K","slow"), ("512K","med"),
                             ("1 MB","fair"), ("5 MB","fast"), ("FREE","off")]:
            b = _action_btn(lbl_t, kbps,
                            G1 if kbps != "off" else G3,
                            lambda *_, k=kbps, kb=kbps: None)
            kbps_val = {"slow":256,"med":512,"fair":1024,"fast":5120,"off":0}
            b.bind(on_release=lambda *_, k=lbl_t,
                   kv=kbps_val.get(kbps,0): self._throttle(ip, kv))
            b.height = dp(44)
            spd_row.add_widget(b)
        self._inner.add_widget(spd_row)

        # ── RECENT ACTIVITY ───────────────────────────────────────
        _section("  RECENT ACTIVITY", G2)
        if not logs:
            r = BoxLayout(size_hint_y=None, height=dp(30),
                          padding=[dp(12), dp(4)])
            _card(r)
            r.add_widget(_lbl("No traffic captured yet.", size=9, color=G3))
            self._inner.add_widget(r)
        else:
            for e in logs[:25]:
                t     = e.get('time', '')
                svc   = e.get('service', '?')
                host  = e.get('hostname', e.get('remote', ''))
                direc = ">>" if e.get('direction') == "OUT" else "<<"
                r = BoxLayout(orientation='horizontal', size_hint_y=None,
                              height=dp(22), padding=[dp(10), 0], spacing=dp(4))
                _card(r)
                r.add_widget(_lbl(f"{direc}", size=9, color=CYN,
                                  size_hint_x=None, width=dp(20), bold=True))
                r.add_widget(_lbl(svc, size=9, color=G1, bold=True,
                                  size_hint_x=None, width=dp(80)))
                r.add_widget(_lbl(host, size=8, color=G3))
                r.add_widget(_lbl(t[-5:], size=8, color=G3,
                                  size_hint_x=None, width=dp(36),
                                  halign='right'))
                self._inner.add_widget(r)

        self._inner.add_widget(Widget(size_hint_y=None, height=dp(24)))

    # ── Action helpers ───────────────────────────────────────────────
    def _kick(self, mac, ip):
        self.db.toggle_block(mac)
        blocked = self.db.is_blocked(mac)
        if blocked:
            msg = self.scanner.kick_device(ip)
        else:
            msg = self.scanner.unkick_device(ip)
        self._status.text = msg[:60]
        self.load(self.db.get(mac) or self._dev)

    def _toggle_trust(self, mac):
        if self.db.is_trusted(mac):
            self.db.untrust(mac)
        else:
            self.db.trust(mac)
        self._status.text = "Trust updated."
        self.load(self.db.get(mac) or self._dev)

    def _ping(self, ip):
        self._status.text = "Pinging…"
        def _do():
            ok = PingMonitor._ping_once(ip)
            Clock.schedule_once(
                lambda dt: setattr(self._status, 'text',
                                   f"{'ONLINE' if ok else 'OFFLINE'}: {ip}"), 0)
        threading.Thread(target=_do, daemon=True).start()

    def _rescan(self, ip, mac):
        self._status.text = "Port scanning…"
        def _do():
            self.scanner._port_scan(ip, mac)
            dev = self.db.get(mac)
            if dev:
                Clock.schedule_once(lambda dt, d=dev: self.load(d), 0)
        threading.Thread(target=_do, daemon=True).start()

    def _throttle(self, ip, kbps):
        msg = self.scanner.throttle_device(ip, kbps)
        self._status.text = msg[:60]

    def _traceroute(self, ip):
        self._status.text = f"Traceroute to {ip}…"
        def _do():
            import subprocess
            try:
                cmd = (["tracert", "-d", "-h", "15", ip]
                       if os.name == "nt"
                       else ["traceroute", "-n", "-m", "15", ip])
                res = subprocess.run(cmd, capture_output=True,
                                     text=True, timeout=20)
                lines = (res.stdout or res.stderr or "No output").strip()
                out   = "\n".join(lines.split("\n")[:18])
            except Exception as ex:
                out = str(ex)
            Clock.schedule_once(
                lambda dt: setattr(self._status, 'text',
                                   out.replace("\n", "  ")[:80]), 0)
        threading.Thread(target=_do, daemon=True).start()


class DevicesScreen(BaseScreen):
    def __init__(self, db, **kwargs):
        super().__init__(db, name='devices', **kwargs)

        # ── Status bar ────────────────────────────────────────────────
        self._stat = _lbl("Scanning for phones…", size=10, color=G2,
                          halign='center')
        stat_row = BoxLayout(size_hint_y=None, height=dp(26),
                             padding=[dp(8), dp(2)])
        stat_row.add_widget(self._stat)

        # ── Filter tabs: PHONES (default) | ALL | OTHER ──────────────
        tab_row = BoxLayout(size_hint_y=None, height=dp(36),
                            padding=[dp(6), dp(2)], spacing=dp(4))
        self._filter = "phone"   # Default = phones only
        for label, key in [("PHONES","phone"),("ALL","all"),("OTHER","other")]:
            btn = Button(text=label, font_size=sp(9), bold=(key == "phone"),
                         color=G1 if key == "phone" else G3,
                         background_color=(0, 0, 0, 0), background_normal='')
            btn.bind(on_release=lambda b, k=key: self._set_filter(k, tab_row))
            tab_row.add_widget(btn)

        self.root_box.add_widget(
            self._header("[ DEVICES ]", "All detected network devices"))
        self.root_box.add_widget(stat_row)
        self.root_box.add_widget(tab_row)

        sv = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self._box = BoxLayout(orientation='vertical', size_hint_y=None,
                              spacing=dp(6), padding=[dp(8), dp(8)])
        self._box.bind(minimum_height=self._box.setter('height'))
        sv.add_widget(self._box)
        self.root_box.add_widget(sv)

    def set_detail_screen(self, detail_screen):
        """Called from app.build() once detail screen is ready."""
        self._detail = detail_screen

    def on_pre_enter(self, *args):
        self.refresh()

    def _open_detail(self, dev):
        if hasattr(self, '_detail') and self._detail:
            self._detail.load(dev)
            self._detail.sm.transition.direction = 'left'
            self._detail.sm.current = 'device_detail'

    def _set_filter(self, key, tab_row):
        self._filter = key
        for btn in tab_row.children:
            if isinstance(btn, Button):
                active = (btn.text.lower() == key or
                          (key == "phone" and btn.text == "PHONES") or
                          (key == "all"   and btn.text == "ALL") or
                          (key == "other" and btn.text == "OTHER"))
                btn.bold  = active
                btn.color = G1 if active else G3
        self.refresh()

    def refresh(self):
        self._box.clear_widgets()
        all_devs = self.db.all()
        all_devs.sort(key=lambda d: d.get('last_seen', ''), reverse=True)

        # Apply filter
        filt = self._filter if hasattr(self, '_filter') else "phone"
        if filt == "phone":
            devs = [d for d in all_devs if _is_phone(d)]
        elif filt == "other":
            devs = [d for d in all_devs if not _is_phone(d)]
        else:
            devs = all_devs   # ALL

        phones   = [d for d in all_devs if _is_phone(d)]
        cameras  = [d for d in all_devs if _is_camera(d)]
        pcs      = [d for d in all_devs if _is_pc(d)]
        total    = len(all_devs)
        n_phone  = len(phones)

        # Update status bar
        scan_txt = (f"Phones: {n_phone}  |  Showing: {len(devs)}  "
                    f"(All devices: {total})")
        try:
            self._stat.text = scan_txt
            self._stat.color = G1 if n_phone > 0 else YEL
        except Exception:
            pass

        if not devs:
            self._box.add_widget(
                _lbl("No phones detected yet – scanning…\n"
                     "Make sure WiFi is on and Location permission is granted.",
                     size=11, color=G3, halign='center'))
            return

        for dev in devs:
            self._box.add_widget(
                DeviceRow(dev, self.db, self._block, on_trust=self._trust,
                          on_tap=self._open_detail))

    def _block(self, mac):
        self.db.toggle_block(mac)
        self.refresh()

    def _trust(self, mac):
        if self.db.is_trusted(mac):
            self.db.untrust(mac)
        else:
            self.db.trust(mac)
        self.refresh()


# ─── Traffic Screen ───────────────────────────────────────────────────────────
# ─── Log Screen ───────────────────────────────────────────────────────────────
class LogScreen(BaseScreen):
    """
    Per-phone traffic log.
    Shows what each phone is sending and receiving in real time.
    Note: WhatsApp / Instagram DMs are E2E encrypted –
          content cannot be read. Service name and metadata are shown.
    """

    def __init__(self, db, scanner_ref=None, **kwargs):
        super().__init__(db, name='log', **kwargs)
        self.scanner = scanner_ref
        self.root_box.add_widget(
            self._header("[ PHONE LOG ]",
                         "DNS lookups + TCP traffic per device"))

        # encryption notice
        enc_bar = BoxLayout(size_hint_y=None, height=dp(28),
                            padding=[dp(8), dp(2)])
        with enc_bar.canvas.before:
            Color(0.6, 0.3, 0.0, 0.4)
            rb = Rectangle(pos=enc_bar.pos, size=enc_bar.size)
            enc_bar.bind(pos=lambda w, v: setattr(rb, 'pos', v),
                         size=lambda w, v: setattr(rb, 'size', v))
        enc_bar.add_widget(_lbl(
            "WhatsApp / Instagram DMs: E2E encrypted – content CANNOT be decrypted by any tool",
            size=8, color=YEL, halign='center'))
        self.root_box.add_widget(enc_bar)

        sv = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self._box = BoxLayout(orientation='vertical', size_hint_y=None,
                              spacing=dp(6), padding=[dp(8), dp(6)])
        self._box.bind(minimum_height=self._box.setter('height'))
        sv.add_widget(self._box)
        self.root_box.add_widget(sv)
        Clock.schedule_interval(self._refresh, 3.0)

    def _refresh(self, *_):
        self._box.clear_widgets()
        all_devs = self.db.all()
        phones   = [d for d in all_devs if _is_phone(d)]
        dns_log  = self.db._d.get("dns_log", [])

        def _section_hdr(title, col=G1):
            hb = BoxLayout(size_hint_y=None, height=dp(30),
                           padding=[dp(8), dp(4)])
            with hb.canvas.before:
                Color(col[0], col[1], col[2], 0.08)
                rb = RoundedRectangle(pos=hb.pos, size=hb.size, radius=[dp(4)])
                hb.bind(pos=lambda w,v: setattr(rb,'pos',v),
                        size=lambda w,v: setattr(rb,'size',v))
            hb.add_widget(_lbl(title, size=10, color=col, bold=True))
            self._box.add_widget(hb)

        def _row(items, colors, widths):
            """Generic horizontal row."""
            r = BoxLayout(orientation='horizontal', size_hint_y=None,
                          height=dp(22), padding=[dp(8), 0], spacing=dp(4))
            for txt, col, w in zip(items, colors, widths):
                kw = {} if w is None else {'size_hint_x': None, 'width': dp(w)}
                r.add_widget(_lbl(txt, size=9, color=col, **kw))
            self._box.add_widget(r)

        # ═══════════════════════════════════════════════════════════
        # 1. DNS LOG — websites visited by every device
        # ═══════════════════════════════════════════════════════════
        _section_hdr("  DNS LOG — WEBSITES VISITED", CYN)

        if not dns_log:
            proxy_port = getattr(self.scanner, '_dns_proxy_port', None)
            if proxy_port:
                tip = (f"DNS proxy running on port {proxy_port}.\n"
                       "Set your router's DHCP DNS to this device's IP\n"
                       "to capture ALL websites from ALL devices.")
            else:
                tip = ("Waiting for DNS queries…\n"
                       "Tip: set this device as DNS server in router\n"
                       "to capture websites from all devices.")
            r = BoxLayout(orientation='vertical', size_hint_y=None,
                          height=dp(60), padding=[dp(12), dp(4)])
            _card(r)
            r.add_widget(_lbl(tip, size=9, color=G3))
            self._box.add_widget(r)
        else:
            # Group by source device, newest first
            seen_domains: dict = {}   # src_ip → [domains]
            for e in dns_log[:300]:
                src = e.get('src', '?')
                seen_domains.setdefault(src, [])
                d = e.get('domain', '')
                if d and d not in seen_domains[src]:
                    seen_domains[src].append(d)

            for src_ip, domains in seen_domains.items():
                dev = self.db._find_by_ip(src_ip)
                dev_name = (dev.get('name', src_ip) if dev else src_ip)
                mfr  = (dev.get('manufacturer','?') if dev else '?')
                sym, sym_col, _ = _brand_sym(mfr, dev.get('dtype','other') if dev else 'other')

                # device sub-header
                dh = BoxLayout(orientation='horizontal', size_hint_y=None,
                               height=dp(28), padding=[dp(8), dp(3)], spacing=dp(6))
                _card(dh)
                dh.add_widget(_lbl(sym, size=10, color=sym_col, bold=True,
                                   size_hint_x=None, width=dp(30)))
                dh.add_widget(_lbl(f"{dev_name}  [{mfr}]  {src_ip}",
                                   size=10, color=G1, bold=True))
                dh.add_widget(_lbl(f"{len(domains)} domains", size=9,
                                   color=G3, halign='right'))
                self._box.add_widget(dh)

                for domain in domains[:40]:
                    svc = _domain_to_service(domain)
                    r = BoxLayout(orientation='horizontal', size_hint_y=None,
                                  height=dp(20), padding=[dp(16), 0], spacing=dp(6))
                    r.add_widget(_lbl("→", size=9, color=CYN,
                                      size_hint_x=None, width=dp(14), bold=True))
                    r.add_widget(_lbl(svc, size=9, color=G1, bold=True,
                                      size_hint_x=None, width=dp(90)))
                    r.add_widget(_lbl(domain, size=8, color=G3))
                    self._box.add_widget(r)

        self._box.add_widget(Widget(size_hint_y=None, height=dp(6)))

        # ═══════════════════════════════════════════════════════════
        # 2. PER-PHONE DETAIL (sites + connections)
        # ═══════════════════════════════════════════════════════════
        _section_hdr("  PHONES — WEBSITES & CONNECTIONS", G1)

        if not phones:
            r = BoxLayout(size_hint_y=None, height=dp(30), padding=[dp(10), dp(2)])
            _card(r)
            r.add_widget(_lbl("No phones detected yet – scanning…",
                              size=9, color=G3))
            self._box.add_widget(r)
        else:
            for dev in sorted(phones,
                              key=lambda d: d.get('last_seen', ''), reverse=True):
                self._add_phone_section(dev)

        # ═══════════════════════════════════════════════════════════
        # 3. SYSTEM EVENTS
        # ═══════════════════════════════════════════════════════════
        self._box.add_widget(Widget(size_hint_y=None, height=dp(6)))
        sys_logs = self.db._d.get("log", [])[:30]
        if sys_logs:
            _section_hdr("  SYSTEM EVENTS", G2)
            for e in sys_logs:
                lvl = e.get('level', 'INFO')
                col = RED if lvl == "ALERT" else (YEL if lvl == "WARN" else G3)
                _row([f"[{e.get('time','')}]", e.get('msg','')],
                     [col, G2], [56, None])

        self._box.add_widget(Widget(size_hint_y=None, height=dp(20)))

    def _add_phone_section(self, dev):
        mac     = dev['mac']
        mfr     = dev.get('manufacturer', '?')
        os_     = dev.get('os', '?')
        ip      = dev.get('ip', '?')
        name    = dev.get('name', mac)
        visits  = dev.get('dns_visits', [])   # domain list from DNS
        logs    = dev.get('phone_log',  [])   # TCP traffic events
        sym, sym_col, _ = _brand_sym(mfr, dev.get('dtype','phone'))

        # ── phone header card ─────────────────────────────────────────
        hdr = BoxLayout(orientation='horizontal', size_hint_y=None,
                        height=dp(46), padding=[dp(8), dp(6)],
                        spacing=dp(8))
        _card(hdr)
        hdr.add_widget(_lbl(sym, size=14, color=sym_col, bold=True,
                            size_hint_x=None, width=dp(36)))
        info_col = BoxLayout(orientation='vertical')
        info_col.add_widget(_lbl(name, size=12, color=G1, bold=True))
        info_col.add_widget(_lbl(f"{mfr}  ·  {os_}  ·  {ip}",
                                 size=8, color=G3))
        hdr.add_widget(info_col)
        n_sites = len(visits)
        n_conn  = len(logs)
        hdr.add_widget(_lbl(f"{n_sites} sites\n{n_conn} conn",
                            size=8, color=CYN, halign='right',
                            size_hint_x=None, width=dp(52)))
        self._box.add_widget(hdr)

        # ── WEBSITES VISITED (DNS) — primary ─────────────────────────
        if visits:
            sites_row = BoxLayout(orientation='vertical',
                                  size_hint_y=None, padding=[dp(10), dp(4)],
                                  spacing=dp(1))
            sites_row.bind(minimum_height=sites_row.setter('height'))
            for domain in visits[:60]:
                svc = _domain_to_service(domain)
                r = BoxLayout(orientation='horizontal', size_hint_y=None,
                              height=dp(20), spacing=dp(6))
                r.add_widget(_lbl("→", size=9, color=CYN, bold=True,
                                  size_hint_x=None, width=dp(14)))
                r.add_widget(_lbl(svc, size=9, color=G1, bold=True,
                                  size_hint_x=None, width=dp(88)))
                r.add_widget(_lbl(domain, size=8, color=G3))
                sites_row.add_widget(r)
            self._box.add_widget(sites_row)
        else:
            r = BoxLayout(size_hint_y=None, height=dp(20),
                          padding=[dp(14), 0])
            r.add_widget(_lbl("No DNS activity captured yet…",
                              size=9, color=G3))
            self._box.add_widget(r)

        # ── TCP CONNECTIONS (compact) ─────────────────────────────────
        tcp_events = [e for e in logs if e.get('port', 0) != 53][:20]
        if tcp_events:
            sub = BoxLayout(size_hint_y=None, height=dp(18),
                            padding=[dp(10), 0])
            sub.add_widget(_lbl("TCP CONNECTIONS:", size=8,
                                color=G2, bold=True))
            self._box.add_widget(sub)
            for e in tcp_events:
                t     = e.get('time', '')
                svc   = e.get('service', '?')
                host  = e.get('hostname', e.get('remote', ''))
                direc = ">>" if e.get('direction') == "OUT" else "<<"
                r = BoxLayout(orientation='horizontal', size_hint_y=None,
                              height=dp(18), padding=[dp(14), 0], spacing=dp(4))
                r.add_widget(_lbl(t[-5:], size=7, color=G3,
                                  size_hint_x=None, width=dp(32)))
                r.add_widget(_lbl(direc, size=8, color=CYN, bold=True,
                                  size_hint_x=None, width=dp(16)))
                r.add_widget(_lbl(svc, size=8, color=G1, bold=True,
                                  size_hint_x=None, width=dp(80)))
                r.add_widget(_lbl(host, size=7, color=G3))
                self._box.add_widget(r)

        self._box.add_widget(Widget(size_hint_y=None, height=dp(10)))

    def push(self, events):
        """Called when new traffic arrives."""
        self._refresh()


# ─── Access Screen ────────────────────────────────────────────────────────────
class AccessScreen(BaseScreen):
    """
    Network Command Center:
      - Live network stats card (gateway, your IP, device count)
      - Per-phone cards with online/offline ping status
      - KICK (block) / UNBLOCK
      - Speed throttle presets
      - Quick Ping + Copy MAC/IP actions
      - Blocked devices list
    KICK/THROTTLE requires Admin (Windows) or Root (Android/Linux).
    """

    SPEED_PRESETS = [
        ("256K",  256),
        ("512K",  512),
        ("1 MB",  1024),
        ("5 MB",  5120),
        ("FREE",  0),
    ]

    def __init__(self, db, scanner_ref, ping_monitor=None, **kwargs):
        super().__init__(db, name='access', **kwargs)
        self.scanner  = scanner_ref
        self.ping_mon = ping_monitor   # PingMonitor reference
        self.root_box.add_widget(
            self._header("[ NETWORK COMMAND CENTER ]",
                         "Home network control – Kick / Speed limit / Monitor"))

        # ── status bar ───────────────────────────────────────────────
        self._status = _lbl("Ready", size=9, color=G2, halign='center')
        sb = BoxLayout(size_hint_y=None, height=dp(22), padding=[dp(8), dp(2)])
        _card(sb)
        sb.add_widget(self._status)
        self.root_box.add_widget(sb)

        sv = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self._inner = BoxLayout(orientation='vertical', size_hint_y=None,
                                spacing=dp(10), padding=[dp(10), dp(8)])
        self._inner.bind(minimum_height=self._inner.setter('height'))
        sv.add_widget(self._inner)
        self.root_box.add_widget(sv)

        self._throttled = {}   # ip → kbps
        self._ping_results = {}   # ip → "ONLINE"/"OFFLINE"/"..."

        # cache gateway + my IP (resolved once in bg)
        self._gw_ip = "..."
        self._my_ip = "..."
        threading.Thread(target=self._resolve_net_info, daemon=True).start()

        Clock.schedule_interval(self._refresh, 6.0)
        self._refresh()

    def _resolve_net_info(self):
        gw = Scanner.gateway_ip()
        my = Scanner.my_ip()
        def _update(dt):
            self._gw_ip = gw
            self._my_ip = my
            self._refresh()
        Clock.schedule_once(_update, 0)

    def _set_status(self, msg, col=YEL):
        self._status.text  = msg
        self._status.color = col

    def _sec(self, title, col=G1):
        b = BoxLayout(size_hint_y=None, height=dp(28), padding=[dp(4), 0])
        b.add_widget(_lbl(title, size=12, color=col, bold=True))
        return b

    # ── network stats card ───────────────────────────────────────────
    def _net_card(self):
        phones   = [d for d in self.db.all() if _is_phone(d)]
        active   = [d for d in self.db.active() if _is_phone(d)]
        blocked  = self.db.setting("blocked", [])
        online   = sum(1 for d in active
                       if self.ping_mon and self.ping_mon.is_online(d.get('ip','')))

        card = BoxLayout(orientation='vertical', size_hint_y=None,
                         height=dp(114), padding=[dp(12), dp(8)], spacing=dp(5))
        _card(card)

        # row 1: title
        card.add_widget(_lbl("NETWORK STATUS", size=12, color=G1, bold=True))

        # row 2: gateway + my ip
        row1 = BoxLayout(orientation='horizontal',
                         size_hint_y=None, height=dp(20), spacing=dp(10))
        row1.add_widget(_lbl(f"Gateway (Router):  {self._gw_ip}", size=10, color=G2))
        row1.add_widget(_lbl(f"Your IP:  {self._my_ip}", size=10, color=G2,
                             halign='right'))
        card.add_widget(row1)

        # row 3: counters
        row2 = BoxLayout(orientation='horizontal',
                         size_hint_y=None, height=dp(22), spacing=dp(6))
        stats = [
            (f"{len(phones)}",  "KNOWN",   G2),
            (f"{len(active)}",  "ACTIVE",  G1),
            (f"{online}",       "ONLINE",  CYN),
            (f"{len(blocked)}", "BLOCKED", RED if blocked else G3),
        ]
        for val, lbl_txt, col in stats:
            cell = BoxLayout(orientation='vertical')
            cell.add_widget(_lbl(val,     size=14, color=col,  bold=True, halign='center'))
            cell.add_widget(_lbl(lbl_txt, size=7,  color=G3,              halign='center'))
            row2.add_widget(cell)
        card.add_widget(row2)

        # row 4: router admin link hint
        if self._gw_ip not in ("...", "Unknown"):
            card.add_widget(_lbl(
                f"Router admin panel:  http://{self._gw_ip}  (open in browser)",
                size=8, color=YEL, halign='center'))
        return card

    def _refresh(self, *_):
        self._inner.clear_widgets()
        blocked = self.db.setting("blocked", [])
        phones  = [d for d in self.db.active() if _is_phone(d)]

        # ── Network stats ─────────────────────────────────────────────
        self._inner.add_widget(self._sec("NETWORK OVERVIEW", G1))
        self._inner.add_widget(self._net_card())

        # ── Active phones ─────────────────────────────────────────────
        self._inner.add_widget(
            self._sec(f"ACTIVE PHONES  ({len(phones)})", G1))

        if not phones:
            self._inner.add_widget(
                _lbl("No phones detected – scanning…", size=10, color=G3,
                     halign='center'))
        else:
            for dev in phones:
                self._add_phone_card(dev, blocked)

        # ── Blocked list ──────────────────────────────────────────────
        self._inner.add_widget(self._sec(f"BLOCKED  ({len(blocked)})", RED))
        if blocked:
            for mac in blocked:
                d    = self.db.get(mac)
                name = d.get('name', mac) if d else mac
                ip   = d.get('ip', '?')  if d else '?'
                row  = BoxLayout(orientation='horizontal',
                                 size_hint_y=None, height=dp(36),
                                 padding=[dp(8), dp(4)], spacing=dp(8))
                _card(row)
                row.add_widget(_lbl(
                    f"[X] {name}   MAC: {mac}   IP: {ip}",
                    size=10, color=RED))
                ub = Button(text="[UNBLOCK]", font_size=sp(10), color=YEL,
                            background_color=(0,0,0,0), background_normal='',
                            size_hint_x=None, width=dp(80), bold=True)
                ub.bind(on_release=lambda *_, m=mac, i=ip: self._do_unkick(m, i))
                row.add_widget(ub)
                self._inner.add_widget(row)
        else:
            self._inner.add_widget(
                _lbl("No blocked devices", size=10, color=G3, halign='center'))

        # ── Footer note ───────────────────────────────────────────────
        note = BoxLayout(size_hint_y=None, height=dp(40), padding=[dp(8), dp(4)])
        note.add_widget(_lbl(
            "KICK requires Admin rights (Windows) or Root (Android/Linux).\n"
            "Speed LIMIT requires Root on Android/Linux.",
            size=8, color=G3, halign='center'))
        self._inner.add_widget(note)
        self._inner.add_widget(Widget(size_hint_y=None, height=dp(16)))

    def _add_phone_card(self, dev, blocked):
        mac          = dev['mac']
        ip           = dev.get('ip', '?')
        mfr          = dev.get('manufacturer', '?')
        os_          = dev.get('os', '?')
        name         = dev.get('name', mac)
        blk          = mac in blocked
        ports        = dev.get('open_ports', [])
        svcs         = dev.get('services', [])
        sig          = dev.get('signal', '?')
        cur_throttle = self._throttled.get(ip, 0)
        is_intruder  = self.db.is_intruder(mac)
        is_trusted   = self.db.is_trusted(mac)
        ping_status  = self._ping_results.get(ip, "")
        if self.ping_mon:
            ping_online = self.ping_mon.is_online(ip)
            ping_status = "ONLINE" if ping_online else "OFFLINE"

        # card container
        card = BoxLayout(orientation='vertical', size_hint_y=None,
                         spacing=dp(4), padding=[dp(10), dp(8)])
        _card(card)

        # ── row 1: identity + status ──────────────────────────────────
        h = BoxLayout(orientation='horizontal',
                      size_hint_y=None, height=dp(30), spacing=dp(6))
        sym     = "[A]" if mfr == "Apple" else "[D]"
        tag     = (" [INTRUDER]" if is_intruder
                   else (" [TRUSTED]" if is_trusted
                         else (" [BLOCKED]" if blk else "")))
        name_col = RED if (blk or is_intruder) else (WHT if is_trusted else G1)
        h.add_widget(_lbl(f"{sym}  {name}{tag}", size=13,
                           color=name_col, bold=True))
        # online badge
        badge_col = CYN if ping_status == "ONLINE" else (RED if ping_status == "OFFLINE" else G3)
        h.add_widget(_lbl(f"[{ping_status or '...'}]",
                           size=10, color=badge_col, bold=True,
                           halign='right', size_hint_x=None, width=dp(70)))
        card.add_widget(h)

        # ── row 2: details ────────────────────────────────────────────
        card.add_widget(_lbl(
            f"{mfr}  |  {os_}  |  IP: {ip}  |  MAC: {mac}  |  RSSI: {sig} dBm",
            size=8, color=G2))

        # ── row 3: ports + services ───────────────────────────────────
        if ports:
            card.add_widget(_lbl(f"Open ports:  {', '.join(ports)}",
                                  size=8, color=YEL))
        if svcs:
            card.add_widget(_lbl(f"Services:  {', '.join(svcs[:8])}",
                                  size=8, color=CYN))

        # ── row 4: speed throttle status ─────────────────────────────
        if cur_throttle > 0:
            card.add_widget(_lbl(f"Speed limited to  {cur_throttle} Kbps",
                                  size=8, color=YEL))

        # ── row 5: action buttons ─────────────────────────────────────
        btn_row = BoxLayout(orientation='horizontal',
                            size_hint_y=None, height=dp(32),
                            spacing=dp(4), padding=[0, dp(2)])

        # KICK / UNBLOCK
        kick_btn = Button(
            text="[UNBLOCK]" if blk else "[KICK]",
            font_size=sp(10),
            color=YEL if blk else RED,
            background_color=(0,0,0,0), background_normal='',
            size_hint_x=None, width=dp(70), bold=True,
        )
        if blk:
            kick_btn.bind(on_release=lambda *_, m=mac, i=ip: self._do_unkick(m, i))
        else:
            kick_btn.bind(on_release=lambda *_, m=mac, i=ip: self._do_kick(m, i))
        btn_row.add_widget(kick_btn)

        # speed presets
        for lbl_text, kbps in self.SPEED_PRESETS:
            active = ((cur_throttle == kbps and kbps > 0) or
                      (kbps == 0 and cur_throttle == 0))
            b = Button(
                text=lbl_text, font_size=sp(9),
                color=G1 if active else G3, bold=active,
                background_color=(0,0,0,0), background_normal='',
            )
            b.bind(on_release=lambda *_, k=kbps, i=ip: self._do_throttle(i, k))
            btn_row.add_widget(b)

        card.add_widget(btn_row)

        # ── row 6: utility buttons ────────────────────────────────────
        util_row = BoxLayout(orientation='horizontal',
                             size_hint_y=None, height=dp(28),
                             spacing=dp(4))

        # Ping now
        ping_btn = Button(
            text="[PING]", font_size=sp(9), color=CYN,
            background_color=(0,0,0,0), background_normal='',
            size_hint_x=None, width=dp(58), bold=True,
        )
        ping_btn.bind(on_release=lambda *_, i=ip: self._do_ping(i))
        util_row.add_widget(ping_btn)

        # Copy IP
        copy_ip = Button(
            text=f"IP: {ip}", font_size=sp(9), color=G2,
            background_color=(0,0,0,0), background_normal='',
        )
        copy_ip.bind(on_release=lambda *_, v=ip: self._copy(v, "IP"))
        util_row.add_widget(copy_ip)

        # Copy MAC
        copy_mac = Button(
            text=f"MAC: {mac}", font_size=sp(9), color=G3,
            background_color=(0,0,0,0), background_normal='',
        )
        copy_mac.bind(on_release=lambda *_, v=mac: self._copy(v, "MAC"))
        util_row.add_widget(copy_mac)

        card.add_widget(util_row)

        card.height = sum(
            getattr(c, 'height', 0) for c in card.children
        ) + dp(24)
        self._inner.add_widget(card)

    # ── actions ──────────────────────────────────────────────────────────
    def _do_kick(self, mac, ip):
        self.db.toggle_block(mac)
        self.db.log("WARN", f"KICK issued: {ip}  MAC:{mac}")
        self._set_status(f"Kicking {ip}…", YEL)

        def run():
            msg = self.scanner.kick_device(ip)
            Clock.schedule_once(
                lambda dt: self._set_status(msg,
                                            G1 if "BLOCKED" in msg else YEL), 0)

        threading.Thread(target=run, daemon=True).start()
        self._refresh()

    def _do_unkick(self, mac, ip):
        self.db.toggle_block(mac)
        self.db.log("INFO", f"UNBLOCK: {ip}  MAC:{mac}")
        self._set_status(f"Unblocking {ip}…", G2)

        def run():
            msg = self.scanner.unkick_device(ip)
            Clock.schedule_once(lambda dt: self._set_status(msg, G1), 0)

        threading.Thread(target=run, daemon=True).start()
        self._refresh()

    def _do_ping(self, ip):
        self._ping_results[ip] = "..."
        self._set_status(f"Pinging {ip}…", G2)

        def run():
            online = PingMonitor._ping_once(ip)
            result = "ONLINE" if online else "OFFLINE"
            self._ping_results[ip] = result
            col = CYN if online else RED
            Clock.schedule_once(
                lambda dt: (self._set_status(f"{ip}  →  {result}", col),
                            self._refresh()), 0)

        threading.Thread(target=run, daemon=True).start()

    def _copy(self, value, label):
        try:
            from kivy.core.clipboard import Clipboard
            Clipboard.copy(value)
            self._set_status(f"{label} copied: {value}", G1)
        except Exception:
            self._set_status(f"{label}: {value}", G2)

    def _do_throttle(self, ip, kbps):
        self._throttled[ip] = kbps
        label = f"{kbps} Kbps" if kbps > 0 else "FREE"
        self.db.log("INFO", f"Throttle {ip} → {label}")

        def run(*_):
            msg = self.scanner.throttle_device(ip, kbps)
            Clock.schedule_once(
                lambda dt: self._set_status(msg,
                                            G1 if "LIMITED" in msg or
                                            "REMOVED" in msg else YEL), 0)

        threading.Thread(target=run, daemon=True).start()
        self._refresh()


# ─── Settings Screen ─────────────────────────────────────────────────────────
class SettingsScreen(BaseScreen):
    def __init__(self, db, **kwargs):
        super().__init__(db, name='settings', **kwargs)
        self.root_box.add_widget(
            self._header("[ SETTINGS ]", "Network / Scan / Privacy / Speed Test"))
        self._speed = SpeedTest()

        # ── Persistent network info bar – 2 rows, always visible ─────────
        self._net_bar = BoxLayout(
            orientation='vertical', size_hint_y=None, height=dp(68),
            padding=[dp(10), dp(4)], spacing=dp(3)
        )
        with self._net_bar.canvas.before:
            Color(0.0, 0.18, 0.0, 1.0)
            _nb_bg = Rectangle(pos=self._net_bar.pos, size=self._net_bar.size)
            # border line at bottom
            Color(*G1, 0.35)
            _nb_ln = Line(points=[0, 0, 1, 0], width=dp(0.7))
            def _upd_nb(w, v, bg=_nb_bg, ln=_nb_ln):
                bg.pos  = v if isinstance(v, (list, tuple)) and len(v) == 2 else w.pos
                bg.size = w.size
                ln.points = [w.x, w.y, w.x + w.width, w.y]
            self._net_bar.bind(pos=_upd_nb, size=_upd_nb)

        # Row 1: SSID | ISP
        _row1 = BoxLayout(orientation='horizontal', size_hint_y=None, height=dp(28))
        self._lbl_ssid = _lbl("SSID: ...", size=11, color=G1, bold=True)
        self._lbl_isp  = _lbl("ISP: ...",  size=11, color=CYN, halign='right')
        _row1.add_widget(self._lbl_ssid)
        _row1.add_widget(self._lbl_isp)

        # Row 2: IP | Password
        _row2 = BoxLayout(orientation='horizontal', size_hint_y=None, height=dp(24))
        self._lbl_ip   = _lbl("IP: ...",       size=10, color=G2)
        self._lbl_pw   = _lbl("Pass: ...",     size=10, color=YEL, halign='right')
        _row2.add_widget(self._lbl_ip)
        _row2.add_widget(self._lbl_pw)

        self._net_bar.add_widget(_row1)
        self._net_bar.add_widget(_row2)
        self.root_box.add_widget(self._net_bar)

        sv = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self._inner = BoxLayout(orientation='vertical', size_hint_y=None,
                                spacing=dp(10), padding=[dp(12), dp(10)])
        self._inner.bind(minimum_height=self._inner.setter('height'))
        sv.add_widget(self._inner)
        self.root_box.add_widget(sv)
        self._build()

    def on_pre_enter(self, *args):
        """Reload network info bar every time settings screen is opened."""
        threading.Thread(target=self._load_net_info, daemon=True).start()

    # ── helpers ───────────────────────────────────────────────────────
    def _section(self, title):
        row = BoxLayout(size_hint_y=None, height=dp(28), padding=[dp(4), 0])
        row.add_widget(_lbl(title, size=12, color=G1, bold=True))
        return row

    def _toggle_row(self, label, setting_key):
        val = self.db.setting(setting_key, True)
        row = BoxLayout(orientation='horizontal', size_hint_y=None,
                        height=dp(42), padding=[dp(10), dp(4)])
        _card(row)
        row.add_widget(_lbl(label, size=11, color=G2))
        btn_lbl = "[ON]" if val else "[OFF]"
        btn = Button(text=btn_lbl, font_size=sp(11),
                     color=G1 if val else RED,
                     background_color=(0,0,0,0),
                     background_normal='',
                     size_hint_x=None, width=dp(56), bold=True)
        def _toggle(b, key=setting_key, btn_ref=btn):
            cur = self.db.setting(key, True)
            new = not cur
            self.db.set_setting(key, new)
            btn_ref.text  = "[ON]"  if new else "[OFF]"
            btn_ref.color = G1 if new else RED
        btn.bind(on_release=_toggle)
        row.add_widget(btn)
        return row

    def _interval_row(self):
        row = BoxLayout(orientation='horizontal', size_hint_y=None,
                        height=dp(42), padding=[dp(10), dp(4)], spacing=dp(6))
        _card(row)
        row.add_widget(_lbl("SCAN INTERVAL", size=11, color=G2))
        for sec in (5, 10, 15, 30, 60):
            cur = self.db.setting("scan_interval", 15)
            b = Button(
                text=f"{sec}s", font_size=sp(10),
                color=G1 if cur == sec else G3, bold=(cur == sec),
                background_color=(0,0,0,0), background_normal='',
            )
            def _set(btn, s=sec, btns_row=row):
                self.db.set_setting("scan_interval", s)
                for child in btns_row.children:
                    if isinstance(child, Button):
                        child.color = G1 if child.text == f"{s}s" else G3
                        child.bold  = (child.text == f"{s}s")
            b.bind(on_release=_set)
            row.add_widget(b)
        return row

    # ── build all sections ────────────────────────────────────────────
    def _build(self):
        inner = self._inner

        # ── MIUI / Redmi / Xiaomi battery optimization notice ──────────
        if ANDROID:
            note_row = BoxLayout(size_hint_y=None, height=dp(52),
                                 padding=[dp(10), dp(4)])
            with note_row.canvas.before:
                Color(0.5, 0.3, 0.0, 0.45)
                nb = Rectangle(pos=note_row.pos, size=note_row.size)
                note_row.bind(pos=lambda w, v: setattr(nb, 'pos', v),
                              size=lambda w, v: setattr(nb, 'size', v))
            note_row.add_widget(_lbl(
                "MIUI / Redmi: Go to  Settings > Battery > App Battery Saver\n"
                "and set Nexus Vision to  'No restrictions'  for best performance.",
                size=8, color=YEL, halign='center'))
            inner.add_widget(note_row)

        # ── Scan settings ─────────────────────────────────────────────
        inner.add_widget(self._section("SCAN SETTINGS"))
        inner.add_widget(self._interval_row())
        inner.add_widget(self._toggle_row("Service Analysis (DNS lookup)",
                                          "service_analysis"))
        inner.add_widget(self._toggle_row("Alert: New Device",
                                          "alert_new_device"))
        inner.add_widget(self._toggle_row("Alert: Unknown Activity",
                                          "alert_unknown"))

        # ── Intruder Detection ────────────────────────────────────────
        inner.add_widget(self._section("INTRUDER DETECTION"))
        inner.add_widget(self._toggle_row(
            "Whitelist Mode (alert non-trusted phones)",
            "whitelist_active"))
        # trusted devices summary
        self._wl_summary = _lbl("", size=9, color=G3, halign='center')
        self._refresh_wl_summary()
        wl_row = BoxLayout(size_hint_y=None, height=dp(38),
                           padding=[dp(10), dp(4)])
        _card(wl_row)
        wl_row.add_widget(self._wl_summary)
        clr_wl = Button(text="[CLEAR LIST]", font_size=sp(9), color=YEL,
                        background_color=(0,0,0,0), background_normal='',
                        size_hint_x=None, width=dp(88), bold=True)
        clr_wl.bind(on_release=lambda *_: self._clear_whitelist())
        wl_row.add_widget(clr_wl)
        inner.add_widget(wl_row)

        # ── Privacy settings ──────────────────────────────────────────
        inner.add_widget(self._section("PRIVACY"))
        inner.add_widget(self._toggle_row("Save Event Log", "save_log"))
        inner.add_widget(self._toggle_row("Save Traffic Log", "save_traffic"))

        clear_row = BoxLayout(orientation='horizontal', size_hint_y=None,
                              height=dp(42), padding=[dp(10), dp(4)])
        _card(clear_row)
        clear_row.add_widget(_lbl("Clear All Data & Database", size=11, color=G2))
        cb = Button(text="[CLEAR]", font_size=sp(11), color=RED,
                    background_color=(0,0,0,0), background_normal='',
                    size_hint_x=None, width=dp(70), bold=True)
        cb.bind(on_release=lambda *_: self._clear())
        clear_row.add_widget(cb)
        inner.add_widget(clear_row)

        # ── Speed Test ────────────────────────────────────────────────
        inner.add_widget(self._section("INTERNET SPEED TEST"))
        self._build_speedtest(inner)

        # ── My Network ────────────────────────────────────────────────
        inner.add_widget(self._section("MY NETWORK"))
        self._net_rows = {}   # key → label widget (for async update)
        # ALL values loaded in background to avoid blocking main thread
        net_keys = [
            ("SSID",             "Loading…", G1),
            ("Password",         "Loading…", YEL),
            ("Your IP",          "Loading…", CYN),
            ("Gateway (Router)", "Loading…", CYN),
            ("ISP",              "Loading…", G2),
        ]
        for key, val, col in net_keys:
            r = BoxLayout(orientation='horizontal', size_hint_y=None,
                          height=dp(38), padding=[dp(10), dp(4)], spacing=dp(6))
            _card(r)
            key_lbl = _lbl(key, size=10, color=G2)
            key_lbl.size_hint_x = None
            key_lbl.width = dp(130)
            r.add_widget(key_lbl)
            lbl_val = _lbl(val, size=10, color=col, bold=True, halign='right')
            r.add_widget(lbl_val)
            self._net_rows[key] = lbl_val
            inner.add_widget(r)

        # ── Feature Status (root / permission required) ────────────────
        inner.add_widget(self._section("FEATURE STATUS"))
        feat_items = [
            ("Device Detection (ARP)",    True,  "No root needed"),
            ("Network Traffic Analysis",  True,  "OWN device only"),
            ("WiFi SSID / IP Info",       True,  "Location perm needed"),
            ("WiFi Password (Android)",   False, "Root required"),
            ("Block Device (Kick)",       False, "Root required"),
            ("Speed Throttle",            False, "Root required"),
            ("Bluetooth Scan",            True,  "BLUETOOTH perm needed"),
        ]
        for feat, available, note in feat_items:
            row = BoxLayout(orientation='horizontal', size_hint_y=None,
                            height=dp(36), padding=[dp(10), dp(2)])
            _card(row)
            icon_col = G1 if available else RED
            icon_txt = "[OK]" if available else "[!!]"
            icon_lbl = _lbl(icon_txt, size=10, color=icon_col, bold=True)
            icon_lbl.size_hint_x = None
            icon_lbl.width = dp(40)
            feat_lbl = _lbl(feat, size=9, color=WHT)
            feat_lbl.size_hint_x = 0.55
            note_lbl = _lbl(note, size=8, color=G3, halign='right')
            row.add_widget(icon_lbl)
            row.add_widget(feat_lbl)
            row.add_widget(note_lbl)
            inner.add_widget(row)

        # async load ALL network values in background
        threading.Thread(target=self._load_net_info, daemon=True).start()

        # ── App info ──────────────────────────────────────────────────
        inner.add_widget(self._section("APP INFO"))
        for key, val in [
            ("Version",  "1.0.0"),
            ("Platform", kivy_platform.upper()),
            ("Database", str(self.db.path)),
            ("Known Phones", str(len([d for d in self.db.all() if _is_phone(d)]))),
            ("Log entries",  str(len(self.db._d["log"]))),
        ]:
            r = BoxLayout(orientation='horizontal', size_hint_y=None,
                          height=dp(38), padding=[dp(10), dp(4)])
            _card(r)
            r.add_widget(_lbl(key, size=10, color=G2))
            r.add_widget(_lbl(val, size=10, color=G1,
                              bold=True, halign='right'))
            inner.add_widget(r)

        inner.add_widget(Widget(size_hint_y=None, height=dp(20)))

    def _load_net_info(self):
        """Runs in background thread, updates ALL MY NETWORK labels."""
        try:
            ssid = Scanner.wifi_ssid()
        except Exception:
            ssid = "Unknown"
        try:
            pw = Scanner.wifi_password(ssid)
        except Exception:
            pw = "Root required"
        try:
            isp = Scanner.isp_info()
        except Exception:
            isp = "Unknown"
        try:
            my_ip = Scanner.my_ip()
        except Exception:
            my_ip = "Unknown"
        try:
            gw = Scanner.gateway_ip()
        except Exception:
            gw = "Unknown"

        def _update(dt):
            try:
                if "SSID" in self._net_rows:
                    self._net_rows["SSID"].text = ssid or "Unknown"
                if "Password" in self._net_rows:
                    self._net_rows["Password"].text = pw or "Root required"
                if "Your IP" in self._net_rows:
                    self._net_rows["Your IP"].text = my_ip
                if "Gateway (Router)" in self._net_rows:
                    self._net_rows["Gateway (Router)"].text = gw
                if "ISP" in self._net_rows:
                    self._net_rows["ISP"].text = isp or "Unknown"
                # Update persistent top bar
                self._lbl_ssid.text = f"  SSID: {ssid or 'Unknown'}"
                self._lbl_isp.text  = f"ISP: {isp or 'Unknown'}"
                self._lbl_ip.text   = f"  IP: {my_ip}   GW: {gw}"
                # Password: show clearly or explain why not available
                pw_show = pw if pw and pw not in ("Root required", "", "Unknown") \
                          else ("Root required" if ANDROID else "Not found")
                self._lbl_pw.text  = f"Pass: {pw_show}"
                self._lbl_pw.color = YEL if pw_show.startswith("Root") \
                                     else (G1 if pw_show != "Not found" else RED)
            except Exception:
                pass

        Clock.schedule_once(_update, 0)

    def _refresh_wl_summary(self):
        wl = self.db._d["settings"].get("whitelist", [])
        mode = "ACTIVE" if self.db.setting("whitelist_active") else "INACTIVE"
        self._wl_summary.text = (
            f"Whitelist mode: {mode}  |  Trusted devices: {len(wl)}"
        )

    def _clear_whitelist(self):
        self.db._d["settings"]["whitelist"] = []
        self.db.save()
        self._refresh_wl_summary()

    def _build_speedtest(self, parent):
        # result labels
        result_box = BoxLayout(orientation='vertical', size_hint_y=None,
                               height=dp(110), padding=[dp(10), dp(6)],
                               spacing=dp(4))
        _card(result_box)

        self._st_ping = _lbl("Ping     :  --  ms",  size=12, color=G2)
        self._st_dl   = _lbl("Download :  --  Mbps",size=12, color=G2)
        self._st_ul   = _lbl("Upload   :  --  Mbps",size=12, color=G2)
        self._st_stat = _lbl("",                    size=9,  color=G3,
                              halign='center')

        result_box.add_widget(self._st_ping)
        result_box.add_widget(self._st_dl)
        result_box.add_widget(self._st_ul)
        result_box.add_widget(self._st_stat)
        parent.add_widget(result_box)

        run_row = BoxLayout(size_hint_y=None, height=dp(44),
                            padding=[dp(10), dp(4)])
        self._st_btn = Button(
            text="[ RUN SPEED TEST ]",
            font_size=sp(12), color=G1, bold=True,
            background_color=(0,0,0,0), background_normal='',
        )
        self._st_btn.bind(on_release=lambda *_: self._run_speed_test())
        run_row.add_widget(self._st_btn)
        parent.add_widget(run_row)

    def _run_speed_test(self):
        self._st_btn.text  = "[ TESTING... ]"
        self._st_btn.color = YEL
        self._st_ping.text = "Ping     :  measuring..."
        self._st_dl.text   = "Download :  measuring..."
        self._st_ul.text   = "Upload   :  measuring..."
        self._st_stat.text = ""
        self._speed.run(
            on_ping     = self._on_ping,
            on_download = self._on_dl,
            on_upload   = self._on_ul,
            on_done     = self._on_done,
        )

    def _on_ping(self, ms):
        if ms < 0:
            self._st_ping.text  = "Ping     :  timeout"
            self._st_ping.color = RED
        else:
            col = G1 if ms < 50 else (YEL if ms < 120 else RED)
            self._st_ping.text  = f"Ping     :  {ms} ms"
            self._st_ping.color = col

    def _on_dl(self, mbps):
        col = G1 if mbps > 5 else (YEL if mbps > 1 else RED)
        self._st_dl.text  = f"Download :  {mbps} Mbps"
        self._st_dl.color = col

    def _on_ul(self, mbps):
        col = G1 if mbps > 2 else (YEL if mbps > 0.5 else RED)
        self._st_ul.text  = f"Upload   :  {mbps} Mbps"
        self._st_ul.color = col

    def _on_done(self):
        self._st_btn.text  = "[ RUN SPEED TEST ]"
        self._st_btn.color = G1
        self._st_stat.text = f"Test completed  {datetime.now().strftime('%H:%M:%S')}"

    def _clear(self):
        self.db.clear_all()
        self._st_stat.text = "Database cleared."


# ─── NavBar ───────────────────────────────────────────────────────────────────
class NavBar(BoxLayout):
    TABS = [
        ('radar',   'RADAR'),
        ('devices', 'PHONES'),
        ('log',     'LOG'),
        ('access',  'ACCESS'),
        ('settings','SETTINGS'),
    ]

    def __init__(self, sm: ScreenManager, **kwargs):
        super().__init__(orientation='horizontal',
                         size_hint_y=None, height=dp(50), **kwargs)
        self.sm = sm
        with self.canvas.before:
            Color(*G4)
            rb = Rectangle(pos=self.pos, size=self.size)
            Color(*G3)
            tl = Line(points=[0]*4, width=dp(0.7))
            self.bind(
                pos =lambda w, v: (
                    setattr(rb, 'pos', v),
                    setattr(tl, 'points',
                            [v[0], v[1]+self.height,
                             v[0]+self.width, v[1]+self.height])),
                size=lambda w, v: (
                    setattr(rb, 'size', v),
                    setattr(tl, 'points',
                            [self.x, self.y+v[1],
                             self.x+v[0], self.y+v[1]])),
            )
        self._btns = {}
        for name, label in self.TABS:
            btn = Button(
                text=label, font_size=sp(10),
                color=G2, bold=False,
                background_color=(0, 0, 0, 0),
                background_normal='',
            )
            btn.bind(on_release=lambda b, n=name: self._go(n))
            self._btns[name] = btn
            self.add_widget(btn)
        self._go('radar')

    def _go(self, name):
        self.sm.current = name
        for n, btn in self._btns.items():
            btn.color = G1  if n == name else G2
            btn.bold  = (n == name)


# ─── App ─────────────────────────────────────────────────────────────────────
def _request_android_permissions():
    """
    Request runtime permissions on Android 6+.
    Called once at startup.  Silent on all other platforms.
    """
    if not ANDROID:
        return
    try:
        from android.permissions import request_permissions, Permission  # type: ignore
        request_permissions([
            Permission.ACCESS_FINE_LOCATION,
            Permission.ACCESS_COARSE_LOCATION,
            Permission.ACCESS_WIFI_STATE,
            Permission.CHANGE_WIFI_STATE,
            Permission.ACCESS_NETWORK_STATE,
            Permission.BLUETOOTH,
            Permission.BLUETOOTH_ADMIN,
            Permission.VIBRATE,
            Permission.READ_PHONE_STATE,
        ])
    except Exception:
        pass


class NexusVisionApp(App):
    def build(self):
        Window.clearcolor = BG

        # Request runtime permissions FIRST on Android
        _request_android_permissions()

        self.db    = Database()
        self.alert = AlertSystem()
        self.db.log("INFO", "Nexus Vision started – real scan initiated")

        # scanner + ping monitor
        self.scanner  = Scanner(self.db, self._on_device, self._on_traffic,
                                alert=self.alert)
        self.ping_mon = PingMonitor(self.db, on_update=self._on_ping_update)

        self.sm  = ScreenManager(transition=FadeTransition(duration=0.12))
        self.rdr = RadarScreen(self.db)
        self.dev = DevicesScreen(self.db)
        self.lg  = LogScreen(self.db, scanner_ref=self.scanner)
        self.acc = AccessScreen(self.db, self.scanner,
                                ping_monitor=self.ping_mon)
        self.cfg = SettingsScreen(self.db)
        self.detail = DeviceDetailScreen(self.db, self.scanner,
                                         self.ping_mon, self.sm)

        for s in [self.rdr, self.dev, self.lg, self.acc, self.cfg, self.detail]:
            self.sm.add_widget(s)

        # Link detail screen to devices screen
        self.dev.set_detail_screen(self.detail)

        root = BoxLayout(orientation='vertical', spacing=0, padding=0)
        root.add_widget(self.sm)
        root.add_widget(NavBar(self.sm))

        self.scanner.start()
        self.ping_mon.start()
        return root

    def _on_device(self, dev):
        self.rdr.on_device(dev)
        self.dev.refresh()

    def _on_traffic(self, events):
        self.lg.push(events)
        self.dev.refresh()

    def _on_ping_update(self):
        """Called by PingMonitor after each ping cycle – refresh Access screen."""
        if hasattr(self, 'acc'):
            self.acc._refresh()

    def on_stop(self):
        self.scanner.stop()
        self.ping_mon.stop()
        self.db.save()


if __name__ == '__main__':
    NexusVisionApp().run()
