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


def _oui(mac: str) -> str:
    return _OUI.get(mac.upper()[:8], "Unknown")


def _guess_os(mfr: str) -> str:
    if mfr == "Apple":
        return "iOS/macOS"
    if mfr in {"Samsung", "Google", "Huawei", "Xiaomi", "OnePlus", "OPPO",
               "Realme", "LG", "Sony", "Motorola", "Nokia"}:
        return "Android"
    if mfr in {"Cisco", "Netgear", "TP-Link", "DLink", "Tenda"}:
        return "Router/AP"
    if mfr == "Microsoft":
        return "Windows"
    if mfr in {"RaspberryPi"}:
        return "Linux/Server"
    return "Unknown"


_PHONE_MFRS = {
    # Major global brands
    "Apple", "Samsung", "Google", "Huawei", "Xiaomi",
    "OnePlus", "OPPO", "Realme", "LG", "Sony", "Motorola", "Nokia",
    # Additional brands for broad compatibility
    "Vivo", "Tecno", "Infinix", "Itel", "ZTE", "Meizu",
    "HTC", "Lenovo", "Asus", "TCL", "Alcatel", "BlackBerry",
    "Honor", "Nothing", "Fairphone", "Poco",
    # Arabic / regional market brands
    "Redmi", "MIUI",
}

def _is_phone(dev: dict) -> bool:
    """Return True only for mobile phones (iPhone / Android)."""
    mfr = dev.get("manufacturer", "")
    os_ = dev.get("os", "")
    return mfr in _PHONE_MFRS or os_ in ("iOS/macOS", "Android")

def _classify(dev: dict) -> str:
    if _is_phone(dev):
        return "phone"
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
    Measures Ping / Download / Upload using standard library only.
    No external dependencies.
    """
    PING_HOST  = ("8.8.8.8", 53)
    DL_URL     = "http://speedtest.tele2.net/1MB.zip"
    UL_URL     = "https://httpbin.org/post"

    def run(self, on_ping, on_download, on_upload, on_done):
        threading.Thread(
            target=self._measure,
            args=(on_ping, on_download, on_upload, on_done),
            daemon=True
        ).start()

    def _measure(self, on_ping, on_dl, on_ul, on_done):
        # ── Ping ─────────────────────────────────────────────────────
        ping_ms = self._ping()
        Clock.schedule_once(lambda dt: on_ping(ping_ms), 0)

        # ── Download ─────────────────────────────────────────────────
        dl_mbps = self._download()
        Clock.schedule_once(lambda dt: on_dl(dl_mbps), 0)

        # ── Upload ───────────────────────────────────────────────────
        ul_mbps = self._upload()
        Clock.schedule_once(lambda dt: on_ul(ul_mbps), 0)

        Clock.schedule_once(lambda dt: on_done(), 0)

    def _ping(self) -> float:
        try:
            times = []
            for _ in range(4):
                t0 = time.perf_counter()
                s  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect(self.PING_HOST)
                s.close()
                times.append((time.perf_counter() - t0) * 1000)
                time.sleep(0.1)
            return round(sum(times) / len(times), 1)
        except Exception:
            return -1.0

    def _download(self) -> float:
        import urllib.request
        try:
            start      = time.perf_counter()
            total      = 0
            req        = urllib.request.Request(
                self.DL_URL,
                headers={"User-Agent": "NexusVision/1.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                while True:
                    chunk = resp.read(16384)
                    if not chunk:
                        break
                    total += len(chunk)
                    if time.perf_counter() - start > 10:
                        break
            elapsed = time.perf_counter() - start
            return round((total * 8) / (elapsed * 1_000_000), 2) if elapsed > 0 else 0.0
        except Exception:
            return 0.0

    def _upload(self) -> float:
        import urllib.request
        try:
            data  = b"x" * (256 * 1024)   # 256 KB payload
            start = time.perf_counter()
            req   = urllib.request.Request(
                self.UL_URL, data=data, method="POST",
                headers={"Content-Type": "application/octet-stream",
                         "User-Agent": "NexusVision/1.0"}
            )
            urllib.request.urlopen(req, timeout=15)
            elapsed = time.perf_counter() - start
            return round((len(data) * 8) / (elapsed * 1_000_000), 2) if elapsed > 0 else 0.0
        except Exception:
            return 0.0


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
                    self._d.update(json.load(f))
        except Exception:
            pass

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
        self.save()

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
        self._rssi_cache: dict = {}   # ip → signal_dbm

    def start(self):
        self._run = True
        threading.Thread(target=self._loop_arp,     daemon=True).start()
        threading.Thread(target=self._loop_traffic, daemon=True).start()

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
        # last resort: assume .1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            my_ip = s.getsockname()[0]
            s.close()
            return ".".join(my_ip.split(".")[:3]) + ".1"
        except Exception:
            return "Unknown"

    @staticmethod
    def my_ip() -> str:
        """Return this device's LAN IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "Unknown"

    @staticmethod
    def wifi_ssid() -> str:
        """Return the name of the current WiFi network."""
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "interfaces"],
                    stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                for line in out.splitlines():
                    if "SSID" in line and "BSSID" not in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            return parts[1].strip()
            elif platform.system() == "Linux":
                out = subprocess.check_output(
                    ["iwgetid", "-r"],
                    stderr=subprocess.DEVNULL
                ).decode().strip()
                if out:
                    return out
        except Exception:
            pass
        if ANDROID:
            try:
                act = _PythonActivity.mActivity
                wm  = act.getSystemService(_Context.WIFI_SERVICE)
                info = wm.getConnectionInfo()
                ssid = str(info.getSSID()).strip('"')
                return ssid or "Unknown"
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

    # ── ARP loop ─────────────────────────────────────────────────────────
    def _loop_arp(self):
        while self._run:
            try:
                self._scan_arp()
                if ANDROID:
                    self._scan_wifi()
                    self._scan_bt()
            except Exception:
                pass
            time.sleep(self.db.setting("scan_interval", 15))

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

    def _scan_arp(self):
        for ip, mac in self._read_arp():
            if not self._is_real_device(ip, mac):
                continue
            mfr  = _oui(mac)
            os_  = _guess_os(mfr)
            name = self._hostname(ip) or f"Host-{ip.split('.')[-1]}"
            dev_stub = {"manufacturer": mfr, "os": os_, "name": name}

            # ── PHONES ONLY ──────────────────────────────────────────
            if not _is_phone(dev_stub):
                continue

            is_new  = self.db.get(mac) is None
            # use real RSSI if available from WiFi scan cache
            signal  = self._rssi_cache.get(ip, -55)
            dev = self.db.upsert(
                mac, ip=ip, name=name, manufacturer=mfr,
                os=os_, signal=signal, dtype="phone"
            )
            if is_new:
                level = "ALERT" if self.db.setting("alert_new_device") else "INFO"
                self.db.log(level,
                            f"Phone detected: {name}  MAC:{mac}  [{mfr} / {os_}]")
                if self.alert and self.db.setting("alert_new_device"):
                    is_intruder = self.db.is_intruder(mac)
                    title   = "INTRUDER ALERT" if is_intruder else "New Phone Detected"
                    message = (f"Unknown device: {name} [{mfr}]"
                               if is_intruder else
                               f"{name}  [{mfr} / {os_}]  IP:{ip}")
                    self.alert.trigger(title, message, mac)
                threading.Thread(
                    target=self._port_scan, args=(ip, mac), daemon=True
                ).start()
            Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)
        self.db.save()

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
        rows = []
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    "arp -a", shell=True,
                    stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                for line in out.splitlines():
                    m = re.search(
                        r'(\d+\.\d+\.\d+\.\d+)\s+([\da-f\-]{17})', line, re.I)
                    if m:
                        rows.append((
                            m.group(1),
                            m.group(2).replace("-", ":").upper()
                        ))
            else:
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        p = line.split()
                        if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                            rows.append((p[0], p[3].upper()))
        except Exception:
            pass
        return rows

    def _hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0].split(".")[0]
        except Exception:
            return None

    def _scan_wifi(self):
        try:
            act = _PythonActivity.mActivity
            wm  = act.getSystemService(_Context.WIFI_SERVICE)
            wm.startScan()
            for ap in wm.getScanResults().toArray():
                mac  = str(ap.BSSID).upper()
                ssid = str(ap.SSID) or "Hidden-AP"
                sig  = int(ap.level)
                mfr  = _oui(mac)
                # ── update RSSI in db if we already know this device ────
                dev_in_db = self.db.get(mac)
                if dev_in_db:
                    dev_in_db["signal"] = sig
                    ip = dev_in_db.get("ip", "")
                    if ip:
                        self._rssi_cache[ip] = sig
                    # refresh radar blip with updated signal
                    Clock.schedule_once(
                        lambda dt, d=dev_in_db: self.on_device(d), 0)
                # skip adding APs to device list (we only track phones)
                continue
                new = self.db.get(mac) is None
                dev = self.db.upsert(
                    mac, name=f"AP:{ssid}", manufacturer=mfr,
                    os="Router/AP", signal=sig, dtype="router"
                )
                if new:
                    self.db.log("INFO",
                                f"WiFi AP: {ssid}  MAC:{mac}  RSSI:{sig}dBm")
                Clock.schedule_once(lambda dt, d=dev: self.on_device(d), 0)
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

    # ── TCP traffic loop ─────────────────────────────────────────────────
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
        """Read ESTABLISHED TCP connections; return (local_ip, remote_ip, port, direction)."""
        rows = []
        for fname in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(fname) as f:
                    for line in f.readlines()[1:]:
                        p = line.split()
                        if len(p) < 4:
                            continue
                        state = int(p[3], 16)
                        if state != 1:
                            continue
                        local_hex   = p[1]
                        remote_hex  = p[2]
                        local_ip    = _hex_to_ip4(local_hex.split(":")[0])
                        local_port  = int(local_hex.split(":")[1], 16)
                        remote_ip   = _hex_to_ip4(remote_hex.split(":")[0])
                        remote_port = int(remote_hex.split(":")[1], 16)
                        if remote_ip in ("0.0.0.0", "127.0.0.1"):
                            continue
                        # direction: if remote port is well-known → OUT (we connected)
                        #            if local port is well-known  → IN  (they connected)
                        if remote_port < 1024 or remote_port in (
                            5222, 5228, 5353, 8080, 8443, 19305
                        ):
                            direction = "OUT"
                        elif local_port < 1024:
                            direction = "IN"
                        else:
                            direction = "OUT"
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

            # ── outer glow (largest, most transparent) ────────────────
            sg = dp(22)
            cgo.rgba = (*col, alpha * 0.12)
            ego.pos  = (bx - sg/2, by - sg/2)
            ego.size = (sg, sg)

            # ── mid glow ─────────────────────────────────────────────
            sm = dp(13)
            cgm.rgba = (*col, alpha * 0.30)
            egm.pos  = (bx - sm/2, by - sm/2)
            egm.size = (sm, sm)

            # ── core dot ─────────────────────────────────────────────
            sd = dp(7)
            c_dot.rgba = (*col, min(1.0, alpha + 0.15))
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

    def on_device(self, dev):
        if not _is_phone(dev):
            return
        mac = dev['mac']
        self.radar.set_device(
            dev,
            threat      = self.db.is_blocked(mac),
            is_intruder = self.db.is_intruder(mac)
        )
        phones    = [d for d in self.db.active() if _is_phone(d)]
        intruders = [d for d in phones if self.db.is_intruder(d['mac'])]
        mfr       = dev.get('manufacturer', '?')
        os_       = dev.get('os', '?')
        sig       = dev.get('signal', '?')
        alert_txt = f"  [!] {len(intruders)} INTRUDER(S)" if intruders else ""
        self._hud.text = (
            f"PHONES: {len(phones)}  |  "
            f"LAST: {dev.get('name','?')} [{mfr}/{os_}] RSSI:{sig}dBm"
            f"{alert_txt}"
        )
        if intruders:
            self._hud.color = RED
        else:
            self._hud.color = G2


# ─── Devices Screen ───────────────────────────────────────────────────────────
class DeviceRow(BoxLayout):
    def __init__(self, dev, db, on_block, on_trust=None, **kwargs):
        super().__init__(orientation='horizontal', size_hint_y=None,
                         spacing=dp(8), padding=[dp(10), dp(8)], **kwargs)
        _card(self)
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

        # ── icon column ──────────────────────────────────────────────
        icon_col = BoxLayout(orientation='vertical',
                             size_hint_x=None, width=dp(44),
                             padding=[0, dp(4)])
        sym = "[A]" if mfr == "Apple" else "[D]"
        icon_col.add_widget(_lbl(sym, size=14,
                                 color=WHT if mfr == "Apple" else G1,
                                 halign='center'))
        icon_col.add_widget(_lbl(
            "iOS" if os_ == "iOS/macOS" else "Droid",
            size=8, color=G3, halign='center'))
        # trust badge
        badge_txt   = "[OK]"  if trusted  else ("[!!]" if intruder else "")
        badge_color = G1      if trusted  else (RED    if intruder else G3)
        if badge_txt:
            icon_col.add_widget(_lbl(badge_txt, size=9,
                                     color=badge_color, halign='center', bold=True))

        # ── info column ──────────────────────────────────────────────
        info = BoxLayout(orientation='vertical', spacing=dp(2))

        # row 1: name (red if blocked / intruder, green if trusted)
        name_color = (RED if (blocked or intruder) else
                      (G1  if trusted              else G1))
        name_prefix = "[INTRUDER] " if intruder else ("[BLOCKED] " if blocked else "")
        info.add_widget(_lbl(
            name_prefix + dev.get('name', 'Unknown'),
            size=14, color=name_color, bold=True))

        info.add_widget(_lbl(
            f"{mfr}  |  {os_}  |  MAC: {mac}",
            size=9, color=G2))

        first = str(dev.get('first_seen', ''))[:16]
        last  = str(dev.get('last_seen',  ''))[:16]
        info.add_widget(_lbl(
            f"IP: {dev.get('ip','?')}  |  RSSI: {dev.get('signal','?')}dBm  |"
            f"  First: {first}  Last: {last}",
            size=8, color=G3))

        if ports:
            info.add_widget(_lbl(
                f"Open ports: {', '.join(ports)}",
                size=9, color=YEL))
        else:
            info.add_widget(_lbl("Open ports: scanning...", size=9, color=G3))

        if svcs:
            info.add_widget(_lbl(
                f"Services: {', '.join(svcs[:6])}",
                size=9, color=CYN))

        # ── button column ─────────────────────────────────────────────
        btn_col = BoxLayout(orientation='vertical',
                            size_hint_x=None, width=dp(80), spacing=dp(6))

        btn_block = Button(
            text="[UNBLOCK]" if blocked else "[BLOCK]",
            font_size=sp(10),
            color=YEL if blocked else RED,
            background_color=(0, 0, 0, 0), background_normal='',
            bold=True,
        )
        btn_block.bind(on_release=lambda *_: on_block(mac))

        btn_trust = Button(
            text="[UNTRUST]" if trusted else "[TRUST]",
            font_size=sp(10),
            color=G3 if trusted else G1,
            background_color=(0, 0, 0, 0), background_normal='',
            bold=True,
        )
        if on_trust:
            btn_trust.bind(on_release=lambda *_: on_trust(mac))

        btn_col.add_widget(btn_block)
        btn_col.add_widget(btn_trust)

        self.add_widget(icon_col)
        self.add_widget(info)
        self.add_widget(btn_col)


class DevicesScreen(BaseScreen):
    def __init__(self, db, **kwargs):
        super().__init__(db, name='devices', **kwargs)
        self.root_box.add_widget(
            self._header("[ DEVICES ]",
                         "All detected network devices"))
        sv = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self._box = BoxLayout(orientation='vertical', size_hint_y=None,
                              spacing=dp(6), padding=[dp(8), dp(8)])
        self._box.bind(minimum_height=self._box.setter('height'))
        sv.add_widget(self._box)
        self.root_box.add_widget(sv)

    def refresh(self):
        self._box.clear_widgets()
        phones = [d for d in self.db.all() if _is_phone(d)]
        phones.sort(key=lambda d: d.get('last_seen', ''), reverse=True)
        if not phones:
            self._box.add_widget(
                _lbl("No phones detected yet – scanning...",
                     size=11, color=G3, halign='center'))
        for dev in phones:
            self._box.add_widget(
                DeviceRow(dev, self.db, self._block, on_trust=self._trust))

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

    def __init__(self, db, **kwargs):
        super().__init__(db, name='log', **kwargs)
        self.root_box.add_widget(
            self._header("[ PHONE LOG ]",
                         "Real-time traffic per phone  (metadata only for E2E apps)"))

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
        phones = [d for d in self.db.all() if _is_phone(d)]

        if not phones:
            self._box.add_widget(
                _lbl("No phones detected yet.", size=11, color=G3,
                     halign='center'))
            return

        for dev in sorted(phones,
                          key=lambda d: d.get('last_seen', ''), reverse=True):
            self._add_phone_section(dev)

    def _add_phone_section(self, dev):
        mac  = dev['mac']
        mfr  = dev.get('manufacturer', '?')
        os_  = dev.get('os', '?')
        ip   = dev.get('ip', '?')
        name = dev.get('name', mac)
        logs = dev.get('phone_log', [])

        # ── phone header ──────────────────────────────────────────────
        hdr = BoxLayout(size_hint_y=None, height=dp(40),
                        padding=[dp(8), dp(4)])
        _card(hdr)
        sym = "[A]" if mfr == "Apple" else "[D]"
        hdr.add_widget(_lbl(
            f"{sym}  {name}  |  {mfr}  {os_}  |  IP: {ip}  |  MAC: {mac}",
            size=11, color=WHT if mfr == "Apple" else G1, bold=True))
        self._box.add_widget(hdr)

        if not logs:
            row = BoxLayout(size_hint_y=None, height=dp(22),
                            padding=[dp(12), 0])
            row.add_widget(
                _lbl("No traffic captured yet.", size=9, color=G3))
            self._box.add_widget(row)
            return

        # ── traffic rows ──────────────────────────────────────────────
        for e in logs[:50]:
            direction = e.get('direction', 'OUT')
            svc       = e.get('service', '?')
            detail    = e.get('detail', '')
            hostname  = e.get('hostname', e.get('remote', '?'))
            port      = e.get('port', 0)
            t         = e.get('time', '')

            dir_sym = ">>" if direction == "OUT" else "<<"
            dir_col = CYN  if direction == "OUT" else YEL
            is_interesting = svc not in ("HTTPS", "HTTP", ":443", ":80")

            row = BoxLayout(orientation='horizontal', size_hint_y=None,
                            height=dp(20), padding=[dp(12), 0], spacing=dp(4))

            row.add_widget(_lbl(f"[{t}] {dir_sym}", size=8,
                                color=dir_col, halign='left'))
            row.add_widget(_lbl(
                svc, size=9,
                color=G1 if is_interesting else G2,
                bold=is_interesting, halign='left'))
            # show real domain name
            domain_display = hostname if hostname != e.get('remote','') else f":{port}"
            row.add_widget(_lbl(
                f"{domain_display}  {detail}",
                size=8, color=YEL if is_interesting else G3,
                halign='left'))

            self._box.add_widget(row)

        # separator
        sep = BoxLayout(size_hint_y=None, height=dp(8))
        self._box.add_widget(sep)

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
            self._header("[ SETTINGS ]", "Scan / Privacy / Alerts / Speed Test"))
        self._speed = SpeedTest()
        sv = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self._inner = BoxLayout(orientation='vertical', size_hint_y=None,
                                spacing=dp(10), padding=[dp(12), dp(10)])
        self._inner.bind(minimum_height=self._inner.setter('height'))
        sv.add_widget(self._inner)
        self.root_box.add_widget(sv)
        self._build()

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
        self.lg  = LogScreen(self.db)
        self.acc = AccessScreen(self.db, self.scanner,
                                ping_monitor=self.ping_mon)
        self.cfg = SettingsScreen(self.db)

        for s in [self.rdr, self.dev, self.lg, self.acc, self.cfg]:
            self.sm.add_widget(s)

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
