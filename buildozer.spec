[app]

# ── Identity ──────────────────────────────────────────────────────────────────
title           = Nexus Vision
package.name    = nexusvision
package.domain  = org.nexus.vision
version         = 1.0

# ── Source ────────────────────────────────────────────────────────────────────
source.dir            = .
source.include_exts   = py,png,jpg,kv,atlas,json,wav
source.exclude_dirs   = __pycache__,.buildozer,.git,tests

# ── Requirements ─────────────────────────────────────────────────────────────
# plyer: notifications + vibration
requirements = python3,kivy==2.3.0,plyer

# ── Orientation & display ─────────────────────────────────────────────────────
orientation  = portrait
fullscreen   = 1
android.presplash_color = #030D03

# ── Android SDK/NDK ───────────────────────────────────────────────────────────
android.api    = 33
android.minapi = 21
android.ndk    = 25b
android.ndk_api = 21

# Build both 64-bit and 32-bit for maximum device compatibility
# arm64-v8a  → Samsung, Xiaomi, Poco, Redmi, OPPO, Realme (2018+)
# armeabi-v7a → older / budget devices
android.archs = arm64-v8a, armeabi-v7a

# ── SDK License (required for CI/CD) ─────────────────────────────────────────
android.accept_sdk_license = True

# ── Gradle / Build ────────────────────────────────────────────────────────────
android.enable_androidx   = True
android.gradle_dependencies = com.google.android.material:material:1.9.0

# ── Permissions ───────────────────────────────────────────────────────────────
android.permissions =
    INTERNET,
    ACCESS_NETWORK_STATE,
    ACCESS_WIFI_STATE,
    CHANGE_WIFI_STATE,
    ACCESS_FINE_LOCATION,
    ACCESS_COARSE_LOCATION,
    CHANGE_NETWORK_STATE,
    BLUETOOTH,
    BLUETOOTH_ADMIN,
    BLUETOOTH_SCAN,
    BLUETOOTH_CONNECT,
    VIBRATE,
    READ_PHONE_STATE,
    READ_EXTERNAL_STORAGE,
    WRITE_EXTERNAL_STORAGE,
    RECEIVE_BOOT_COMPLETED

# ── Python for Android ────────────────────────────────────────────────────────
p4a.branch = develop

# ── Buildozer ────────────────────────────────────────────────────────────────
[buildozer]
log_level    = 2
warn_on_root = 1
