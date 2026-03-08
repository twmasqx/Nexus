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

# ── Requirements ──────────────────────────────────────────────────────────────
# CRITICAL: python3==3.10 — Python 3.14 breaks Kivy config.pxi / Cython build
# hostpython3==3.10 — match host toolchain to target
requirements = python3==3.10,hostpython3==3.10,kivy==2.3.0,plyer,Cython>=0.29.33,<3.0

# ── Display ───────────────────────────────────────────────────────────────────
orientation  = portrait
fullscreen   = 1
android.presplash_color = #030D03

# ── Android SDK/NDK ───────────────────────────────────────────────────────────
android.api     = 33
android.minapi  = 21
android.ndk     = 25b
android.ndk_api = 21
android.archs   = arm64-v8a, armeabi-v7a

# ── SDK License ───────────────────────────────────────────────────────────────
android.accept_sdk_license = True

# ── AndroidX ──────────────────────────────────────────────────────────────────
android.enable_androidx = True

# ── Permissions (single line — required by buildozer parser) ──────────────────
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,CHANGE_NETWORK_STATE,BLUETOOTH,BLUETOOTH_ADMIN,BLUETOOTH_SCAN,BLUETOOTH_CONNECT,VIBRATE,READ_PHONE_STATE,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,RECEIVE_BOOT_COMPLETED

# ── p4a ───────────────────────────────────────────────────────────────────────
# master = stable, develop = Python 3.14 default (breaks Kivy)
p4a.branch = master

[buildozer]
log_level    = 2
warn_on_root = 1
