
''' 
cmd by administrator: "wevtutil epl Security D:\Security.evtx" copy file Vì sao Security.evtx đặc biệt?
Chứa log đăng nhập, đăng xuất, audit, RDP, quyền truy cập…
Windows bảo vệ rất chặt để tránh bị sửa/xóa dấu vết 
'''


# ==========================================================
# RDP Hunter v3 GEOIP
# Security.evtx + GeoIP + Attacker Risk Score
# Need:
#   pip install python-evtx requests
# ==========================================================

# ==========================================================
# RDP Hunter v4 - DISCOVER MODE
# Auto Discover Security.evtx Contents
# Need: pip install python-evtx
# ==========================================================

# ==========================================================
# RDP Hunter v5 - THREAT HUNT MODE
# Security.evtx + Windows Threat Hunting
# Need: pip install python-evtx
# ==========================================================

# ==========================================================
# RDP Hunter v6 - SMART SCORING MODE
# Reduce False Positive / Chain-based Detection
# Need: pip install python-evtx
# ==========================================================

# ==========================================================
# RDP Hunter v7 - MALWARE ARTIFACT HUNT
# Windows Local Artifact Threat Hunting
# Run as Administrator recommended
# Python 3.x
# ==========================================================

import os
import csv
import subprocess
import winreg
from pathlib import Path
from datetime import datetime

# ----------------------------------------------------------
# CONFIG
# ----------------------------------------------------------
EXPORT_CSV = "malware_artifact_report.csv"

# ----------------------------------------------------------
# HELPERS
# ----------------------------------------------------------
def safe_listdir(path):
    try:
        return os.listdir(path)
    except:
        return []

def file_time(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return ""

def add_result(results, category, item, detail):
    results.append([category, item, detail])

# ----------------------------------------------------------
# STORAGE
# ----------------------------------------------------------
results = []

# ==========================================================
# 1. PREFETCH (executed programs)
# ==========================================================
prefetch = r"C:\Windows\Prefetch"

for f in safe_listdir(prefetch):
    if f.lower().endswith(".pf"):
        suspicious = [
            "powershell", "cmd", "wscript", "cscript",
            "rundll32", "regsvr32", "mshta",
            "anydesk", "teamviewer", "rustdesk"
        ]

        for s in suspicious:
            if s in f.lower():
                add_result(results, "Prefetch", f, "Suspicious execution")

# ==========================================================
# 2. STARTUP FOLDER
# ==========================================================
startup_paths = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
]

for path in startup_paths:
    for f in safe_listdir(path):
        add_result(results, "StartupFolder", f, path)

# ==========================================================
# 3. RUN REGISTRY KEYS
# ==========================================================
run_keys = [
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),

    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run")
]

for hive, path in run_keys:
    try:
        key = winreg.OpenKey(hive, path)
        i = 0
        while True:
            name, value, _ = winreg.EnumValue(key, i)
            add_result(results, "RunKey", name, value)
            i += 1
    except:
        pass

# ==========================================================
# 4. SCHEDULED TASKS
# ==========================================================
try:
    output = subprocess.check_output(
        "schtasks /query /fo LIST /v",
        shell=True,
        text=True,
        errors="ignore"
    )

    for line in output.splitlines():
        if "TaskName:" in line:
            add_result(results, "ScheduledTask", line.strip(), "")
except:
    pass

# ==========================================================
# 5. RECENT DOWNLOADS
# ==========================================================
downloads = str(Path.home() / "Downloads")

for f in safe_listdir(downloads):
    fp = os.path.join(downloads, f)
    try:
        mtime = os.path.getmtime(fp)
        add_result(results, "Downloads", f, file_time(mtime))
    except:
        pass

# ==========================================================
# 6. REMOTE ACCESS SOFTWARE
# ==========================================================
program_files = [
    r"C:\Program Files",
    r"C:\Program Files (x86)"
]

remote_tools = [
    "AnyDesk",
    "TeamViewer",
    "RustDesk",
    "UltraViewer",
    "TightVNC"
]

for base in program_files:
    for name in safe_listdir(base):
        for tool in remote_tools:
            if tool.lower() in name.lower():
                add_result(results, "RemoteTool", name, base)

# ==========================================================
# 7. WINDOWS TEMP
# ==========================================================
temp_dirs = [
    r"C:\Windows\Temp",
    os.path.expandvars(r"%TEMP%")
]

for td in temp_dirs:
    for f in safe_listdir(td)[:50]:
        add_result(results, "TempFile", f, td)

# ==========================================================
# REPORT
# ==========================================================
print("=" * 60)
print("RDP Hunter v7 - MALWARE ARTIFACT HUNT")
print("=" * 60)

categories = {}
for row in results:
    categories[row[0]] = categories.get(row[0], 0) + 1

print("\n[1] SUMMARY")
for k, v in categories.items():
    print(f"{k:20} : {v}")

print("\n[2] POSSIBLE FINDINGS")
for row in results[:80]:
    print(row)

# ==========================================================
# EXPORT CSV
# ==========================================================
with open(EXPORT_CSV, "w", newline="", encoding="utf-8-sig") as f:
    writer = csv.writer(f)
    writer.writerow(["Category", "Item", "Detail"])
    writer.writerows(results)

print(f"\n[+] CSV Exported : {EXPORT_CSV}")
print("\nDone.")