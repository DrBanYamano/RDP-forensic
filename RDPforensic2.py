# ==========================================================
# RDP Hunter v3 GEOIP
# Security.evtx + GeoIP + Attacker Risk Score
# Need:
#   pip install python-evtx requests
# ==========================================================

from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from collections import defaultdict
import requests
import csv
import os
import time

# ----------------------------------------------------------
# CONFIG
# ----------------------------------------------------------
EVTX_FILE = r"D:\Python\Security.evtx"
EXPORT_CSV = "rdp_report_v3_geoip.csv"

# ----------------------------------------------------------
# HELPERS
# ----------------------------------------------------------
def find_tag_text(root, tag_name):
    for elem in root.iter():
        if elem.tag.endswith(tag_name):
            return elem.text if elem.text else ""
    return ""

def get_data(root, name):
    for elem in root.iter():
        if elem.tag.endswith("Data"):
            if elem.attrib.get("Name") == name:
                return elem.text if elem.text else ""
    return ""

def get_time(root):
    for elem in root.iter():
        if elem.tag.endswith("TimeCreated"):
            return elem.attrib.get("SystemTime", "")
    return ""

def clean_ip(ip):
    bad = ["", "-", "::1", "127.0.0.1", "localhost"]
    return "" if ip in bad else ip

# ----------------------------------------------------------
# GEOIP LOOKUP
# ----------------------------------------------------------
geo_cache = {}

def geo_lookup(ip):
    if ip in geo_cache:
        return geo_cache[ip]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,hosting,proxy"
        r = requests.get(url, timeout=5)
        data = r.json()

        if data["status"] == "success":
            geo_cache[ip] = data
            time.sleep(0.4)   # avoid rate limit
            return data

    except:
        pass

    geo_cache[ip] = {}
    return {}

# ----------------------------------------------------------
# RISK SCORE
# ----------------------------------------------------------
def risk_score(fail_count, geo):
    score = 0

    if fail_count >= 5:
        score += 40

    if geo.get("proxy"):
        score += 25

    if geo.get("hosting"):
        score += 20

    if geo.get("country") not in ["South Korea", "Korea, Republic of", ""]:
        score += 15

    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"

# ----------------------------------------------------------
# STORAGE
# ----------------------------------------------------------
failed_ip = defaultdict(int)
success_logins = []
rdp_logins = []
timeline = []

# ----------------------------------------------------------
# START
# ----------------------------------------------------------
if not os.path.exists(EVTX_FILE):
    print("[-] Security.evtx not found.")
    exit()

print("=" * 60)
print("RDP Hunter v3 GEOIP")
print("=" * 60)

count = 0

# ----------------------------------------------------------
# PARSE EVTX
# ----------------------------------------------------------
with Evtx(EVTX_FILE) as log:
    for record in log.records():
        count += 1

        if count % 1000 == 0:
            print(f"[+] Processed {count} records...")

        try:
            root = ET.fromstring(record.xml())

            event_id = find_tag_text(root, "EventID")
            time_str = get_time(root)
            user = get_data(root, "TargetUserName")
            ip = clean_ip(get_data(root, "IpAddress"))
            logon_type = get_data(root, "LogonType")

            # FAIL LOGIN
            if event_id == "4625":
                if ip:
                    failed_ip[ip] += 1
                timeline.append([time_str, "FAIL LOGIN", user, ip])

            # SUCCESS LOGIN
            elif event_id == "4624":
                success_logins.append([time_str, user, ip, logon_type])
                timeline.append([time_str, "SUCCESS LOGIN", user, ip])

                if logon_type == "10":
                    rdp_logins.append([time_str, user, ip])

        except:
            continue

# ----------------------------------------------------------
# REPORT
# ----------------------------------------------------------
print("\n" + "=" * 60)
print("ATTACKER ANALYSIS REPORT")
print("=" * 60)

print("\n[1] RDP LOGIN + GEOIP")

csv_rows = []

for row in rdp_logins:
    time_str, user, ip = row

    geo = geo_lookup(ip) if ip else {}

    country = geo.get("country", "")
    city = geo.get("city", "")
    isp = geo.get("isp", "")
    hosting = geo.get("hosting", False)
    proxy = geo.get("proxy", False)

    fail_count = failed_ip[ip]
    risk = risk_score(fail_count, geo)

    print("-" * 60)
    print("Time     :", time_str)
    print("User     :", user)
    print("IP       :", ip)
    print("Country  :", country)
    print("City     :", city)
    print("ISP      :", isp)
    print("Hosting  :", hosting)
    print("ProxyVPN :", proxy)
    print("Failed   :", fail_count)
    print("Risk     :", risk)

    csv_rows.append([
        time_str, user, ip, country, city, isp,
        hosting, proxy, fail_count, risk
    ])

# ----------------------------------------------------------
# TOP FAILED IPS
# ----------------------------------------------------------
print("\n[2] TOP FAILED IP")
for ip, c in sorted(failed_ip.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(ip, ":", c)

# ----------------------------------------------------------
# EXPORT CSV
# ----------------------------------------------------------
with open(EXPORT_CSV, "w", newline="", encoding="utf-8-sig") as f:
    writer = csv.writer(f)
    writer.writerow([
        "Time", "User", "IP", "Country", "City", "ISP",
        "Hosting", "Proxy", "FailCount", "Risk"
    ])
    writer.writerows(csv_rows)

print(f"\n[+] CSV Exported: {EXPORT_CSV}")
print("\nDone.")