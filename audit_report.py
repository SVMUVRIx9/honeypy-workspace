#!/usr/bin/env python3
import os
import re
import json
import requests
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ========== CONFIG ==========
LOG_FILE = "http_audits.log"
REPORT_FILE = "http_audit_report.txt"
IPINFO_TOKEN = "b9c415b7381756"   # <- your ipinfo token

# ========== regex (tuned to your lines) ==========
TS_RE = re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+')
IP_RE = re.compile(r'Client with IP Address:\s*(\d{1,3}(?:\.\d{1,3}){3})')
USER_RE = re.compile(r'Username[:=]\s*([^\s,]+)', re.IGNORECASE)
PASS_RE = re.compile(r'Password[:=]\s*([^\s,]+)', re.IGNORECASE)

# ========== caches ==========
_geo_cache = {}
_vpn_cache = {}

# ========== helpers ==========
def now_utc_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def ipinfo_lookup(ip):
    """Return (location_str, vpn_str) using ipinfo.io, with caching and graceful fallback."""
    if not ip or ip == "-":
        return "Unknown", "Unknown"
    if ip in _geo_cache and ip in _vpn_cache:
        return _geo_cache[ip], _vpn_cache[ip]

    base = f"https://ipinfo.io/{ip}/json"
    if IPINFO_TOKEN:
        base += f"?token={IPINFO_TOKEN}"
    try:
        r = requests.get(base, timeout=5)
        if r.status_code != 200:
            _geo_cache[ip] = "Unknown"
            _vpn_cache[ip] = "Unknown"
            return "Unknown", "Unknown"
        data = r.json()
        city = data.get("city", "") or ""
        region = data.get("region", "") or ""
        country = data.get("country", "") or ""
        org = data.get("org", "") or ""
        loc_parts = [p for p in (city, region, country) if p]
        loc = ", ".join(loc_parts) if loc_parts else (org or "Unknown")
        # privacy flags (ipinfo paid returns 'privacy')
        privacy = data.get("privacy") or {}
        flags = []
        if isinstance(privacy, dict):
            if privacy.get("vpn"):
                flags.append("VPN")
            if privacy.get("proxy"):
                flags.append("Proxy")
            if privacy.get("tor"):
                flags.append("Tor")
            if privacy.get("hosting"):
                flags.append("Hosting")
        vpn_str = "No"
        if flags:
            vpn_str = "Yes (" + "/".join(flags) + ")"
        # store caches
        _geo_cache[ip] = f"{loc} ({org})" if org else loc
        _vpn_cache[ip] = vpn_str
        return _geo_cache[ip], _vpn_cache[ip]
    except Exception:
        _geo_cache[ip] = "Unknown"
        _vpn_cache[ip] = "Unknown"
        return "Unknown", "Unknown"

# ========== parse log ==========
def parse_http_logs():
    """
    Parses lines like:
    2025-10-18 20:17:05,788 Client with IP Address: 196.75.162.63 entered
    Username: DEMBELE, Password: LIDAHA
    """
    creds = []   # list of (ip, ts_str, user, pass)
    lines = []
    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file not found: {LOG_FILE}")
        return creds, 0

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as fh:
        # We'll read lines, keep state in case IP and credentials are on different lines (like your sample)
        pending_ip = None
        pending_ts = None
        for raw in fh:
            line = raw.strip()
            if not line:
                continue

            # timestamp extraction on line start
            ts_m = TS_RE.match(line)
            if ts_m:
                try:
                    ts = datetime.strptime(ts_m.group("ts"), "%Y-%m-%d %H:%M:%S")
                    pending_ts = ts.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pending_ts = "N/A"

            # IP line
            ip_m = IP_RE.search(line)
            if ip_m:
                pending_ip = ip_m.group(1)

            # username/password might be on same or next line
            user_m = USER_RE.search(line)
            pass_m = PASS_RE.search(line)
            if user_m or pass_m:
                user = user_m.group(1) if user_m else "-"
                pwd  = pass_m.group(1) if pass_m else "-"
                ts_str = pending_ts or "N/A"
                ip_val = pending_ip or "-"
                creds.append((ip_val, ts_str, user, pwd))
                # clear pending (avoid reuse for unrelated lines)
                pending_ip = None
                pending_ts = None

    return creds, len(creds)

# ========== generate text report ==========
def generate_report():
    creds, total = parse_http_logs()
    ip_counts = Counter([c[0] for c in creds if c[0] and c[0] != "-"])
    cred_pairs = Counter([(c[2], c[3]) for c in creds if (c[2] and c[2] != "-") or (c[3] and c[3] != "-")])

    header_lines = []
    header_lines.append("===== HONEYPY HTTP ATTACK REPORT =====")
    header_lines.append(f"Generated on: {now_utc_str()}\n")
    header_lines.append(f"Total entries processed: {total}")
    header_lines.append(f"Unique attacker IPs: {len(ip_counts)}\n")

    body_lines = []

    # Top IPs
    body_lines.append("Top Attacker IPs:")
    if ip_counts:
        for ip, cnt in ip_counts.most_common():
            geo, vpn = ipinfo_lookup(ip)
            body_lines.append(f"{ip:20} | {geo:40} | {vpn:20} | {cnt} attempts")
    else:
        body_lines.append("No attacker IPs found.")
    body_lines.append("")

    # Captured Credentials
    body_lines.append("Captured Credentials:")
    if creds:
        body_lines.append(f"{'IP':18} | {'Timestamp':19} | {'User':15} | {'Pass':15} | {'Location (ASN/Org)'}")
        for ip, ts, user, pwd in creds:
            geo, vpn = ipinfo_lookup(ip)
            body_lines.append(f"{ip:18} | {ts:19} | {user:15} | {pwd:15} | {geo}")
    else:
        body_lines.append("No credentials captured.")
    body_lines.append("")

    # Credential pairs summary
    body_lines.append("Top Credential Pairs (user,password):")
    if cred_pairs:
        for (u,p), c in cred_pairs.most_common(50):
            body_lines.append(f"{c:5} | {u:20} | {p:20}")
    else:
        body_lines.append("No credential pairs to show.")
    body_lines.append("")

    # write to file and print
    with open(REPORT_FILE, "w", encoding="utf-8") as rpt:
        for L in header_lines + body_lines:
            rpt.write(L + "\n")
    # also print to stdout
    print("\n".join(header_lines + body_lines))
    print(f"\n[+] Saved text report to: {REPORT_FILE}")

if __name__ == "__main__":
    # check that requests exists
    try:
        import requests  # noqa: F401
    except Exception:
        print("[!] Python 'requests' module not installed. Install with: pip install requests")
        raise SystemExit(1)
    generate_report()
