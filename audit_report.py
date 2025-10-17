import re
import os
import sys
from collections import Counter
from datetime import datetime

try:
    import geoip2.database
    GEO_OK = True
except:
    GEO_OK = False

TS_RE = re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<body>.*)$')
IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
USER_RE = re.compile(r'username[:=]\s*([^\s,]+)', re.IGNORECASE)
PASS_RE = re.compile(r'password[:=]\s*([^\s,]+)', re.IGNORECASE)
CMD_RE = re.compile(r'executed[:=]\s*(.+)', re.IGNORECASE)
PORT_COLON_RE = re.compile(r'(?<!\d):(\d{2,5})')         # colon followed by port
PORT_WORD_RE = re.compile(r'\bport[:=]?\s*(\d{2,5})', re.IGNORECASE)

def get_geo_info(ip):
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        return "Local Network"
    if not GEO_OK or not os.path.exists("GeoLite2-City.mmdb"):
        return "Unknown"
    try:
        with geoip2.database.Reader("GeoLite2-City.mmdb") as reader:
            r = reader.city(ip)
            country = r.country.name or "Unknown Country"
            city = r.city.name or ""
            return f"{city}, {country}" if city else country
    except:
        return "Unknown"

def extract_ts_and_body(line):
    m = TS_RE.match(line)
    if m:
        try:
            ts = datetime.strptime(m.group('ts'), "%Y-%m-%d %H:%M:%S")
            return ts, m.group('body')
        except:
            return None, line.strip()
    return None, line.strip()

def extract_port_from_text(text):
    m = PORT_WORD_RE.search(text)
    if m:
        return m.group(1)
    m2 = PORT_COLON_RE.findall(text)
    if m2:
        # prefer last colon-port occurrence that's not part of IP (heuristic)
        for v in reversed(m2):
            return v
    return "-"

def parse_logs():
    creds = []
    cmds = []

    if os.path.exists("cmd_audits.log"):
        with open("cmd_audits.log", "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                ts, body = extract_ts_and_body(line)
                ip_m = IP_RE.search(body)
                if not ip_m:
                    continue
                ip = ip_m.group(1)
                user_m = USER_RE.search(body)
                pass_m = PASS_RE.search(body)
                user = user_m.group(1) if user_m else "-"
                pwd = pass_m.group(1) if pass_m else "-"
                port = extract_port_from_text(body)
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"
                creds.append((ip, ts_str, port, user, pwd))

    if os.path.exists("audits.log"):
        with open("audits.log", "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                ts, body = extract_ts_and_body(line)
                ip_m = IP_RE.search(body)
                if not ip_m:
                    continue
                ip = ip_m.group(1)
                cmd_m = CMD_RE.search(body)
                if cmd_m:
                    cmd = cmd_m.group(1).strip()
                else:
                    rest = body[ip_m.end():].strip()
                    cand = re.search(r'([A-Za-z0-9_\-./\|><\s]+)$', rest)
                    cmd = cand.group(1).strip() if cand else None
                if not cmd:
                    continue
                port = extract_port_from_text(body)
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"
                cmds.append((ip, ts_str, port, cmd))
    return creds, cmds

def generate_report():
    creds, cmds = parse_logs()
    all_ips = [ip for ip, _, _, _, _ in creds] + [ip for ip, _, _, _ in cmds]
    ip_count = Counter(all_ips)
    t = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    with open("report.txt", "w", encoding="utf-8") as rpt:
        rpt.write("===== HONEYPY ATTACK REPORT =====\n")
        rpt.write(f"Generated on: {t}\n\n")

        rpt.write("Top Attacker IPs:\n")
        if ip_count:
            for ip, cnt in ip_count.most_common(20):
                geo = get_geo_info(ip)
                rpt.write(f"{ip:20} | {geo:25} | {cnt} attempts\n")
        else:
            rpt.write("No IPs found.\n")

        rpt.write("\nCaptured Credentials: \n\nIP                   | Timestamp           | Port   | User            | Pass\n")
        if creds:
            for ip, ts, port, user, pwd in creds:
                geo = get_geo_info(ip)
                rpt.write(f"{ip:20} | {ts} | {port:6} | {user:15} | {pwd:15} | {geo}\n")
        else:
            rpt.write("No credentials captured.\n")

        rpt.write("\nExecuted Commands: \n\nIP                   | Timestamp           | Port   | Command\n")
        if cmds:
            for ip, ts, port, cmd in cmds:
                geo = get_geo_info(ip)
                rpt.write(f"{ip:20} | {ts} | {port:6} | {cmd} | {geo}\n")
        else:
            rpt.write("No commands executed.\n")

if __name__ == "__main__":
    generate_report()
