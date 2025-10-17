import re
import os
from collections import Counter, defaultdict
from datetime import datetime

try:
    import geoip2.database
    GEO_OK = True
except:
    GEO_OK = False

GEO_DB = "GeoLite2-City.mmdb"
TS_RE = re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<body>.*)$')
IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
USER_RE = re.compile(r'username[:=]\s*([^\s,]+)', re.IGNORECASE)
PASS_RE = re.compile(r'password[:=]\s*([^\s,]+)', re.IGNORECASE)
UA_RE = re.compile(r'user[-_\s]?agent[:=]\s*(.+)', re.IGNORECASE)
URL_RE = re.compile(r'url[:=]\s*(https?://[^\s,]+|/[^,\s]+)', re.IGNORECASE)
PORT_WORD_RE = re.compile(r'\bport[:=]?\s*(\d{2,5})', re.IGNORECASE)
PORT_COLON_RE = re.compile(r'(?<!\d):(\d{2,5})')
BEACON_JSON_RE = re.compile(r'\{.*"(?:username|user)".*?\}', re.IGNORECASE | re.DOTALL)

def geo_info(ip):
    if ip.startswith(("127.","10.","192.168.")):
        return "Local Network"
    if not GEO_OK or not os.path.exists(GEO_DB):
        return "Unknown"
    try:
        with geoip2.database.Reader(GEO_DB) as r:
            rec = r.city(ip)
            country = rec.country.name or "Unknown Country"
            city = rec.city.name or ""
            return f"{city}, {country}" if city else country
    except:
        return "Unknown"

def extract_ts_and_body(line):
    m = TS_RE.match(line)
    if m:
        try:
            ts = datetime.strptime(m.group('ts'), "%Y-%m-%d %H:%M:%S")
        except:
            ts = None
        return ts, m.group('body')
    return None, line.strip()

def extract_port(text):
    m = PORT_WORD_RE.search(text)
    if m:
        return m.group(1)
    m2 = PORT_COLON_RE.findall(text)
    if m2:
        return m2[-1]
    return "-"

def parse_http_logs():
    creds = []
    hits = []
    lines_processed = 0
    log_files = ["http_audits.log", "audits.log"]
    for fname in log_files:
        if not os.path.exists(fname):
            continue
        with open(fname, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                lines_processed += 1
                ts, body = extract_ts_and_body(line)
                ip_m = IP_RE.search(body)
                ip = ip_m.group(1) if ip_m else "-"
                user = "-"
                pwd = "-"
                ua = "-"
                url = "-"
                port = extract_port(body)
                u_m = USER_RE.search(body)
                p_m = PASS_RE.search(body)
                ua_m = UA_RE.search(body)
                url_m = URL_RE.search(body)
                if u_m:
                    user = u_m.group(1)
                if p_m:
                    pwd = p_m.group(1)
                if ua_m:
                    ua = ua_m.group(1).strip()
                if url_m:
                    url = url_m.group(1).strip()
                if user != "-" or pwd != "-":
                    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"
                    creds.append((ip, ts_str, port, user, pwd, ua, url))
                else:
                    # try to detect JSON beacon payload in line
                    j_m = BEACON_JSON_RE.search(body)
                    if j_m:
                        payload = j_m.group(0)
                        u2 = re.search(r'"(?:username|user)"\s*:\s*"([^"]+)"', payload, re.IGNORECASE)
                        p2 = re.search(r'"(?:password|pass)"\s*:\s*"([^"]+)"', payload, re.IGNORECASE)
                        ua2 = re.search(r'"user_agent"\s*:\s*"([^"]+)"', payload, re.IGNORECASE)
                        url2 = re.search(r'"url"\s*:\s*"([^"]+)"', payload, re.IGNORECASE)
                        port2 = re.search(r'"port"\s*:\s*"([^"]+)"', payload, re.IGNORECASE)
                        u_val = u2.group(1) if u2 else "-"
                        p_val = p2.group(1) if p2 else "-"
                        ua_val = ua2.group(1) if ua2 else "-"
                        url_val = url2.group(1) if url2 else "-"
                        port_val = port2.group(1) if port2 else port
                        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"
                        creds.append((ip if ip != "-" else ip, ts_str, port_val, u_val, p_val, ua_val, url_val))
                # capture any command-like or URL hits
                if url != "-" or "GET " in body or "POST " in body:
                    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"
                    hits.append((ip, ts_str, port, url, ua))
    return creds, hits, lines_processed

def generate_report():
    creds, hits, total = parse_http_logs()
    all_ips = [c[0] for c in creds] + [h[0] for h in hits]
    ip_counts = Counter([ip for ip in all_ips if ip and ip != "-"])
    url_counts = Counter([h[3] for h in hits if h[3] and h[3] != "-"])
    ua_counts = Counter([c[5] for c in creds if c[5] and c[5] != "-"] + [h[4] for h in hits if h[4] and h[4] != "-"])
    cred_pairs = Counter([(c[3], c[4]) for c in creds if c[3] != "-" or c[4] != "-"])
    port_counts = Counter([c[2] for c in creds if c[2] and c[2] != "-"] + [h[2] for h in hits if h[2] and h[2] != "-"])

    t = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open("http_report.txt", "w", encoding="utf-8") as rpt:
        rpt.write("===== HONEYPY HTTP ATTACK REPORT =====\n")
        rpt.write(f"Generated on: {t}\n\n")
        rpt.write(f"Total log lines scanned: {total}\n")
        rpt.write(f"Unique source IPs: {len(ip_counts)}\n\n")

        rpt.write("Top Attacker IPs:\n")
        if ip_counts:
            for ip, cnt in ip_counts.most_common(20):
                rpt.write(f"{ip:20} | {geo_info(ip):25} | {cnt} hits\n")
        else:
            rpt.write("No attacker IPs found.\n")

        rpt.write("\nTop Requested URLs / Paths:\n")
        if url_counts:
            for url, c in url_counts.most_common(20):
                rpt.write(f"{c:5} | {url}\n")
        else:
            rpt.write("No URL hits recorded.\n")

        rpt.write("\nTop User-Agents:\n")
        if ua_counts:
            for ua, c in ua_counts.most_common(20):
                rpt.write(f"{c:5} | {ua}\n")
        else:
            rpt.write("No user-agents recorded.\n")

        rpt.write("\nTop Credential Pairs (user,password):\n")
        if cred_pairs:
            for (u,p), c in cred_pairs.most_common(50):
                rpt.write(f"{c:5} | {u:20} | {p:20}\n")
        else:
            rpt.write("No credentials captured.\n")

        rpt.write("\nTop Targeted Ports:\n")
        if port_counts:
            for p,c in port_counts.most_common(20):
                rpt.write(f"{p:6} : {c} hits\n")
        else:
            rpt.write("No targeted ports found.\n")

        rpt.write("\nPer-IP Details:\n")
        rpt.write("IP                | First Seen         | Last Seen          | Hits | Unique URLs | Top URLs (3) | Top UAs (3) | Geo\n")
        per_ip = defaultdict(lambda: {"first": None, "last": None, "hits":0, "urls":Counter(), "uas":Counter()})
        for ip, ts, port, user, pwd, ua, url in creds:
            if ip == "-" or not ip:
                continue
            per_ip[ip]["hits"] += 1
            if ts != "N/A":
                try:
                    d = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    if per_ip[ip]["first"] is None or d < per_ip[ip]["first"]:
                        per_ip[ip]["first"] = d
                    if per_ip[ip]["last"] is None or d > per_ip[ip]["last"]:
                        per_ip[ip]["last"] = d
                except:
                    pass
            if url and url != "-":
                per_ip[ip]["urls"][url] += 1
            if ua and ua != "-":
                per_ip[ip]["uas"][ua] += 1
        for ip, ts, port, url, ua in hits:
            if ip == "-" or not ip:
                continue
            per_ip[ip]["hits"] += 1
            if ts != "N/A":
                try:
                    d = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    if per_ip[ip]["first"] is None or d < per_ip[ip]["first"]:
                        per_ip[ip]["first"] = d
                    if per_ip[ip]["last"] is None or d > per_ip[ip]["last"]:
                        per_ip[ip]["last"] = d
                except:
                    pass
            if url and url != "-":
                per_ip[ip]["urls"][url] += 1
            if ua and ua != "-":
                per_ip[ip]["uas"][ua] += 1

        if per_ip:
            for ip in sorted(per_ip.keys(), key=lambda x: per_ip[x]["hits"], reverse=True):
                info = per_ip[ip]
                first = info["first"].strftime("%Y-%m-%d %H:%M:%S") if info["first"] else "N/A"
                last = info["last"].strftime("%Y-%m-%d %H:%M:%S") if info["last"] else "N/A"
                top_urls = ",".join(f"{u}:{n}" for u,n in info["urls"].most_common(3))
                top_uas = ",".join(f"{u[:30]}:{n}" for u,n in info["uas"].most_common(3))
                rpt.write(f"{ip:17} | {first:19} | {last:19} | {info['hits']:4} | {len(info['urls']):11} | {top_urls:35} | {top_uas:35} | {geo_info(ip)}\n")
        else:
            rpt.write("No per-IP records found.\n")

if __name__ == "__main__":
    generate_report()
