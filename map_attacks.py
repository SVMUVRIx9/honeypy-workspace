import re, os
from datetime import datetime
import folium
from folium.plugins import MarkerCluster

# Try geoip2; if not available or no DB, we'll fallback to a small test map
try:
    import geoip2.database
    GEO_OK = True
except:
    GEO_OK = False

GEO_DB = "GeoLite2-City.mmdb"  # place DB here if you have it

# Test mapping to force Morocco (for local testing)
TEST_IP_MAP = {
    "197.0.0.1": ("Casablanca", "Morocco", 33.5731, -7.5898),
    "41.77.0.1": ("Rabat", "Morocco", 34.0209, -6.8416),
    "8.8.8.8":   ("Mountain View", "United States", 37.386, -122.0838)
}

IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
TS_RE = re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<body>.*)$')
CMD_RE = re.compile(r'executed[:=]\s*(.+)', re.IGNORECASE)
USER_RE = re.compile(r'username[:=]\s*([^\s,]+)', re.IGNORECASE)
PASS_RE = re.compile(r'password[:=]\s*([^\s,]+)', re.IGNORECASE)
PORT_WORD_RE = re.compile(r'\bport[:=]?\s*(\d{2,5})', re.IGNORECASE)
PORT_COLON_RE = re.compile(r'(?<!\d):(\d{2,5})')

def geo_lookup(ip):
    # test map first
    if ip in TEST_IP_MAP:
        city, country, lat, lon = TEST_IP_MAP[ip]
        return {"city": city, "country": country, "lat": lat, "lon": lon}
    # local networks -> no geo
    if ip.startswith(("127.","10.","192.168.")):
        return None
    # try GeoLite DB
    if GEO_OK and os.path.exists(GEO_DB):
        try:
            with geoip2.database.Reader(GEO_DB) as r:
                rec = r.city(ip)
                country = rec.country.name or ""
                city = rec.city.name or ""
                lat = rec.location.latitude
                lon = rec.location.longitude
                if lat is None or lon is None:
                    return {"city": city, "country": country, "lat": None, "lon": None}
                return {"city": city, "country": country, "lat": lat, "lon": lon}
        except Exception:
            return None
    return None

def extract_port(text):
    m = PORT_WORD_RE.search(text)
    if m: return m.group(1)
    m2 = PORT_COLON_RE.findall(text)
    if m2:
        # return last colon-number found (heuristic)
        return m2[-1]
    return "-"

def parse_logs():
    entries = []  # list of dicts: {ip, ts, port, user, pass, cmd}
    # creds in cmd_audits.log
    if os.path.exists("cmd_audits.log"):
        with open("cmd_audits.log","r",encoding="utf-8",errors="ignore") as f:
            for line in f:
                ts_m = TS_RE.match(line)
                if ts_m:
                    ts = ts_m.group("ts")
                    body = ts_m.group("body")
                else:
                    ts = "N/A"; body = line.strip()
                ip_m = IP_RE.search(body)
                if not ip_m: continue
                ip = ip_m.group(1)
                user = USER_RE.search(body)
                pw = PASS_RE.search(body)
                port = extract_port(body)
                entries.append({"ip": ip, "ts": ts, "port": port, "user": (user.group(1) if user else "-"), "pass": (pw.group(1) if pw else "-"), "cmd": None})
    # commands in audits.log
    if os.path.exists("audits.log"):
        with open("audits.log","r",encoding="utf-8",errors="ignore") as f:
            for line in f:
                ts_m = TS_RE.match(line)
                if ts_m:
                    ts = ts_m.group("ts")
                    body = ts_m.group("body")
                else:
                    ts = "N/A"; body = line.strip()
                ip_m = IP_RE.search(body)
                if not ip_m: continue
                ip = ip_m.group(1)
                cmd_m = CMD_RE.search(body)
                if cmd_m:
                    cmd = cmd_m.group(1).strip()
                else:
                    # fallback: take trailing text after the IP
                    rest = body[ip_m.end():].strip()
                    cmd = rest if rest else None
                port = extract_port(body)
                entries.append({"ip": ip, "ts": ts, "port": port, "user": "-", "pass":"-", "cmd": cmd})
    return entries

def build_map(entries, out="attacks_map.html"):
    m = folium.Map(location=[20,0], zoom_start=2)
    mc = MarkerCluster().add_to(m)
    added = 0
    for e in entries:
        ip = e["ip"]
        geo = geo_lookup(ip)
        if not geo or geo.get("lat") is None or geo.get("lon") is None:
            continue
        lat, lon = geo["lat"], geo["lon"]
        city = geo.get("city","")
        country = geo.get("country","")
        popup = (f"IP: {ip}<br>Time: {e['ts']}<br>Port: {e['port']}<br>"
                 f"User: {e.get('user','-')} Pass: {e.get('pass','-')}<br>"
                 f"Cmd: {e.get('cmd','-')}<br>Location: {city}, {country}")
        folium.Marker(location=[lat, lon], popup=folium.Popup(popup, max_width=600)).add_to(mc)
        added += 1
    if added == 0:
        # fallback: no geo points; add a center marker telling user
        folium.Marker([0,0], popup="No geo data found; check GeoLite DB or test IP map").add_to(m)
    m.save(out)
    return out

if __name__ == "__main__":
    entries = parse_logs()
    out = build_map(entries, out="attacks_map.html")
    print("Map saved to", out)
