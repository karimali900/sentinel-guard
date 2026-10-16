#!/usr/bin/env python3
"""
SentinelGuard HTML report - network traffic + suspicious activity.
Cross-platform (Fedora + Windows), stdlib + psutil only.

Generates report.html next to this file:
  python3 sentinel_report.py           -> write report.html
  python3 sentinel_report.py --open    -> write + open in browser

Called automatically by sentinel.py every report_interval_seconds.
"""
import datetime
import html
import ipaddress
import platform
import socket
import sys
from pathlib import Path

try:
    import psutil
except ImportError:
    print("Missing dependency: psutil. Install with: pip install -r requirements.txt")
    sys.exit(1)

BASE_DIR = Path(__file__).parent
LOG_PATH = BASE_DIR / "sentinel.log"
REPORT_PATH = BASE_DIR / "report.html"


def classify_ip(ip_str: str) -> str:
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
        if ip.is_loopback:
            return "loopback"
        if ip.is_private:
            return "LAN"
        if ip.is_global and not ip.is_multicast and not ip.is_reserved:
            return "INTERNET"
        return "other"
    except ValueError:
        return "invalid"


def proc_name(pid) -> str:
    try:
        if not pid:
            return "-"
        return psutil.Process(pid).name()
    except Exception:
        return "?"


def read_alerts(log_path: Path, limit: int = 100):
    """Parse WARNING lines (suspicious activity) + blocked IPs from log."""
    alerts, blocked = [], []
    if not log_path.exists():
        return alerts, blocked
    try:
        with open(log_path, errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return alerts, blocked
    for line in lines:
        if "WARNING" in line or "Auto-blocked" in line or "attack" in line.lower() \
                or "Suspicious" in line or "Firewall OFF" in line:
            alerts.append(line.strip())
        if "Auto-blocked" in line:
            # "... Auto-blocked 1.2.3.4 via ..."
            for tok in line.replace(",", " ").split():
                try:
                    ipaddress.ip_address(tok)
                    if tok not in blocked:
                        blocked.append(tok)
                    break
                except ValueError:
                    continue
    return alerts[-limit:], blocked


def collect():
    conns = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        conns = [f"ERROR: {e}"]

    listening, established, other = [], [], []
    for c in conns if isinstance(conns, list) else []:
        try:
            if isinstance(c, str):
                continue
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            cls = classify_ip(c.raddr.ip) if c.raddr else "-"
            row = {
                "proto": "TCPv6" if getattr(c, "family", 0) == socket.AF_INET6 else "TCP/UDP",
                "status": c.status,
                "local": laddr,
                "remote": raddr,
                "class": cls,
                "pid": c.pid or "-",
                "proc": proc_name(c.pid),
            }
            if c.status == "LISTEN":
                # exposed = bound off-localhost
                try:
                    loop = ipaddress.ip_address(c.laddr.ip.split("%")[0]).is_loopback
                except ValueError:
                    loop = False
                row["class"] = "loopback-only" if loop else "EXPOSED"
                listening.append(row)
            elif c.status == "ESTABLISHED":
                established.append(row)
            else:
                other.append(row)
        except Exception:
            continue

    try:
        io = psutil.net_io_counters()
        io_data = {"sent_mb": round(io.bytes_sent / 1048576, 1),
                   "recv_mb": round(io.bytes_recv / 1048576, 1),
                   "packets_sent": io.packets_sent,
                   "packets_recv": io.packets_recv}
    except Exception:
        io_data = {}

    alerts, blocked = read_alerts(LOG_PATH)
    internet_est = [r for r in established if r["class"] == "INTERNET"]
    return {
        "now": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "io": io_data,
        "listening": sorted(listening, key=lambda r: r["local"]),
        "established": sorted(established, key=lambda r: (r["class"], r["remote"])),
        "other": other,
        "alerts": alerts,
        "blocked": blocked,
        "internet_est": internet_est,
    }


def rows_html(rows, cols):
    out = []
    for r in rows:
        tds = "".join(f"<td>{html.escape(str(r.get(c, '-')))}</td>" for c in cols)
        danger = " class='danger'" if r.get("class") == "INTERNET" or r.get("class") == "EXPOSED" else ""
        out.append(f"<tr{danger}>{tds}</tr>")
    return "\n".join(out) or "<tr><td colspan='7'>none</td></tr>"


def generate_report(output: Path = REPORT_PATH, log_path: Path = LOG_PATH) -> Path:
    global LOG_PATH
    LOG_PATH = log_path
    d = collect()
    alerts_html = "<br>".join(html.escape(a) for a in reversed(d["alerts"])) or "No suspicious activity logged."
    n_alert = len(d["alerts"])
    status = "🔴 ATTENTION" if (n_alert or d["internet_est"] or d["blocked"]) else "🟢 OK"
    # plain ascii fallback safe: keep emoji (browsers handle it)
    listening_rows = rows_html(d["listening"], ["proto", "local", "class", "pid", "proc"])
    est_rows = rows_html(d["established"], ["proto", "status", "local", "remote", "class", "pid", "proc"])
    io = d["io"]
    html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="60">
<title>SentinelGuard Report - {html.escape(d['host'])}</title>
<style>
body{{font-family:Segoe UI,Cantarell,Arial,sans-serif;margin:20px;background:#f5f5f5;color:#222}}
.card{{background:#fff;border-radius:8px;padding:16px;margin-bottom:16px;box-shadow:0 1px 3px #0002}}
h1{{margin:0 0 4px}} .muted{{color:#666;font-size:13px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left}}
th{{background:#263238;color:#fff}} tr.danger{{background:#ffebee}}
.badge{{display:inline-block;padding:4px 12px;border-radius:12px;font-weight:bold}}
.ok{{background:#c8e6c9}} .warn{{background:#ffcdd2}}
pre.alerts{{background:#111;color:#ffccbc;padding:12px;border-radius:6px;max-height:300px;overflow:auto;font-size:12px;white-space:pre-wrap}}
a{{color:#1565c0}}
</style></head><body>
<h1>SentinelGuard Report</h1>
<div class="muted">{html.escape(d['now'])} &bull; {html.escape(d['host'])} &bull; {html.escape(d['os'])} &bull; auto-refresh 60s</div>
<p><span class="badge {'warn' if n_alert or d['internet_est'] or d['blocked'] else 'ok'}">{status}</span></p>

<div class="card"><h2>Summary</h2>
<table><tr><th>Metric</th><th>Value</th></tr>
<tr><td>Suspicious events in log</td><td>{n_alert}</td></tr>
<tr><td>Blocked IPs</td><td>{html.escape(', '.join(d['blocked']) or 'none')}</td></tr>
<tr><td>Listening ports (exposed / loopback-only)</td><td>{sum(1 for r in d['listening'] if r['class']=='EXPOSED')} / {sum(1 for r in d['listening'] if r['class']!='EXPOSED')}</td></tr>
<tr><td>Established sessions (INTERNET / LAN / other)</td><td>{sum(1 for r in d['established'] if r['class']=='INTERNET')} / {sum(1 for r in d['established'] if r['class']=='LAN')} / {sum(1 for r in d['established'] if r['class'] not in ('INTERNET','LAN'))}</td></tr>
<tr><td>Traffic sent / received</td><td>{io.get('sent_mb','?')} MB / {io.get('recv_mb','?')} MB</td></tr>
<tr><td>Packets sent / received</td><td>{io.get('packets_sent','?')} / {io.get('packets_recv','?')}</td></tr>
</table></div>

<div class="card"><h2>Suspicious activity (latest {len(d['alerts'])})</h2>
<pre class="alerts">{alerts_html}</pre>
<div class="muted">Source: {html.escape(str(log_path))}. Internet sessions and exposed ports are highlighted red below.</div></div>

<div class="card"><h2>Listening ports</h2>
<table><tr><th>Proto</th><th>Local</th><th>Exposure</th><th>PID</th><th>Process</th></tr>
{listening_rows}</table>
<div class="muted">loopback-only = reachable from this PC only (ignored by alerts). EXPOSED = reachable from network (alerts after 2 scans).</div></div>

<div class="card"><h2>Established connections</h2>
<table><tr><th>Proto</th><th>Status</th><th>Local</th><th>Remote</th><th>Class</th><th>PID</th><th>Process</th></tr>
{est_rows}</table>
<div class="muted">INTERNET = outside your LAN (internet). LAN = 192.168.x / 10.x / 172.16.x.</div></div>

</body></html>"""
    output.write_text(html_doc)
    return output


if __name__ == "__main__":
    out = generate_report()
    print(f"Report written: {out}")
    if "--open" in sys.argv:
        import webbrowser
        webbrowser.open(out.as_uri())
