#!/usr/bin/env python3
"""
SentinelGuard - Cross-platform (Fedora Linux + Windows) intrusion monitor.
Runs 24/7, auto-starts on boot, auto-detects outside-network intrusions,
auto-blocks attacker IPs, and shows popup alerts. No manual intervention needed.

Detects:
  1. New listening ports (possible backdoor)
  2. High-rate inbound connections from a public IP (port scan / brute force)
  3. Established sessions from internet (outside LAN) hosts
Responds:
  - Popup window (tkinter, built into Python - works on Fedora + Windows)
  - Log to file + console
  - Auto-block IP via OS firewall (firewalld/iptables on Linux, netsh on Windows)

Run: python3 sentinel.py (run as Administrator/root for auto-block)
"""

import ipaddress
import json
import logging
import os
import platform
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    print("Missing dependency: psutil. Install with: pip install -r requirements.txt")
    sys.exit(1)

BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"
DEFAULT_CONFIG = {
    "check_interval_seconds": 10,
    "alert_cooldown_seconds": 300,
    "max_connections_per_ip": 20,
    "port_scan_threshold": 10,
    "port_scan_window_seconds": 60,
    "exposed_confirm_scans": 2,
    "report_file": "report.html",
    "report_interval_seconds": 60,
    "auto_block": True,
    "allowed_public_ips": [],
    "log_file": "sentinel.log",
}

def load_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
            merged = {**DEFAULT_CONFIG, **cfg}
            return merged
        except Exception as e:
            print(f"Config error ({e}), using defaults")
    return dict(DEFAULT_CONFIG)

CONFIG = load_config()

LOG_PATH = BASE_DIR / CONFIG.get("log_file", "sentinel.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("SentinelGuard")

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# ---- state ----
last_alert_time: dict[str, float] = {}
connection_history: dict[str, deque] = defaultdict(deque)  # ip -> deque[timestamps]
blocked_ips: set[str] = set()
baseline_exposed: set[int] | None = None
pending_exposed: dict[int, int] = {}  # port -> consecutive scans seen (needs 2+ to alert)


def is_public_ip(ip_str: str) -> bool:
    """True if IP comes from outside the local network (internet)."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])  # strip IPv6 zone index
        return ip.is_global and not ip.is_multicast and not ip.is_reserved
    except ValueError:
        return False


def is_loopback_bind(ip_str: str) -> bool:
    """True if a LISTEN socket is bound to localhost only (not reachable externally)."""
    try:
        return ipaddress.ip_address(ip_str.split("%")[0]).is_loopback
    except ValueError:
        return False


def popup_alert(title: str, message: str):
    """Cross-platform popup. Threaded so monitoring never blocks."""
    def _show():
        # Headless service (systemd, no display): skip tkinter silently,
        # it can never work there. Login-session notifier shows popups.
        if IS_LINUX and not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            fallback_notify(title, message)
            return
        try:
            import tkinter as tk
            root = tk.Tk()
            root.title(title)
            root.attributes("-topmost", True)
            root.geometry("480x220")
            root.resizable(False, False)
            tk.Label(root, text=title, font=("Segoe UI", 13, "bold"), fg="red").pack(pady=10)
            tk.Label(root, text=message, font=("Segoe UI", 10), wraplength=440,
                     justify="left").pack(pady=10, padx=15)
            tk.Button(root, text="OK / Acknowledge", command=root.destroy,
                      width=20, bg="#d32f2f", fg="white").pack(pady=10)
            # Auto-close after 60s so unattended 24/7 mode doesn't pile up windows
            root.after(60000, root.destroy)
            root.mainloop()
        except Exception as e:
            logger.debug(f"tkinter popup skipped ({e}), using fallback")
            fallback_notify(title, message)

    t = threading.Thread(target=_show, daemon=True)
    t.start()

    # Also try native OS notification so alert is visible even without focus
    try:
        fallback_notify(title, message)
    except Exception:
        pass


def fallback_notify(title: str, message: str):
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x40 | 0x1000)
        except Exception:
            pass
    elif IS_LINUX:
        try:
            subprocess.run(["notify-send", title, message], timeout=5,
                           capture_output=True)
        except Exception:
            pass


def should_alert(key: str) -> bool:
    now = time.time()
    cooldown = CONFIG["alert_cooldown_seconds"]
    if now - last_alert_time.get(key, 0) >= cooldown:
        last_alert_time[key] = now
        return True
    return False


def alert(title: str, message: str, key: str):
    full = f"{title}: {message}"
    logger.warning(full)
    if should_alert(key):
        popup_alert(title, f"{datetime.now():%Y-%m-%d %H:%M:%S}\n{message}")


def block_ip(ip: str):
    if ip in blocked_ips or ip in CONFIG.get("allowed_public_ips", []):
        return
    if not CONFIG.get("auto_block", True):
        logger.info(f"Auto-block disabled, would have blocked {ip}")
        return
    try:
        if IS_WINDOWS:
            rule = f"SentinelGuard_Block_{ip.replace('.', '_').replace(':', '_')}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule}", "dir=in", "action=block", f"remoteip={ip}"],
                capture_output=True, timeout=15, check=False,
            )
        elif IS_LINUX:
            # Prefer firewalld, fall back to iptables
            r = subprocess.run(["which", "firewall-cmd"], capture_output=True, timeout=5)
            if r.returncode == 0:
                subprocess.run(
                    ["firewall-cmd", "--permanent",
                     f"--add-rich-rule=rule family=ipv4 source address={ip} reject"],
                    capture_output=True, timeout=15, check=False,
                )
                subprocess.run(["firewall-cmd", "--reload"],
                               capture_output=True, timeout=30, check=False)
            else:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=15, check=False,
                )
        blocked_ips.add(ip)
        logger.info(f"Auto-blocked {ip} via OS firewall")
    except Exception as e:
        logger.error(f"Failed to block {ip}: {e}")


def check_firewall_active():
    """Verify OS firewall is on; warn loudly if not."""
    try:
        if IS_WINDOWS:
            r = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"],
                               capture_output=True, text=True, timeout=15)
            if "OFF" in r.stdout.upper():
                alert("Firewall OFF",
                      "Windows Firewall is OFF. SentinelGuard needs it ON.\n"
                      "Enable it: Windows Security > Firewall > Turn On.",
                      key="firewall_off")
            else:
                logger.info("Windows Firewall profiles checked: ON")
        elif IS_LINUX:
            r = subprocess.run(["systemctl", "is-active", "firewalld"],
                               capture_output=True, text=True, timeout=10)
            if r.stdout.strip() != "active":
                # Check ufw as alternative
                u = subprocess.run(["ufw", "status"], capture_output=True,
                                   text=True, timeout=10)
                if "active" not in u.stdout.lower():
                    alert("Firewall OFF",
                          "No active firewall detected (firewalld/ufw).\n"
                          "Run: sudo systemctl enable --now firewalld",
                          key="firewall_off")
                else:
                    logger.info("ufw firewall active")
            else:
                logger.info("firewalld active")
    except Exception as e:
        logger.warning(f"Firewall check skipped: {e}")


def scan_once():
    global baseline_exposed
    now = time.time()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        logger.error("Cannot read connections (need admin/root). Retrying...")
        return

    exposed_ports: set[int] = set()  # bound to non-loopback = reachable
    loopback_ports: set[int] = set()  # 127.0.0.1/::1 only = ignored for alerts
    port_binds: dict[int, set[str]] = defaultdict(set)  # port -> bind addrs (for report)
    inbound_from_public: dict[str, int] = defaultdict(int)
    public_hits: dict[str, set[int]] = defaultdict(set)  # ip -> set of local ports touched

    for c in conns:
        try:
            if c.status == "LISTEN" and c.laddr:
                lip = c.laddr.ip
                port_binds[c.laddr.port].add(lip)
                if is_loopback_bind(lip):
                    loopback_ports.add(c.laddr.port)
                else:
                    exposed_ports.add(c.laddr.port)
            if c.raddr:
                rip = c.raddr.ip
                if is_public_ip(rip) and c.laddr:
                    inbound_from_public[rip] += 1
                    public_hits[rip].add(c.laddr.port)
                    connection_history[rip].append(now)
        except Exception:
            continue

    # 1. New EXPOSED listening port detection (2+ consecutive scans to confirm).
    # Loopback-only ports are ignored: they are not reachable from the network.
    required = int(CONFIG.get("exposed_confirm_scans", 2))
    if baseline_exposed is None:
        baseline_exposed = set(exposed_ports)
        pending_exposed.clear()
        logger.info(f"Baseline exposed ports: {sorted(baseline_exposed)} "
                    f"(ignored {len(loopback_ports)} loopback-only)")
    else:
        for port in exposed_ports - baseline_exposed:
            pending_exposed[port] = pending_exposed.get(port, 0) + 1
        # Transient ports that vanished before confirmation: drop silently
        for port in list(pending_exposed):
            if port not in exposed_ports:
                logger.info(f"Transient port {port} vanished before confirm, ignoring")
                del pending_exposed[port]
        confirmed = sorted(p for p, n in pending_exposed.items() if n >= required)
        if confirmed:
            details = ", ".join(
                f"{p} ({','.join(sorted(port_binds.get(p, [])))})" for p in confirmed
            )
            alert("Suspicious listening port",
                  f"New EXPOSED port(s) persisting {required}x scans: {details}\n"
                  f"Possible backdoor. If you didn't open these, investigate now.",
                  key=f"newport_{confirmed}")
            baseline_exposed.update(confirmed)
            for p in confirmed:
                pending_exposed.pop(p, None)
        # Ports that closed: drop from baseline so a later reopen re-confirms
        for port in list(baseline_exposed - exposed_ports):
            baseline_exposed.discard(port)
            pending_exposed.pop(port, None)
            logger.info(f"Port {port} closed, removed from baseline")

    # 2. Flood / brute-force: too many simultaneous inbound from one public IP
    for ip, count in inbound_from_public.items():
        # prune old history
        window = CONFIG["port_scan_window_seconds"]
        hist = connection_history[ip]
        while hist and now - hist[0] > window:
            hist.popleft()
        if count >= CONFIG["max_connections_per_ip"]:
            alert("Possible attack - connection flood",
                  f"{count} inbound connections from internet IP {ip}\n"
                  f"Auto-blocking this IP.",
                  key=f"flood_{ip}")
            block_ip(ip)

        # 3. Port scan: one IP touching many distinct local ports
        if len(public_hits[ip]) >= CONFIG["port_scan_threshold"]:
            alert("Possible port scan",
                  f"Internet IP {ip} probed {len(public_hits[ip])} ports: "
                  f"{sorted(list(public_hits[ip]))[:15]}\nAuto-blocking.",
                  key=f"scan_{ip}")
            block_ip(ip)
            connection_history[ip].clear()


def write_report():
    """Regenerate HTML report (traffic + suspicious activity). Never raises."""
    try:
        from sentinel_report import generate_report
        out = generate_report(BASE_DIR / CONFIG.get("report_file", "report.html"),
                              LOG_PATH)
        logger.debug(f"Report updated: {out}")
    except Exception as e:
        logger.debug(f"Report skipped: {e}")


def main():
    logger.info(f"SentinelGuard starting on {platform.system()} {platform.release()} "
                f"(auto-block={'ON' if CONFIG.get('auto_block') else 'OFF'})")
    check_firewall_active()
    popup_alert("SentinelGuard Active",
                "24/7 intrusion monitor is running.\n"
                "You will get a popup if an internet attack is detected.")
    write_report()
    last_report = time.time()
    while True:
        try:
            scan_once()
            if time.time() - last_report >= CONFIG.get("report_interval_seconds", 60):
                write_report()
                last_report = time.time()
        except Exception as e:
            logger.exception(f"Scan error: {e}")
        time.sleep(CONFIG["check_interval_seconds"])


if __name__ == "__main__":
    main()
