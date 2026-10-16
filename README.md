# SentinelGuard

Cross-platform (Fedora Linux + Windows) **24/7 intrusion monitor** that detects
internet-originated attacks, auto-blocks attacker IPs via the OS firewall,
shows popup alerts, and writes an HTML traffic report. Runs automatically at
boot/login with no manual intervention.

## Features

- **Outside-network only detection** — tracks internet (`is_global`) IPs, ignores LAN.
- **New exposed port detection** — alerts only for non-loopback ports that persist 2+ scans (fewer false positives).
- **Port scan / flood detection** — many ports or many connections from one internet IP.
- **Auto-block** — `firewalld`/`iptables` on Fedora, `netsh advfirewall` on Windows.
- **Popup alerts** — tkinter window + native notification; login-session notifier for Fedora Wayland.
- **HTML report** — `report.html` with traffic, listening ports, sessions, suspicious activity; auto-refreshes every 60s.
- **Auto-start** — systemd service (Fedora) / Scheduled Task (Windows).

## Files

| File | Purpose |
| --- | --- |
| `sentinel.py` | Main monitor: detection, auto-block, alerts, report scheduling |
| `sentinel_notify.py` | Login-session popup notifier (Fedora Wayland/GNOME) |
| `sentinel_report.py` | Standalone HTML report generator |
| `sentinel.service` | systemd unit (Fedora, 24/7 + auto-restart) |
| `sentinelguard.desktop` | GNOME autostart entry for the notifier |
| `config.json` | Thresholds and options |
| `install_fedora.sh` | One-command Fedora setup |
| `install_windows.ps1` | One-command Windows setup (Admin) |

## Install — Fedora

```bash
chmod +x sentinel_guard/install_fedora.sh
./sentinel_guard/install_fedora.sh
```

Then log out + log back in for the popup notifier.

## Install — Windows (Administrator)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\sentinel_guard\install_windows.ps1
```

## Configuration (`config.json`)

```json
{
  "check_interval_seconds": 10,
  "alert_cooldown_seconds": 300,
  "max_connections_per_ip": 20,
  "port_scan_threshold": 10,
  "port_scan_window_seconds": 60,
  "exposed_confirm_scans": 2,
  "report_file": "report.html",
  "report_interval_seconds": 60,
  "auto_block": true,
  "allowed_public_ips": [],
  "log_file": "sentinel.log"
}
```

## Reports & logs

- Log (Fedora): `/opt/sentinel_guard/sentinel.log` — Windows: `C:\SentinelGuard\sentinel.log`
- HTML report: `report.html` in the install dir. Generate manually:
  ```bash
  python3 sentinel_report.py --open
  ```
- Journal: `journalctl -u sentinel.service -f`

## Requirements

- Python 3.8+, `psutil`
- Fedora: `firewalld`, `python3-tkinter`, `libnotify`
- Windows: Python added to PATH, Windows Firewall ON

## Disclaimer

This is a defensive monitoring/IDS layer, not a full security suite. Keep the OS
and firewall updated. Auto-block requires root/Administrator.

## License

MIT
