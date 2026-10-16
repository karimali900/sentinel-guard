#!/usr/bin/env python3
"""
SentinelGuard GUI notifier - runs in YOUR login session (not as root service).
Watches the system-service log and shows popup windows for alerts.
This is required on Fedora because a systemd system service cannot
access your Wayland/GNOME display by design.
"""
import subprocess
import time
from pathlib import Path

LOG_CANDIDATES = [
    Path("/opt/sentinel_guard/sentinel.log"),
    Path(__file__).parent / "sentinel.log",
]

def popup(title: str, message: str):
    try:
        import tkinter as tk
        root = tk.Tk()
        root.title(title)
        root.attributes("-topmost", True)
        root.geometry("480x220")
        root.resizable(False, False)
        tk.Label(root, text=title, font=("Cantarell", 13, "bold"), fg="red").pack(pady=10)
        tk.Label(root, text=message, font=("Cantarell", 10),
                 wraplength=440, justify="left").pack(pady=10, padx=15)
        tk.Button(root, text="OK / Acknowledge", command=root.destroy,
                  width=20).pack(pady=10)
        root.after(60000, root.destroy)
        root.mainloop()
    except Exception as e:
        print(f"tkinter failed: {e}")
        try:
            subprocess.run(["notify-send", title, message], timeout=5)
        except Exception:
            pass

def find_log() -> Path | None:
    for p in LOG_CANDIDATES:
        if p.exists():
            return p
    return None

def main():
    popup("SentinelGuard Active",
          "24/7 monitor is running.\nYou will get a popup here if an internet attack is detected.")
    try:
        subprocess.run(["notify-send", "SentinelGuard Active",
                        "24/7 monitor running - popups enabled for this login."],
                       timeout=5)
    except Exception:
        pass

    log = find_log()
    if log is None:
        popup("SentinelGuard - no log found",
              f"Could not find sentinel.log in:\n{[str(p) for p in LOG_CANDIDATES]}\n"
              f"Protection service may not be running.\nRun: systemctl status sentinel.service")
        return

    print(f"Watching {log} for alerts...")
    pos = log.stat().st_size  # only new alerts after login, no backlog spam
    while True:
        try:
            size = log.stat().st_size
            if size < pos:  # log rotated
                pos = 0
            if size > pos:
                with open(log) as f:
                    f.seek(pos)
                    for line in f:
                        if "WARNING" in line or "attack" in line.lower() \
                           or "Suspicious" in line or "Firewall OFF" in line:
                            msg = line.strip()[-800:]  # keep popup readable
                            popup("SentinelGuard ALERT", msg)
                            try:
                                subprocess.run(
                                    ["notify-send", "SentinelGuard ALERT", msg],
                                    timeout=5)
                            except Exception:
                                pass
                pos = size
        except Exception as e:
            print(f"watch error: {e}")
        time.sleep(3)

if __name__ == "__main__":
    main()
