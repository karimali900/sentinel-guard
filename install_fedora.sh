#!/bin/bash
# Fedora auto-install: sets up SentinelGuard to run 24/7 with zero manual intervention
set -e
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="/opt/sentinel_guard"

echo "[1/5] Installing dependencies..."
sudo dnf install -y python3 python3-pip firewalld python3-tkinter libnotify 2>/dev/null || sudo yum install -y python3 python3-pip firewalld python3-tkinter libnotify
pip3 install --user -r "$SRC_DIR/requirements.txt" || sudo pip3 install -r "$SRC_DIR/requirements.txt"

echo "[2/5] Copying files to $DEST..."
sudo mkdir -p "$DEST"
sudo cp "$SRC_DIR/sentinel.py" "$SRC_DIR/sentinel_notify.py" "$SRC_DIR/sentinel_report.py" "$SRC_DIR/sentinelguard.desktop" "$SRC_DIR/config.json" "$DEST/"
sudo chmod 700 "$DEST/sentinel.py"

echo "[3/4] Enabling firewall..."
sudo systemctl enable --now firewalld || true

echo "[4/5] Installing systemd service for 24/7 autostart..."
sudo cp "$SRC_DIR/sentinel.service" /etc/systemd/system/
# Auto-fix ExecStart path
sudo sed -i "s|ExecStart=.*|ExecStart=/usr/bin/python3 $DEST/sentinel.py|" /etc/systemd/system/sentinel.service
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel.service

echo "[5/5] Installing login-session popup notifier (required on Wayland/GNOME)..."
mkdir -p "$HOME/.config/autostart"
cp "$SRC_DIR/sentinelguard.desktop" "$HOME/.config/autostart/"
sed -i "s|Exec=.*|Exec=/usr/bin/python3 $DEST/sentinel_notify.py|" "$HOME/.config/autostart/sentinelguard.desktop"

echo ""
echo "Done. SentinelGuard is RUNNING and will auto-start on every boot."
echo "Protection service: sudo systemctl status sentinel.service"
echo "Popup notifier: $HOME/.config/autostart/sentinelguard.desktop (shows after login)"
echo "IMPORTANT: log out + log back in to see the 'SentinelGuard Active' popup."
