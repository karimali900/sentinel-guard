#!/bin/bash
# Fix: no popup after reboot on Fedora.
# Root cause: systemd system service runs before login with no access
# to your Wayland/GNOME display, so tkinter/notify-send can't show.
# Fix: keep root service for blocking + add login-session notifier for popups.
set -e
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="/opt/sentinel_guard"
AUTOSTART="$HOME/.config/autostart"

echo "[1/3] Copying notifier to $DEST..."
sudo cp "$SRC_DIR/sentinel_notify.py" "$SRC_DIR/sentinelguard.desktop" "$DEST/" 2>/dev/null || cp "$SRC_DIR/sentinel_notify.py" "$DEST/" 2>/dev/null || true
sudo chmod 644 "$DEST/sentinel_notify.py" "$DEST/sentinelguard.desktop" 2>/dev/null || true

echo "[2/3] Installing login autostart entry..."
mkdir -p "$AUTOSTART"
cp "$SRC_DIR/sentinelguard.desktop" "$AUTOSTART/"
# Point Exec at real location
sed -i "s|Exec=.*|Exec=/usr/bin/python3 $DEST/sentinel_notify.py|" "$AUTOSTART/sentinelguard.desktop"
chmod +x "$AUTOSTART/sentinelguard.desktop" || true

echo "[3/3] Testing popup now (you should see one)..."
python3 "$SRC_DIR/sentinel_notify.py" &
NOTIFY_PID=$!
sleep 4
kill $NOTIFY_PID 2>/dev/null || true

echo ""
echo "Done. Now LOG OUT + LOG BACK IN (or reboot)."
echo "You will get a 'SentinelGuard Active' popup after login."
echo "Root protection still runs at boot: systemctl status sentinel.service"
echo "Notifier autostart file: $AUTOSTART/sentinelguard.desktop"
