#!/bin/bash
set -euo pipefail

echo "=== Installing suse-cve ==="

# Paketabhängigkeiten installieren (python3-lxml beschleunigt OVAL-Parsing um das Zehnfache)
zypper --non-interactive install -y python3 python3-lxml curl sqlite3 jq || true

# Verzeichnisse vorbereiten
mkdir -p /var/cache/suse-cve /usr/local/bin /etc/cron.daily

# Binaries & Cron installieren
install -m 0755 bin/suse-cve /usr/local/bin/suse-cve
install -m 0755 cron/suse-cve-sync /etc/cron.daily/suse-cve-sync

# Feste Ausführungszeit für SUSE run-crons konfigurieren
if [ -f /etc/sysconfig/cron ]; then
    sed -i 's/^DAILY_TIME=.*/DAILY_TIME="04:00"/' /etc/sysconfig/cron
fi

# Initiale Synchronisation
echo "Running initial OVAL database sync (this may take 1-2 minutes)..."
/etc/cron.daily/suse-cve-sync

echo "Installation complete. Try: suse-cve 15sp5 CVE-2026-98432"
