#!/bin/bash
set -euo pipefail

echo "=== Installing suse-cve ==="

# Abhängigkeiten installieren
zypper --non-interactive install -y python3 curl sqlite3 jq || true

# Verzeichnisse anlegen
mkdir -p /var/cache/suse-cve /usr/local/bin /etc/cron.daily

# Binaries & Cron kopieren
install -m 0755 bin/suse-cve /usr/local/bin/suse-cve
install -m 0755 cron/suse-cve-sync /etc/cron.daily/suse-cve-sync

# Initiale OVAL-Synchronisation
echo "Running initial OVAL database sync (this may take 1-2 minutes)..."
/etc/cron.daily/suse-cve-sync

echo "Installation complete. Try running: suse-cve 15sp5 CVE-2026-98432"
