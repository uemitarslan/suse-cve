#!/bin/bash
set -euo pipefail

echo "=== Installing suse-cve ==="

# Install package dependencies (python3-lxml accelerates OVAL XML parsing 10x)
zypper --non-interactive install -y python3 python3-lxml curl sqlite3 jq || true

# Prepare directories
mkdir -p /var/cache/suse-cve /usr/local/bin /etc/cron.daily

# Install CLI binary and daily sync job
install -m 0755 bin/suse-cve /usr/local/bin/suse-cve
install -m 0755 cron/suse-cve-sync /etc/cron.daily/suse-cve-sync

# Configure fixed execution window for SUSE0run-crons
if [ -f /etc/sysconfig/cron ]; then
    sed -i 's/^DAILY_TIME=.*/DAILY_TIME="04:00"/' /etc/sysconfig/cron
fi

# Initial synchronization
echo "Running initial OVAL database sync (this may take 1-2 minutes)..."
/etc/cron.daily/suse-cve-sync

echo "Installation complete. Try: suse-cve 15sp7 CVE-2026-98432 --mitigate"
