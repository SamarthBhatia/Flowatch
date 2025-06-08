#!/bin/bash
echo "=== STARTING: Geographic Anomalies Anomaly Script ==="
echo "🚨 ANOMALY: Unusual geographic patterns"
# These are simulated since we can't actually connect to different countries
# But the firewall will log the attempted connections
FOREIGN_IPS=(
    "8.8.8.8"      # Google DNS (US)
    "1.1.1.1"      # Cloudflare (US)
    "208.67.222.222" # OpenDNS (US)
)

for ip in "${FOREIGN_IPS[@]}"; do
    echo "Connecting to foreign IP: $ip"
    timeout 2s telnet $ip 80 2>/dev/null || true
    ping -c 1 $ip 2>/dev/null || true
    sleep 1
done
echo "=== COMPLETED: Geographic Anomalies Anomaly Script ==="
