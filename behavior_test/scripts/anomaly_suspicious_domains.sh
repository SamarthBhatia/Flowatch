#!/bin/bash
echo "=== STARTING: Suspicious Domains Anomaly Script ==="
echo "🚨 ANOMALY: Suspicious domain connections"
SUSPICIOUS_DOMAINS=(
    "malware-test.example.com"
    "phishing-site.test"
    "command-control.evil"
    "bot.net.test"
    "suspicious.domain.test"
)

for domain in "${SUSPICIOUS_DOMAINS[@]}"; do
    echo "Attempting connection to $domain"
    curl -s --connect-timeout 2 "http://$domain" 2>/dev/null || true
    nslookup "$domain" 2>/dev/null || true
    sleep 1
done
echo "=== COMPLETED: Suspicious Domains Anomaly Script ==="
