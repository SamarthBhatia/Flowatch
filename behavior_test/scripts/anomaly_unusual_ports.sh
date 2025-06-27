#!/bin/bash
echo "=== STARTING: Unusual Ports Anomaly Script ==="
echo "🚨 ANOMALY: Unusual port connections"
for port in 31337 6667 1337 8080 9999; do
    echo "Connecting to unusual port $port"
    timeout 2s telnet httpbin.org $port 2>/dev/null || true
    timeout 2s nc -zv httpbin.org $port 2>/dev/null || true
    sleep 1
done
echo "=== COMPLETED: Unusual Ports Anomaly Script ==="
