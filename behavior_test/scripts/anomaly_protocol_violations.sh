#!/bin/bash
echo "=== STARTING: Protocol Violations Anomaly Script ==="
echo "🚨 ANOMALY: Protocol violations and unusual patterns"
# HTTP requests to HTTPS ports
curl -s --max-time 2 http://httpbin.org:443/ 2>/dev/null || true
# HTTPS requests to HTTP ports  
curl -s --max-time 2 -k https://httpbin.org:80/ 2>/dev/null || true
# Unusual user agents
curl -s -A "Botnet/1.0 (Evil)" http://httpbin.org/user-agent 2>/dev/null || true
curl -s -A "Scanner/Exploit" http://httpbin.org/user-agent 2>/dev/null || true
echo "=== COMPLETED: Protocol Violations Anomaly Script ==="
