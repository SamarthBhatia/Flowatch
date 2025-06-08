#!/bin/bash
echo "=== STARTING: High Frequency Connections Anomaly Script ==="
echo "🚨 ANOMALY: High frequency connection pattern"
for i in {1..100}; do
    echo "Rapid connection $i"
    curl -s --max-time 1 http://httpbin.org/ip > /dev/null 2>&1 &
    if [ $((i % 10)) -eq 0 ]; then
        wait  # Prevent too many background processes
    fi
done
wait
echo "=== COMPLETED: High Frequency Connections Anomaly Script ==="
