#!/bin/bash
echo "=== STARTING: Normal System Updates Behavior Script ==="
echo "Generating normal system update behavior..."
for i in {1..10}; do
    echo "Update check $i"
    curl -s http://httpbin.org/status/200 > /dev/null
    curl -s https://httpbin.org/json > /dev/null
    sleep 4
done
echo "=== COMPLETED: Normal System Updates Behavior Script ==="
