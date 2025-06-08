#!/bin/bash
echo "=== STARTING: Normal Browser Behavior Script ==="
echo "Generating normal browser behavior..."
for i in {1..20}; do
    echo "Browser request $i"
    curl -s -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" \
         http://httpbin.org/ip > /dev/null
    curl -s -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" \
         http://httpbin.org/user-agent > /dev/null
    curl -s -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" \
         https://httpbin.org/headers > /dev/null
    sleep 2
done
echo "=== COMPLETED: Normal Browser Behavior Script ==="
