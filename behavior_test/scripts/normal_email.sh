#!/bin/bash
echo "=== STARTING: Normal Email Client Behavior Script ==="
echo "Generating normal email client behavior..."
for i in {1..15}; do
    echo "Email check $i"
    # Simulate IMAP connections
    timeout 2s telnet imap.gmail.com 993 2>/dev/null || true
    timeout 2s telnet smtp.gmail.com 587 2>/dev/null || true
    sleep 3
done
echo "=== COMPLETED: Normal Email Client Behavior Script ==="
