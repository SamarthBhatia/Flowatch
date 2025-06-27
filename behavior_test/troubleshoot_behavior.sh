#!/bin/bash

echo "🔍 BEHAVIOR ANALYSIS TROUBLESHOOTING"
echo "===================================="
echo ""

# Check if firewall is actually running
echo "1. CHECKING FIREWALL STATUS"
echo "----------------------------"
echo "Checking if firewall process is running..."
ps aux | grep -v grep | grep firewall || echo "❌ No firewall process found!"

echo ""
echo "Testing firewall response..."
if ../build/firewall status > /dev/null 2>&1; then
    echo "✅ Firewall responds to commands"
    ../build/firewall status
else
    echo "❌ Firewall not responding to status command"
    echo ""
    echo "🚨 SOLUTION: Start firewall in another terminal:"
    echo "   sudo ../build/firewall start"
    echo ""
    echo "Or if already running, check if it's hanging:"
    echo "   sudo pkill -f firewall"
    echo "   sudo ../build/firewall start"
    exit 1
fi

echo ""
echo "2. CHECKING CONFIGURATION"
echo "-------------------------"
CONFIG_DIR="$HOME/.config/firewall"
CONFIG_FILE="$CONFIG_DIR/config.json"

echo "Config directory: $CONFIG_DIR"
if [ -d "$CONFIG_DIR" ]; then
    echo "✅ Config directory exists"
    ls -la "$CONFIG_DIR"
else
    echo "❌ Config directory missing - creating it..."
    mkdir -p "$CONFIG_DIR"
fi

echo ""
echo "Config file: $CONFIG_FILE"
if [ -f "$CONFIG_FILE" ]; then
    echo "✅ Config file exists"
    echo "Behavior monitoring enabled:"
    grep -i "enable_behavior_monitoring" "$CONFIG_FILE" || echo "  Not found in config"
else
    echo "❌ Config file missing - firewall should create this"
fi

echo ""
echo "3. CHECKING BEHAVIOR PROFILES LOCATION"
echo "--------------------------------------"
PROFILES_FILE="$CONFIG_DIR/behavior_profiles.json"
echo "Expected profiles file: $PROFILES_FILE"

if [ -f "$PROFILES_FILE" ]; then
    echo "✅ Behavior profiles file exists!"
    echo "File size: $(wc -c < "$PROFILES_FILE") bytes"
    echo "Content preview:"
    head -10 "$PROFILES_FILE"
else
    echo "❌ Behavior profiles file doesn't exist yet"
    echo ""
    echo "This means either:"
    echo "  1. Firewall isn't running"
    echo "  2. Behavior monitoring is disabled"
    echo "  3. No network traffic has been processed yet"
    echo "  4. Not enough time has passed for profile creation"
fi

echo ""
echo "4. CHECKING NETWORK ACTIVITY"
echo "----------------------------"
echo "Recent curl processes (from our test scripts):"
ps aux | grep -v grep | grep curl || echo "No curl processes running"

echo ""
echo "Network connections from our test IPs:"
netstat -an | grep "httpbin.org\|gmail.com" | head -5 || echo "No connections to test hosts found"

echo ""
echo "5. TESTING MANUAL BEHAVIOR MONITORING"
echo "-------------------------------------"
echo "Let's manually enable behavior monitoring and generate some traffic..."

# Test if firewall accepts config commands
echo "Setting behavior monitoring config..."
if ../build/firewall config enable_behavior_monitoring true 2>/dev/null; then
    echo "✅ Successfully set behavior monitoring config"
else
    echo "❌ Failed to set config - firewall may not be running interactively"
fi

echo ""
echo "6. MANUAL PROFILE CHECK"
echo "----------------------"
echo "Generating a quick test connection to trigger profile creation..."
curl -s http://httpbin.org/ip > /dev/null &
sleep 2

echo "Checking again for profiles file..."
if [ -f "$PROFILES_FILE" ]; then
    echo "✅ Profiles file created!"
    cat "$PROFILES_FILE"
else
    echo "❌ Still no profiles file"
    echo ""
    echo "🔧 DEBUGGING STEPS:"
    echo ""
    echo "A. Check if firewall is actually monitoring packets:"
    echo "   In firewall terminal, you should see:"
    echo "   'Packet #N received' messages"
    echo "   'TCP Connection: IP:PORT -> IP:PORT' logs"
    echo ""
    echo "B. Check firewall logs for errors:"
    echo "   tail -f /var/log/system.log | grep firewall"
    echo "   OR check current directory for firewall.log"
    echo ""
    echo "C. Try manual behavior trigger:"
    echo "   ../build/firewall config behavior_learning_period 1"
    echo "   ../build/firewall config enable_behavior_monitoring true"
    echo ""
    echo "D. Check interface configuration:"
    echo "   ../build/firewall config interface en0"
    echo "   (or try eth0, wlan0 depending on your system)"
fi

echo ""
echo "7. QUICK FIX PROCEDURE"
echo "====================="
echo ""
echo "If behavior monitoring isn't working, try this:"
echo ""
echo "Step 1: Stop current firewall"
echo "  sudo pkill -f firewall"
echo ""
echo "Step 2: Start firewall with explicit config"
echo "  sudo ../build/firewall start"
echo ""
echo "Step 3: In firewall interactive mode, run:"
echo "  config enable_behavior_monitoring true"
echo "  config behavior_learning_period 1"
echo "  config log_level debug"
echo "  status"
echo ""
echo "Step 4: Generate traffic and monitor:"
echo "  curl http://httpbin.org/ip"
echo "  (should see logs about packet processing)"
echo ""
echo "Step 5: Wait 2 minutes then check:"
echo "  ls -la ~/.config/firewall/"
echo "  cat ~/.config/firewall/behavior_profiles.json"
echo ""

echo "8. ALTERNATIVE TESTING METHOD"
echo "============================="
echo ""
echo "If behavior profiles still don't appear, test without profiles:"
echo ""
echo "A. Test basic anomaly detection:"
echo "   ./scripts/anomaly_unusual_ports.sh"
echo "   (should see 'Blocked connection' or 'Rule evaluation' in logs)"
echo ""
echo "B. Test rule-based detection:"
echo "   ../build/firewall add-rule curl block httpbin.org 80"
echo "   curl http://httpbin.org/ip"
echo "   (should be blocked and logged)"
echo ""
echo "C. Check traffic statistics:"
echo "   ../build/firewall status"
echo "   (should show packet counts and connection stats)"
echo ""

echo "🎯 EXPECTED BEHAVIOR"
echo "==================="
echo ""
echo "When working correctly, you should see:"
echo "✅ Firewall responds to commands"
echo "✅ Config directory and files exist"
echo "✅ Packet processing logs appear"
echo "✅ behavior_profiles.json gets created"
echo "✅ Profiles show applications and connections"
echo "✅ profileComplete becomes true after learning period"
echo ""
echo "If you don't see these, the issue is likely:"
echo "• Firewall not running with proper permissions (need sudo)"
echo "• Wrong network interface selected"
echo "• Behavior monitoring disabled in code"
echo "• Insufficient time for profile creation"
echo ""

echo "Run this troubleshooting script again after making changes!"
