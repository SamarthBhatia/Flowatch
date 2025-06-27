#!/bin/bash

echo "=== STARTING: Automated Behavior Analysis Test Script ==="
echo "🧠 AUTOMATED BEHAVIOR ANALYSIS TEST"
echo "==================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

FIREWALL="../build/firewall"
PROFILE_FILE="$HOME/.config/firewall/behavior_profiles.json"
LOG_FILE="behavior_test.log"

echo -e "${BLUE}Starting automated behavior analysis test...${NC}"
echo ""

# Function to check if profiles exist and are learning
check_learning_status() {
    if [ -f "$PROFILE_FILE" ]; then
        local profile_count=$(grep -o '"[^"]*":' "$PROFILE_FILE" | wc -l 2>/dev/null || echo "0")
        local complete_count=$(grep -o '"profileComplete":true' "$PROFILE_FILE" | wc -l 2>/dev/null || echo "0")
        echo "Profiles: $profile_count, Complete: $complete_count"
        [ "$complete_count" -gt 0 ]
    else
        echo "No profile file found yet"
        return 1
    fi
}

# Function to run anomaly test and check for detection
test_anomaly() {
    local test_name="$1"
    local script_name="$2"
    
    echo -e "${YELLOW}Testing: $test_name${NC}"
    
    # Run the anomaly script
    if [ -f "scripts/$script_name" ]; then
        ./scripts/$script_name > "$LOG_FILE" 2>&1
        
        # Give firewall time to process
        sleep 5
        
        # Check for anomaly detection in logs
        if grep -qi "abnormal\|anomal\|unusual\|suspicious" "$LOG_FILE" 2>/dev/null; then
            echo -e "${GREEN}✅ Anomaly detected for: $test_name${NC}"
            return 0
        else
            echo -e "${RED}❌ No anomaly detection for: $test_name${NC}"
            return 1
        fi
    else
        echo -e "${RED}❌ Script not found: scripts/$script_name${NC}"
        return 1
    fi
}

echo "Phase 1: Checking firewall status..."
if ! $FIREWALL status > /dev/null 2>&1; then
    echo -e "${RED}❌ Firewall not responding. Start with: sudo $FIREWALL start${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Firewall is running${NC}"

echo ""
echo "Phase 2: Generating baseline behavior..."
echo "Run these in background for 5 minutes:"
echo "./scripts/normal_browser.sh &"
echo "./scripts/normal_email.sh &"
echo "./scripts/normal_updates.sh &"

# Wait for user confirmation
echo ""
echo -e "${YELLOW}Press Enter when baseline behavior has been running for 5+ minutes...${NC}"
read

echo ""
echo "Phase 3: Checking learning status..."
if check_learning_status; then
    echo -e "${GREEN}✅ Behavior profiles are ready for testing${NC}"
else
    echo -e "${YELLOW}⚠️  Profiles still learning. Continuing anyway...${NC}"
fi

echo ""
echo "Phase 4: Running anomaly tests..."

# Test each anomaly type
TESTS_PASSED=0
TOTAL_TESTS=5

test_anomaly "Unusual Ports" "anomaly_unusual_ports.sh" && ((TESTS_PASSED++))
test_anomaly "Suspicious Domains" "anomaly_suspicious_domains.sh" && ((TESTS_PASSED++))
test_anomaly "High Frequency" "anomaly_high_frequency.sh" && ((TESTS_PASSED++))
test_anomaly "Protocol Violations" "anomaly_protocol_violations.sh" && ((TESTS_PASSED++))
test_anomaly "Geographic Anomalies" "anomaly_geographic.sh" && ((TESTS_PASSED++))

echo ""
echo "Phase 5: Results Summary"
echo "========================"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}/${TOTAL_TESTS}"

if [ "$TESTS_PASSED" -ge 3 ]; then
    echo -e "${GREEN}✅ Behavior analysis is working well!${NC}"
elif [ "$TESTS_PASSED" -ge 1 ]; then
    echo -e "${YELLOW}⚠️  Behavior analysis partially working${NC}"
else
    echo -e "${RED}❌ Behavior analysis may not be functioning${NC}"
fi

echo ""
echo "Phase 6: Profile Analysis"
echo "========================"
if [ -f "$PROFILE_FILE" ]; then
    echo "Behavior profile summary:"
    echo "File size: $(wc -c < "$PROFILE_FILE") bytes"
    echo "Applications profiled: $(grep -o '"[a-zA-Z_./]*":' "$PROFILE_FILE" | wc -l)"
    echo ""
    echo "Sample profile data:"
    head -20 "$PROFILE_FILE" 2>/dev/null || echo "Could not read profile file"
else
    echo -e "${RED}❌ No behavior profile file found${NC}"
fi

echo ""
echo -e "${BLUE}Behavior analysis test complete!${NC}"
echo "=== COMPLETED: Automated Behavior Analysis Test Script ==="
