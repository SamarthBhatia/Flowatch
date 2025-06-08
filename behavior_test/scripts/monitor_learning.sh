#!/bin/bash
echo "=== STARTING: Monitor Learning Script ==="
echo "🔍 MONITORING BEHAVIOR LEARNING"
echo "==============================="

PROFILE_FILE="$HOME/.config/firewall/behavior_profiles.json"
echo "Monitoring profile file: $PROFILE_FILE"
echo ""

while true; do
    if [ -f "$PROFILE_FILE" ]; then
        echo "$(date): Checking behavior profiles..."
        
        # Count profiles
        PROFILE_COUNT=$(grep -o '"[^"]*":' "$PROFILE_FILE" | wc -l 2>/dev/null || echo "0")
        echo "  Total application profiles: $PROFILE_COUNT"
        
        # Check for completed profiles
        COMPLETE_COUNT=$(grep -o '"profileComplete":true' "$PROFILE_FILE" | wc -l 2>/dev/null || echo "0")
        echo "  Completed profiles: $COMPLETE_COUNT"
        
        # Show some profile names
        echo "  Applications being profiled:"
        grep -o '"[a-zA-Z_./]*":' "$PROFILE_FILE" | head -5 | sed 's/[":]*//g' | sed 's/^/    /'
        
        if [ "$COMPLETE_COUNT" -gt 0 ]; then
            echo "✅ Some profiles are complete! Ready for anomaly testing."
            echo "=== COMPLETED: Monitor Learning Script ==="
            break
        fi
    else
        echo "$(date): Waiting for behavior profiles to be created..."
    fi
    
    echo ""
    sleep 30
done
