#!/bin/bash

echo "=== Testing struct ip Fix ==="

# Test the updated files
echo "1. Testing updated connection_monitor.cpp..."
if g++ -std=c++17 -I./include -I./extern/spdlog/include -I./extern/json/include -c src/monitor/connection_monitor.cpp -o test_monitor_v2.o 2>/dev/null; then
    echo "✅ connection_monitor.cpp compiles successfully!"
    rm -f test_monitor_v2.o
else
    echo "❌ connection_monitor.cpp still has issues"
    echo "Detailed errors:"
    g++ -std=c++17 -I./include -I./extern/spdlog/include -I./extern/json/include -c src/monitor/connection_monitor.cpp -o test_monitor_v2.o 2>&1 | head -20
    exit 1
fi

echo "2. Testing updated interface.cpp..."
if g++ -std=c++17 -I./include -I./extern/spdlog/include -I./extern/json/include -c src/cli/interface.cpp -o test_interface_v2.o 2>/dev/null; then
    echo "✅ interface.cpp still compiles successfully!"
    rm -f test_interface_v2.o
else
    echo "❌ interface.cpp broke with the header changes"
    g++ -std=c++17 -I./include -I./extern/spdlog/include -I./extern/json/include -c src/cli/interface.cpp -o test_interface_v2.o 2>&1 | head -10
    exit 1
fi

echo ""
echo "🎉 Both critical files compile successfully!"
echo ""
echo "The fix was:"
echo "- Changed 'const struct ip*' to 'const struct ::ip*' in method signatures"
echo "- This tells the compiler to use the global namespace struct ip"
echo "- Instead of looking for Firewall::ip (which doesn't exist)"
echo ""
echo "Now run the full build:"
echo "./build.sh"