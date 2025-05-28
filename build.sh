#!/bin/bash

# Debug build script to identify the hanging issue
set -e

echo "=== Debug Build for Hanging Issue ==="

# Kill any existing build processes
echo "Cleaning up any hanging processes..."
pkill -f "cmake\|make\|g++" || true
sleep 2

# Clean build directory
rm -rf build
mkdir -p build
cd build

echo "Starting debug build with verbose output..."

# Configure with minimal options first
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_VERBOSE_MAKEFILE=ON \
    -DCMAKE_CXX_FLAGS="-v -time" \
    -DSPDLOG_BUILD_EXAMPLES=OFF \
    -DSPDLOG_BUILD_TESTS=OFF \
    -DJSON_BuildTests=OFF

echo ""
echo "Building with single-threaded compilation to identify the problematic file..."

# Build with single thread and verbose output to see where it hangs
timeout 120s make VERBOSE=1 -j1 || {
    echo ""
    echo "❌ Build timed out or failed!"
    echo ""
    echo "Let's try compiling each file individually to find the problem..."
    
    # Go back to root and try manual compilation
    cd ..
    
    echo "Testing individual file compilation..."
    
    # Test main.cpp first
    echo "Testing main.cpp..."
    if timeout 30s g++ -std=c++17 -I./include -I./extern/spdlog/include -I./extern/json/include -c src/main.cpp -o test_main.o; then
        echo "✅ main.cpp compiles fine"
        rm -f test_main.o
    else
        echo "❌ main.cpp has issues"
    fi
    
    # Test interface.cpp (the problematic one)
    echo "Testing cli/interface.cpp..."
    if timeout 30s g++ -std=c++17 -I./include -I./extern/spdlog/include -I./extern/json/include -c src/cli/interface.cpp -o test_interface.o; then
        echo "✅ interface.cpp compiles fine"
        rm -f test_interface.o
    else
        echo "❌ interface.cpp has compilation issues!"
        echo "This is likely the source of the hanging."
        
        # Try to get more detailed error info
        echo "Getting detailed compilation errors..."
        g++ -std=c++17 -I./include -I./extern/spdlog/include -I./extern/json/include -c src/cli/interface.cpp -o test_interface.o -v 2>&1 | head -50
    fi
    
    # Test a dialog file
    if [ -f "src/dialog/dialog_applications.cpp" ]; then
        echo "Testing dialog_applications.cpp..."
        if timeout 60s g++ -std=c++17 -I./include -I./extern/spdlog/include -I./extern/json/include -c src/dialog/dialog_applications.cpp -o test_dialog.o; then
            echo "✅ dialog_applications.cpp compiles fine"
            rm -f test_dialog.o
        else
            echo "❌ dialog_applications.cpp has issues!"
        fi
    fi
    
    exit 1
}

echo "✅ Build completed successfully!"