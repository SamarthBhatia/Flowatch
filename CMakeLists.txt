cmake_minimum_required(VERSION 3.15)
project(network_firewall VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the spdlog submodule
add_subdirectory(extern/spdlog)

# Add the nlohmann/json submodule (if you're using it)
add_subdirectory(extern/json)

# Find other required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPCAP REQUIRED libpcap)

# Add the subdirectories
add_subdirectory(src)
add_subdirectory(tests)

# Main executable
add_executable(firewall src/main.cpp)

# Link libraries
target_link_libraries(firewall
    PRIVATE
    ${LIBPCAP_LIBRARIES}
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    firewall_lib
)

# Include directories
target_include_directories(firewall
    PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${LIBPCAP_INCLUDE_DIRS}
)

# src/CMakeLists.txt
add_library(firewall_lib
    monitor/connection_monitor.cpp 
    monitor/packet_analyzer.cpp 
    monitor/bandwidth_controller.cpp
    rules/rule_manager.cpp 
    rules/rule_parser.cpp 
    profiling/app_fingerprint.cpp 
    profiling/behavior_analyzer.cpp 
    profiling/anomaly_detector.cpp 
    geo/geo_analyzer.cpp 
    geo/ip_mapper.cpp 
    categorization/traffic_classifier.cpp 
    categorization/usage_stats.cpp 
    cli/interface.cpp 
    utils/logger.cpp 
    utils/config.cpp
)

target_include_directories(firewall_lib
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)