cmake_minimum_required(VERSION 3.15)
project(flowatch VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set options for dependencies
set(SPDLOG_BUILD_EXAMPLES OFF CACHE BOOL "")
set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "")
add_subdirectory(extern/spdlog)

set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
add_subdirectory(extern/json)

# Use system-installed libpcap
find_path(PCAP_INCLUDE_DIR pcap.h PATHS /opt/homebrew/include /usr/local/include)
find_library(PCAP_LIBRARY NAMES pcap PATHS /opt/homebrew/lib /usr/local/lib)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Install it with 'brew install libpcap'.")
endif()

add_library(libpcap UNKNOWN IMPORTED)
set_target_properties(libpcap PROPERTIES
    IMPORTED_LOCATION ${PCAP_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${PCAP_INCLUDE_DIR}
)



# Define source files
set(SOURCES
    src/main.cpp
    src/cli/interface.cpp
    src/monitor/connection_monitor.cpp
    src/utils/logger.cpp
    src/rules/rule_manager.cpp
)

# Debugging: Print the full path of each source file
foreach(SOURCE_FILE ${SOURCES})
    message(STATUS "Looking for: ${PROJECT_SOURCE_DIR}/${SOURCE_FILE}")
endforeach()

# Check if source files exist
foreach(SOURCE_FILE ${SOURCES})
    if(NOT EXISTS ${PROJECT_SOURCE_DIR}/${SOURCE_FILE})
        message(FATAL_ERROR "Source file not found: ${PROJECT_SOURCE_DIR}/${SOURCE_FILE}")
    endif()
endforeach()

# Create executable
add_executable(firewall ${SOURCES})

# Include directories
target_include_directories(firewall
    PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/extern/spdlog/include
    ${PROJECT_SOURCE_DIR}/extern/json/include
    ${PCAP_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(firewall
    PRIVATE
    libpcap
    spdlog::spdlog
    nlohmann_json::nlohmann_json
)


# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)