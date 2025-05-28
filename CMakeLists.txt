# cmake_minimum_required(VERSION 3.15)
# project(flowatch VERSION 1.0)

# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)

# if(APPLE)
#   set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lc++fs")
# endif()

# # Set options for dependencies
# set(SPDLOG_BUILD_EXAMPLES OFF CACHE BOOL "")
# set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "")
# add_subdirectory(extern/spdlog)

# set(JSON_BuildTests OFF CACHE INTERNAL "")
# set(JSON_Install OFF CACHE INTERNAL "")
# add_subdirectory(extern/json)

# # Use system-installed libpcap
# find_path(PCAP_INCLUDE_DIR pcap.h PATHS /opt/homebrew/include /usr/local/include)
# find_library(PCAP_LIBRARY NAMES pcap PATHS /opt/homebrew/lib /usr/local/lib)

# if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
#     message(FATAL_ERROR "libpcap not found. Install it with 'brew install libpcap'.")
# endif()

# add_library(libpcap UNKNOWN IMPORTED)
# set_target_properties(libpcap PROPERTIES
#     IMPORTED_LOCATION ${PCAP_LIBRARY}
#     INTERFACE_INCLUDE_DIRECTORIES ${PCAP_INCLUDE_DIR}
# )



# # Define source files
# set(SOURCES
#     src/main.cpp
#     src/cli/interface.cpp
#     src/monitor/connection_monitor.cpp
#     src/monitor/process_monitor.cpp
#     src/monitor/behavior_monitor.cpp
#     src/rules/rule_manager.cpp
#     src/utils/logger.cpp
#     src/utils/config.cpp
#     src/geo/location_manager.cpp

#     src/dialog/dialog_tree.cpp
#     src/dialog/dialog_minimizer.cpp
#     src/dialog/dialog_diffing.cpp
#     src/dialog/dialog_integration.cpp
#     src/dialog/dialog_applications.cpp
# )

# # Debugging: Print the full path of each source file
# foreach(SOURCE_FILE ${SOURCES})
#     message(STATUS "Looking for: ${PROJECT_SOURCE_DIR}/${SOURCE_FILE}")
# endforeach()

# # Check if source files exist
# foreach(SOURCE_FILE ${SOURCES})
#     if(NOT EXISTS ${PROJECT_SOURCE_DIR}/${SOURCE_FILE})
#         message(FATAL_ERROR "Source file not found: ${PROJECT_SOURCE_DIR}/${SOURCE_FILE}")
#     endif()
# endforeach()

# # Create executable
# add_executable(firewall ${SOURCES})

# # Include directories
# target_include_directories(firewall
#     PRIVATE
#     ${PROJECT_SOURCE_DIR}/include
#     ${PROJECT_SOURCE_DIR}/extern/spdlog/include
#     ${PROJECT_SOURCE_DIR}/extern/json/include
#     ${PCAP_INCLUDE_DIRS}
# )

# # Link libraries
# target_link_libraries(firewall
#     PRIVATE
#     libpcap
#     spdlog::spdlog
#     nlohmann_json::nlohmann_json
# )


# # Set output directories
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
# set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
# set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

cmake_minimum_required(VERSION 3.15)
project(flowatch VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force threading support
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# Add this to force threading detection
if(NOT Threads_FOUND)
    message(FATAL_ERROR "Threading support is required but not found")
endif()

# Create a simple spdlog target without subdirectory complications
add_library(simple_spdlog INTERFACE)
target_include_directories(simple_spdlog INTERFACE extern/spdlog/include)
target_link_libraries(simple_spdlog INTERFACE Threads::Threads)

# Create a simple nlohmann_json target
add_library(simple_json INTERFACE)
target_include_directories(simple_json INTERFACE extern/json/include)

# Find libpcap
find_path(PCAP_INCLUDE_DIR pcap.h PATHS /opt/homebrew/include /usr/local/include)
find_library(PCAP_LIBRARY NAMES pcap PATHS /opt/homebrew/lib /usr/local/lib)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Install it with 'brew install libpcap'.")
endif()

# Define source files - only include existing ones
set(SOURCES
    src/main.cpp
    src/cli/interface.cpp
    src/monitor/connection_monitor.cpp
    src/monitor/process_monitor.cpp
    src/monitor/behavior_monitor.cpp
    src/rules/rule_manager.cpp
    src/utils/logger.cpp
    src/utils/config.cpp
    src/geo/location_manager.cpp
)

# Only add dialog sources if they exist
set(DIALOG_SOURCES
    src/dialog/dialog_tree.cpp
    src/dialog/dialog_diffing.cpp
    src/dialog/dialog_minimizer.cpp
    src/dialog/dialog_integration.cpp
    src/dialog/dialog_applications.cpp
)

foreach(DIALOG_SOURCE ${DIALOG_SOURCES})
    if(EXISTS ${PROJECT_SOURCE_DIR}/${DIALOG_SOURCE})
        list(APPEND SOURCES ${DIALOG_SOURCE})
        message(STATUS "Adding dialog source: ${DIALOG_SOURCE}")
    else()
        message(STATUS "Skipping missing dialog source: ${DIALOG_SOURCE}")
    endif()
endforeach()

# Check if required source files exist
foreach(SOURCE_FILE ${SOURCES})
    if(NOT EXISTS ${PROJECT_SOURCE_DIR}/${SOURCE_FILE})
        message(WARNING "Source file not found: ${PROJECT_SOURCE_DIR}/${SOURCE_FILE}")
        list(REMOVE_ITEM SOURCES ${SOURCE_FILE})
    endif()
endforeach()

# Create executable
add_executable(firewall ${SOURCES})

# Include directories
target_include_directories(firewall
    PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIR}
)

# Link libraries - simplified
target_link_libraries(firewall
    PRIVATE
    simple_spdlog
    simple_json
    ${PCAP_LIBRARY}
    Threads::Threads
)

# Add platform-specific threading flags
if(APPLE)
    target_link_libraries(firewall PRIVATE "-framework CoreFoundation")
elseif(UNIX)
    target_link_libraries(firewall PRIVATE pthread)
endif()

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Compiler flags
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(firewall PRIVATE -Wall -Wextra -pthread)
endif()

message(STATUS "Sources to build: ${SOURCES}")
message(STATUS "Threading support: ${CMAKE_THREAD_LIBS_INIT}")
message(STATUS "PCAP library: ${PCAP_LIBRARY}")
message(STATUS "PCAP include: ${PCAP_INCLUDE_DIR}")