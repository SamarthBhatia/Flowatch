#pragma once

#include <string>
#include <ctime>
#include <cstdint>

namespace Firewall {

// Shared connection information structure
struct ConnectionInfo {
    std::string application;
    std::string remoteIP;
    int remotePort;
    std::string protocol;
    std::time_t timestamp;
    std::string country;
    std::string reason;  // For blocked connections
    
    ConnectionInfo() 
        : remotePort(0), timestamp(0) {}
        
    ConnectionInfo(const std::string& app, const std::string& ip, int port, 
                   const std::string& proto, const std::string& ctry = "", 
                   const std::string& rsn = "")
        : application(app), remoteIP(ip), remotePort(port), protocol(proto),
          timestamp(std::time(nullptr)), country(ctry), reason(rsn) {}
};

// Network traffic statistics
struct TrafficStats {
    uint64_t bytesTotal = 0;
    uint64_t packetsTotal = 0;
    double bytesPerSecond = 0.0;
    double packetsPerSecond = 0.0;
    std::time_t timestamp = std::time(nullptr);
    
    TrafficStats() = default;
    
    TrafficStats(uint64_t bytes, uint64_t packets, double bps, double pps)
        : bytesTotal(bytes), packetsTotal(packets), 
          bytesPerSecond(bps), packetsPerSecond(pps),
          timestamp(std::time(nullptr)) {}
};

// Protocol types for packet analysis
enum class ProtocolType {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    DNS,
    UNKNOWN
};

// Connection direction for analysis
enum class ConnectionDirection {
    INBOUND,
    OUTBOUND,
    BIDIRECTIONAL,
    UNKNOWN
};

// Connection state for tracking
enum class ConnectionState {
    ESTABLISHING,
    ESTABLISHED,
    CLOSING,
    CLOSED,
    BLOCKED,
    ALLOWED,
    UNKNOWN
};

// Enhanced connection information for dialog analysis
struct EnhancedConnectionInfo : public ConnectionInfo {
    ProtocolType protocolType = ProtocolType::UNKNOWN;
    ConnectionDirection direction = ConnectionDirection::UNKNOWN;
    ConnectionState state = ConnectionState::UNKNOWN;
    uint64_t bytesTransferred = 0;
    uint64_t packetsTransferred = 0;
    std::time_t firstSeen = 0;
    std::time_t lastSeen = 0;
    
    EnhancedConnectionInfo() {
        firstSeen = lastSeen = std::time(nullptr);
    }
    
    EnhancedConnectionInfo(const ConnectionInfo& base) 
        : ConnectionInfo(base) {
        firstSeen = lastSeen = timestamp;
    }
};

// Event types for logging and analysis
enum class EventType {
    CONNECTION_ESTABLISHED,
    CONNECTION_BLOCKED,
    RULE_MATCHED,
    ATTACK_DETECTED,
    BEHAVIOR_ANOMALY,
    DIALOG_MINIMIZED,
    MALWARE_COLLECTED,
    VULNERABILITY_FOUND
};

// Event information structure
struct EventInfo {
    EventType type;
    std::time_t timestamp;
    std::string source;
    std::string destination;
    std::string description;
    std::string severity;  // LOW, MEDIUM, HIGH, CRITICAL
    
    EventInfo(EventType t, const std::string& src, const std::string& dst, 
              const std::string& desc, const std::string& sev = "MEDIUM")
        : type(t), timestamp(std::time(nullptr)), source(src), 
          destination(dst), description(desc), severity(sev) {}
};

// Statistics aggregation structure
struct AggregateStats {
    uint64_t totalConnections = 0;
    uint64_t blockedConnections = 0;
    uint64_t allowedConnections = 0;
    uint64_t totalBytesTransferred = 0;
    uint64_t totalPacketsTransferred = 0;
    double averageConnectionDuration = 0.0;
    std::time_t reportingPeriodStart = 0;
    std::time_t reportingPeriodEnd = 0;
    
    AggregateStats() {
        auto now = std::time(nullptr);
        reportingPeriodStart = reportingPeriodEnd = now;
    }
    
    // Calculate blocking rate as percentage
    double getBlockingRate() const {
        if (totalConnections == 0) return 0.0;
        return (static_cast<double>(blockedConnections) / totalConnections) * 100.0;
    }
    
    // Calculate average bytes per connection
    double getAverageBytesPerConnection() const {
        if (totalConnections == 0) return 0.0;
        return static_cast<double>(totalBytesTransferred) / totalConnections;
    }
};

} // namespace Firewall