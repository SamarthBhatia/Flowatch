#pragma once

#include <string>
#include <vector>
#include <memory>
#include <deque>
#include <mutex>
#include <thread>
#include <chrono>
#include <atomic>
#include <pcap.h>

#include "../rules/rule_manager.hpp"

namespace Firewall {

// Information about a network connection
struct ConnectionInfo {
    std::string application;
    std::string remoteIP;
    int remotePort;
    std::string protocol;
    std::time_t timestamp;
    std::string country;
    std::string reason;  // For blocked connections
};

// Network traffic statistics
struct TrafficStats {
    uint64_t bytesTotal = 0;
    uint64_t packetsTotal = 0;
    double bytesPerSecond = 0;
    double packetsPerSecond = 0;
    std::time_t timestamp = std::time(nullptr);
};

class ConnectionMonitor {
public:
    ConnectionMonitor();
    ~ConnectionMonitor();

    bool start();
    void stop();
    bool isRunning() const;
    
    // Access connection data
    const std::deque<ConnectionInfo>& getActiveConnections() const;
    const std::deque<ConnectionInfo>& getBlockedConnections() const;
    
    // Access traffic statistics
    const TrafficStats& getCurrentStats() const;
    const std::deque<TrafficStats>& getTrafficHistory() const;

private:
    static void packetCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
    // Packet processing by protocol
    void processTCPPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, 
                         const struct ip* ip, const char* srcIP, const char* dstIP);
    void processUDPPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, 
                         const struct ip* ip, const char* srcIP, const char* dstIP);
    
    // Utility functions
    std::string getLocalIPAddress();
    void addToActiveConnections(const std::string& app, const std::string& remoteIP, 
                              int remotePort, const std::string& protocol);
    void addToRecentBlocks(const std::string& app, const std::string& remoteIP, 
                          int remotePort, const std::string& reason);
    
    // Traffic statistics functions
    void updateTrafficStats(size_t packetSize);
    void startStatsCollection();
    void stopStatsCollection();
    void collectStats();

public:
    // Make rule manager public so CLI can access it
    std::unique_ptr<RuleManager> ruleManager_;

private:
    pcap_t* handle_;
    bool running_;
    
    // Connection tracking
    std::deque<ConnectionInfo> activeConnections_;
    std::deque<ConnectionInfo> blockedConnections_;
    std::mutex connectionsMutex_;
    
    // Traffic statistics
    TrafficStats currentStats_;
    TrafficStats lastStats_;
    std::deque<TrafficStats> trafficHistory_;
    std::mutex statsMutex_;
    std::thread statsThread_;
    std::atomic<bool> statsRunning_;
    std::chrono::steady_clock::time_point lastStatsTime_;
};
