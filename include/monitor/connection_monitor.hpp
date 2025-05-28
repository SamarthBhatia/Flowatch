// #pragma once

// #include <string>
// #include <vector>
// #include <memory>
// #include <pcap.h>
// #include "rules/rule_manager.hpp"

// namespace Firewall {

//     class ConnectionMonitor {
//     public:
//         ConnectionMonitor();
//         ~ConnectionMonitor();
    
//         bool start();
//         void stop();
//         bool isRunning() const;
    
//     private:
//         static void packetCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
//         void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
        
//     public:
//         static void staticPacketCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
//         pcap_t* handle_;
//         bool running_;
//         std::unique_ptr<RuleManager> ruleManager_;
//     };
    
//     }


#pragma once

#include <string>
#include <vector>
#include <memory>
#include <pcap.h>
#include "../rules/rule_manager.hpp"
#include "../utils/types.hpp"
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

// Forward declarations for system structs
struct pcap_pkthdr;
struct ip;

namespace Firewall {

    class ConnectionMonitor {
    public:
        ConnectionMonitor();
        virtual ~ConnectionMonitor();
    
        virtual bool start();
        virtual void stop();
        bool isRunning() const;
        
        // Access to connection data
        const std::deque<ConnectionInfo>& getActiveConnections() const;
        const std::deque<ConnectionInfo>& getBlockedConnections() const;
        
        // Access traffic statistics  
        const TrafficStats& getCurrentStats() const;
        const std::deque<TrafficStats>& getTrafficHistory() const;
        
        // PUBLIC RULE MANAGER ACCESS METHODS - ADDED TO FIX COMPILATION
        bool addRule(const Rule& rule);
        bool removeRule(const std::string& application);
        bool loadRules(const std::string& filename);
        bool saveRules(const std::string& filename);
        const std::vector<Rule>& getRules() const;
        bool hasRuleManager() const;
    
    protected:
        // Virtual method that can be overridden by derived classes
        virtual void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
        
        // Packet processing helpers - FIXED: Use ::ip for global namespace
        void processTCPPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, 
                             const struct ::ip* ip, const char* srcIP, const char* dstIP);
        void processUDPPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, 
                             const struct ::ip* ip, const char* srcIP, const char* dstIP);
        
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
        
        // Protected members for derived classes
        pcap_t* handle_;
        std::atomic<bool> running_;
        std::unique_ptr<RuleManager> ruleManager_;
        
        // Connection tracking
        std::deque<ConnectionInfo> activeConnections_;
        std::deque<ConnectionInfo> blockedConnections_;
        mutable std::mutex connectionsMutex_;
        
        // Traffic statistics
        TrafficStats currentStats_;
        TrafficStats lastStats_;
        std::deque<TrafficStats> trafficHistory_;
        mutable std::mutex statsMutex_;
        std::thread statsThread_;
        std::atomic<bool> statsRunning_;
        std::chrono::steady_clock::time_point lastStatsTime_;
        
    public:
        static void staticPacketCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
    private:
        static void packetCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    };
    
}