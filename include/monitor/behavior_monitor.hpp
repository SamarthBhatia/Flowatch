#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <memory>
#include <chrono>
#include <atomic>
#include <thread>

namespace Firewall {

struct AppBehavior {
    std::unordered_set<std::string> knownDomains;
    std::unordered_set<std::string> knownIPs;
    std::unordered_set<int> knownPorts;
    std::unordered_set<std::string> knownCountries;
    
    uint64_t totalConnections = 0;
    uint64_t totalDataSent = 0;
    uint64_t totalDataReceived = 0;
    
    std::chrono::steady_clock::time_point lastSeen;
    std::chrono::steady_clock::time_point profiledAt;
    bool profileComplete = false;
};

class BehaviorMonitor {
public:
    static BehaviorMonitor& getInstance();
    
    // Start/stop behavior monitoring
    void start();
    void stop();
    bool isRunning() const;
    
    // Record connection to build behavior profile
    void recordConnection(const std::string& app, const std::string& remoteIP, 
                         int remotePort, const std::string& country, 
                         uint64_t bytesSent, uint64_t bytesReceived);
    
    // Check if connection matches app's normal behavior
    bool isNormalBehavior(const std::string& app, const std::string& remoteIP, 
                         int remotePort, const std::string& country);
    
    // Get app behavior profile
    const AppBehavior* getAppBehavior(const std::string& app);
    
    // Save/load behavior profiles
    bool saveProfiles(const std::string& filename);
    bool loadProfiles(const std::string& filename);
    
private:
    BehaviorMonitor();
    ~BehaviorMonitor();
    
    // Background thread to update and maintain profiles
    void profileMaintenanceThread();
    
    // Analyze and mark profiles as complete after learning period
    void analyzeProfiles();
    
    std::unordered_map<std::string, AppBehavior> appProfiles_;
    std::mutex profilesMutex_;
    
    std::thread maintenanceThread_;
    std::atomic<bool> running_;
};

} // namespace Firewall
