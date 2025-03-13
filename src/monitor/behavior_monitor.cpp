#include "../../include/monitor/behavior_monitor.hpp"
#include "../../include/utils/logger.hpp"
#include "../../include/utils/config.hpp"

#include <fstream>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <netdb.h>

namespace Firewall {

BehaviorMonitor& BehaviorMonitor::getInstance() {
    static BehaviorMonitor instance;
    return instance;
}

BehaviorMonitor::BehaviorMonitor() : running_(false) {
}

BehaviorMonitor::~BehaviorMonitor() {
    stop();
}

void BehaviorMonitor::start() {
    if (running_) {
        return;
    }
    
    running_ = true;
    
    // Load saved profiles if available
    std::string profilePath = Config::getInstance().get<std::string>(
        "behavior_profiles", getenv("HOME") + std::string("/.config/firewall/behavior_profiles.json"));
    loadProfiles(profilePath);
    
    // Start maintenance thread
    maintenanceThread_ = std::thread(&BehaviorMonitor::profileMaintenanceThread, this);
    
    Logger::get()->info("Behavior monitoring started");
}

void BehaviorMonitor::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    if (maintenanceThread_.joinable()) {
        maintenanceThread_.join();
    }
    
    // Save profiles before stopping
    std::string profilePath = Config::getInstance().get<std::string>(
        "behavior_profiles", getenv("HOME") + std::string("/.config/firewall/behavior_profiles.json"));
    saveProfiles(profilePath);
    
    Logger::get()->info("Behavior monitoring stopped");
}

bool BehaviorMonitor::isRunning() const {
    return running_;
}

void BehaviorMonitor::recordConnection(const std::string& app, const std::string& remoteIP, 
                                     int remotePort, const std::string& country, 
                                     uint64_t bytesSent, uint64_t bytesReceived) {
    if (app.empty() || app == "unknown" || !running_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    // Get or create app profile
    auto& profile = appProfiles_[app];
    
    // Update profile with this connection
    profile.knownIPs.insert(remoteIP);
    profile.knownPorts.insert(remotePort);
    if (!country.empty() && country != "UNKNOWN") {
        profile.knownCountries.insert(country);
    }
    
    // Try to resolve domain from IP
    struct hostent* host = gethostbyaddr(remoteIP.c_str(), sizeof(remoteIP), AF_INET);
    if (host && host->h_name) {
        profile.knownDomains.insert(host->h_name);
    }
    
    // Update statistics
    profile.totalConnections++;
    profile.totalDataSent += bytesSent;
    profile.totalDataReceived += bytesReceived;
    profile.lastSeen = std::chrono::steady_clock::now();
    
    // If profile not yet complete, update profiling timestamp
    if (!profile.profileComplete) {
        profile.profiledAt = std::chrono::steady_clock::now();
    }
}

bool BehaviorMonitor::isNormalBehavior(const std::string& app, const std::string& remoteIP, 
                                     int remotePort, const std::string& country) {
    if (app.empty() || app == "unknown" || !running_) {
        return true;  // Can't evaluate unknown apps
    }
    
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    // Check if we have a profile for this app
    auto it = appProfiles_.find(app);
    if (it == appProfiles_.end() || !it->second.profileComplete) {
        return true;  // No complete profile yet, consider normal
    }
    
    const auto& profile = it->second;
    
    // If we've seen this IP or port before, it's normal
    if (profile.knownIPs.find(remoteIP) != profile.knownIPs.end()) {
        return true;
    }
    
    if (profile.knownPorts.find(remotePort) != profile.knownPorts.end()) {
        return true;
    }
    
    // Check country if available
    if (!country.empty() && country != "UNKNOWN" && 
        profile.knownCountries.find(country) != profile.knownCountries.end()) {
        return true;
    }
    
    // Try to resolve domain from IP and check if domain is known
    struct hostent* host = gethostbyaddr(remoteIP.c_str(), sizeof(remoteIP), AF_INET);
    if (host && host->h_name && 
        profile.knownDomains.find(host->h_name) != profile.knownDomains.end()) {
        return true;
    }
    
    // This is abnormal behavior for this app
    Logger::get()->info("Abnormal behavior detected for {}: connection to {}:{}", 
                      app, remoteIP, remotePort);
    return false;
}

const AppBehavior* BehaviorMonitor::getAppBehavior(const std::string& app) const {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    auto it = appProfiles_.find(app);
    if (it != appProfiles_.end()) {
        return &(it->second);
    }
    
    return nullptr;
}

bool BehaviorMonitor::saveProfiles(const std::string& filename) {
    try {
        std::lock_guard<std::mutex> lock(profilesMutex_);
        
        nlohmann::json profilesJson;
        
        for (const auto& [app, profile] : appProfiles_) {
            nlohmann::json profileJson;
            
            // Convert sets to arrays
            nlohmann::json knownIPs = nlohmann::json::array();
            for (const auto& ip : profile.knownIPs) {
                knownIPs.push_back(ip);
            }
            
            nlohmann::json knownPorts = nlohmann::json::array();
            for (const auto& port : profile.knownPorts) {
                knownPorts.push_back(port);
            }
            
            nlohmann::json knownDomains = nlohmann::json::array();
            for (const auto& domain : profile.knownDomains) {
                knownDomains.push_back(domain);
            }
            
            nlohmann::json knownCountries = nlohmann::json::array();
            for (const auto& country : profile.knownCountries) {
                knownCountries.push_back(country);
            }
            
            profileJson["knownIPs"] = knownIPs;
            profileJson["knownPorts"] = knownPorts;
            profileJson["knownDomains"] = knownDomains;
            profileJson["knownCountries"] = knownCountries;
            profileJson["totalConnections"] = profile.totalConnections;
            profileJson["totalDataSent"] = profile.totalDataSent;
            profileJson["totalDataReceived"] = profile.totalDataReceived;
            profileJson["profileComplete"] = profile.profileComplete;
            
            profilesJson[app] = profileJson;
        }
        
        // Create directories if needed
        std::filesystem::path path(filename);
        std::filesystem::create_directories(path.parent_path());
        
        // Save to file
        std::ofstream file(filename);
        if (!file.is_open()) {
            Logger::get()->error("Failed to open behavior profiles file for writing: {}", filename);
            return false;
        }
        
        file << std::setw(4) << profilesJson << std::endl;
        Logger::get()->info("Saved behavior profiles to {}", filename);
        return true;
    } catch (const std::exception& e) {
        Logger::get()->error("Error saving behavior profiles: {}", e.what());
        return false;
    }
}

bool BehaviorMonitor::loadProfiles(const std::string& filename) {
    try {
        if (!std::filesystem::exists(filename)) {
            Logger::get()->warn("Behavior profiles file does not exist: {}", filename);
            return false;
        }
        
        std::ifstream file(filename);
        if (!file.is_open()) {
            Logger::get()->error("Failed to open behavior profiles file: {}", filename);
            return false;
        }
        
        std::lock_guard<std::mutex> lock(profilesMutex_);
        
        nlohmann::json profilesJson;
        file >> profilesJson;
        
        appProfiles_.clear();
        
        for (auto it = profilesJson.begin(); it != profilesJson.end(); ++it) {
            const std::string& app = it.key();
            const auto& profileJson = it.value();
            
            AppBehavior profile;
            
            // Load IP addresses
            if (profileJson.contains("knownIPs") && profileJson["knownIPs"].is_array()) {
                for (const auto& ip : profileJson["knownIPs"]) {
                    profile.knownIPs.insert(ip.get<std::string>());
                }
            }
            
            // Load ports
            if (profileJson.contains("knownPorts") && profileJson["knownPorts"].is_array()) {
                for (const auto& port : profileJson["knownPorts"]) {
                    profile.knownPorts.insert(port.get<int>());
                }
            }
            
            // Load domains
            if (profileJson.contains("knownDomains") && profileJson["knownDomains"].is_array()) {
                for (const auto& domain : profileJson["knownDomains"]) {
                    profile.knownDomains.insert(domain.get<std::string>());
                }
            }
            
            // Load countries
            if (profileJson.contains("knownCountries") && profileJson["knownCountries"].is_array()) {
                for (const auto& country : profileJson["knownCountries"]) {
                    profile.knownCountries.insert(country.get<std::string>());
                }
            }
            
            // Load stats
            profile.totalConnections = profileJson.value("totalConnections", 0);
            profile.totalDataSent = profileJson.value("totalDataSent", 0);
            profile.totalDataReceived = profileJson.value("totalDataReceived", 0);
            profile.profileComplete = profileJson.value("profileComplete", false);
            
            // Set timestamps to now
            profile.lastSeen = std::chrono::steady_clock::now();
            profile.profiledAt = std::chrono::steady_clock::now();
            
            appProfiles_[app] = profile;
        }
        
        Logger::get()->info("Loaded {} behavior profiles from {}", appProfiles_.size(), filename);
        return true;
    } catch (const std::exception& e) {
        Logger::get()->error("Error loading behavior profiles: {}", e.what());
        return false;
    }
}

void BehaviorMonitor::profileMaintenanceThread() {
    while (running_) {
        // Sleep for a minute
        std::this_thread::sleep_for(std::chrono::minutes(1));
        
        if (!running_) {
            break;
        }
        
        // Analyze profiles
        analyzeProfiles();
        
        // Periodically save profiles
        static int saveCounter = 0;
        if (++saveCounter >= 10) { // Save every 10 minutes
            saveCounter = 0;
            std::string profilePath = Config::getInstance().get<std::string>(
                "behavior_profiles", getenv("HOME") + std::string("/.config/firewall/behavior_profiles.json"));
            saveProfiles(profilePath);
        }
    }
}

void BehaviorMonitor::analyzeProfiles() {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    auto now = std::chrono::steady_clock::now();
    int learningPeriodMinutes = Config::getInstance().get<int>("behavior_learning_period", 60);
    std::chrono::minutes learningPeriod(learningPeriodMinutes);
    
    for (auto& [app, profile] : appProfiles_) {
        // Skip already completed profiles
        if (profile.profileComplete) {
            continue;
        }
        
        // Check if we've been profiling for enough time
        if (now - profile.profiledAt >= learningPeriod && 
            profile.totalConnections >= 10) { // Require at least 10 connections
            
            profile.profileComplete = true;
            Logger::get()->info("Behavior profile complete for {}: {} connections, {} IPs, {} ports, {} domains", 
                              app, profile.totalConnections, profile.knownIPs.size(), 
                              profile.knownPorts.size(), profile.knownDomains.size());
        }
    }
}

} // namespace Firewall
