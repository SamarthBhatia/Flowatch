#include "../../include/monitor/connection_monitor.hpp"
#include "../../include/monitor/process_monitor.hpp"
#include "../../include/utils/logger.hpp"
#include "../../include/utils/config.hpp"
#include "../../include/geo/location_manager.hpp"

#include <stdexcept>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <functional>
#include <chrono>
#include <thread>

namespace Firewall {

ConnectionMonitor::ConnectionMonitor() 
    : handle_(nullptr), running_(false), ruleManager_(std::make_unique<RuleManager>()) {
}

ConnectionMonitor::~ConnectionMonitor() {
    stop();
}

bool ConnectionMonitor::start() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    
    // Start process monitor if not already running
    if (!ProcessMonitor::getInstance().isRunning()) {
        ProcessMonitor::getInstance().start();
    }
    
    // Find all available devices
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        Logger::get()->error("Failed to find network devices: {}", errbuf);
        return false;
    }

    // Use the first device if available
    if (!devices) {
        Logger::get()->error("No network devices found");
        return false;
    }

    // Allow override of interface via config
    std::string interface = Config::getInstance().get<std::string>("interface", devices->name);
    
    handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    pcap_freealldevs(devices);  // Free the device list

    if (handle_ == nullptr) {
        Logger::get()->error("Failed to open device: {}", errbuf);
        return false;
    }

    // Set filter to capture only IP packets
    struct bpf_program fp;
    char filter_exp[] = "ip";
    if (pcap_compile(handle_, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        Logger::get()->error("Failed to compile filter: {}", pcap_geterr(handle_));
        return false;
    }

    if (pcap_setfilter(handle_, &fp) == -1) {
        Logger::get()->error("Failed to set filter: {}", pcap_geterr(handle_));
        return false;
    }

    running_ = true;
    Logger::get()->info("Connection monitoring started on interface: {}", interface);
    
    // Start traffic stats thread
    startStatsCollection();
    
    // Start packet capture
    pcap_loop(handle_, -1, packetCallback, reinterpret_cast<u_char*>(this));
    return true;
}

void ConnectionMonitor::stop() {
    if (running_ && handle_) {
        pcap_breakloop(handle_);
        pcap_close(handle_);
        handle_ = nullptr;
        running_ = false;
        stopStatsCollection();
        Logger::get()->info("Connection monitoring stopped");
    }
}

bool ConnectionMonitor::isRunning() const {
    return running_;
}

void ConnectionMonitor::packetCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    auto* monitor = reinterpret_cast<ConnectionMonitor*>(user);
    monitor->processPacket(pkthdr, packet);
}

void ConnectionMonitor::processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Skip ethernet header
    const struct ip* ip = reinterpret_cast<const struct ip*>(packet + 14);
    
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(ip->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dstIP, INET_ADDRSTRLEN);

    // Track traffic statistics (bytes)
    updateTrafficStats(ip->ip_len);
    
    // Process TCP packets
    if (ip->ip_p == IPPROTO_TCP) {
        processTCPPacket(pkthdr, packet, ip, srcIP, dstIP);
    } 
    // Process UDP packets
    else if (ip->ip_p == IPPROTO_UDP) {
        processUDPPacket(pkthdr, packet, ip, srcIP, dstIP);
    }
}

void ConnectionMonitor::processTCPPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, 
                                     const struct ip* ip, const char* srcIP, const char* dstIP) {
    const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + 14 + (ip->ip_hl << 2));
    int srcPort = ntohs(tcp->th_sport);
    int dstPort = ntohs(tcp->th_dport);

    // Get local IP address
    std::string localIP = getLocalIPAddress();
    bool isOutbound = (std::string(srcIP) == localIP);
    
    // Determine connection direction and remote IP
    std::string connectionDirection = isOutbound ? "outbound" : "inbound";
    std::string remoteIP = isOutbound ? dstIP : srcIP;
    int remotePort = isOutbound ? dstPort : srcPort;
    
    // For outbound connections, identify the source application
    std::string application = "unknown";
    if (isOutbound) {
        application = ProcessMonitor::getInstance().getProcessForConnection(
            srcIP, srcPort, dstIP, dstPort);
    }
    
    Logger::get()->debug("TCP {} Connection: {}:{} -> {}:{} (App: {})", 
        connectionDirection, srcIP, srcPort, dstIP, dstPort, application);
    
    // Check if connection should be allowed based on GeoIP rules
    bool allowedByGeo = true;
    auto blockedCountries = Config::getInstance().get<std::vector<std::string>>(
        "blocked_countries", std::vector<std::string>());
    
    if (!blockedCountries.empty()) {
        if (Geo::LocationManager::getInstance().isInCountries(remoteIP, blockedCountries)) {
            Logger::get()->info("Blocked connection to country in blocklist: IP={}", remoteIP);
            allowedByGeo = false;
            
            // Update blocked count statistics
            int blockCount = Config::getInstance().get<int>("blocked_count", 0);
            Config::getInstance().set("blocked_count", blockCount + 1);
            
            // Log this connection to recent blocks
            addToRecentBlocks(application, remoteIP, remotePort, "GeoIP");
        }
    }
    
    // Evaluate connection against rules
    bool allowedByRules = ruleManager_->evaluateConnection(application, remoteIP, remotePort);
    
    if (!allowedByGeo || !allowedByRules) {
        if (allowedByGeo) {
            Logger::get()->info("Blocked connection to {}:{} from app {}", remoteIP, remotePort, application);
            
            // Update blocked count statistics
            int blockCount = Config::getInstance().get<int>("blocked_count", 0);
            Config::getInstance().set("blocked_count", blockCount + 1);
            
            // Log this connection to recent blocks
            addToRecentBlocks(application, remoteIP, remotePort, "Rule");
        }
        
        // Implement blocking mechanism here
        // This could involve sending a RST packet or other mitigation
    } else {
        // Connection is allowed - add to active connections
        addToActiveConnections(application, remoteIP, remotePort, "TCP");
    }
}

void ConnectionMonitor::processUDPPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, 
                                     const struct ip* ip, const char* srcIP, const char* dstIP) {
    // Similar to TCP processing but for UDP
    const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(packet + 14 + (ip->ip_hl << 2));
    int srcPort = ntohs(udp->source);
    int dstPort = ntohs(udp->dest);
    
    // Get local IP address
    std::string localIP = getLocalIPAddress();
    bool isOutbound = (std::string(srcIP) == localIP);
    
    // Determine connection direction and remote IP
    std::string connectionDirection = isOutbound ? "outbound" : "inbound";
    std::string remoteIP = isOutbound ? dstIP : srcIP;
    int remotePort = isOutbound ? dstPort : srcPort;
    
    // For outbound connections, identify the source application
    std::string application = "unknown";
    if (isOutbound) {
        application = ProcessMonitor::getInstance().getProcessForConnection(
            srcIP, srcPort, dstIP, dstPort);
    }
    
    Logger::get()->debug("UDP {} Connection: {}:{} -> {}:{} (App: {})", 
        connectionDirection, srcIP, srcPort, dstIP, dstPort, application);
    
    // Evaluate and handle the connection (similar to TCP)
    bool allowedByGeo = true;
    auto blockedCountries = Config::getInstance().get<std::vector<std::string>>(
        "blocked_countries", std::vector<std::string>());
    
    if (!blockedCountries.empty()) {
        if (Geo::LocationManager::getInstance().isInCountries(remoteIP, blockedCountries)) {
            allowedByGeo = false;
            Logger::get()->info("Blocked UDP connection to country in blocklist: IP={}", remoteIP);
            
            // Update blocked count statistics
            int blockCount = Config::getInstance().get<int>("blocked_count", 0);
            Config::getInstance().set("blocked_count", blockCount + 1);
            
            // Log this connection to recent blocks
            addToRecentBlocks(application, remoteIP, remotePort, "GeoIP");
        }
    }
    
    bool allowedByRules = ruleManager_->evaluateConnection(application, remoteIP, remotePort);
    
    if (!allowedByGeo || !allowedByRules) {
        if (allowedByGeo) {
            Logger::get()->info("Blocked UDP connection to {}:{} from app {}", remoteIP, remotePort, application);
            
            // Update blocked count statistics
            int blockCount = Config::getInstance().get<int>("blocked_count", 0);
            Config::getInstance().set("blocked_count", blockCount + 1);
            
            // Log this connection to recent blocks
            addToRecentBlocks(application, remoteIP, remotePort, "Rule");
        }
        
        // UDP blocking would be different from TCP (can't send RST)
    } else {
        // Connection is allowed - add to active connections
        addToActiveConnections(application, remoteIP, remotePort, "UDP");
    }
}

std::string ConnectionMonitor::getLocalIPAddress() {
    // Cache this value to avoid repeatedly looking it up
    static std::string localIP;
    if (!localIP.empty()) {
        return localIP;
    }
    
    // Try to get local IP address
    try {
        // Create a UDP socket
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == -1) {
            return "127.0.0.1";
        }
        
        // The address we connect to doesn't need to be reachable
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
        
        // Connect the socket
        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == -1) {
            close(sock);
            return "127.0.0.1";
        }
        
        // Get the local address
        sockaddr_in localAddr;
        socklen_t addrLen = sizeof(localAddr);
        if (getsockname(sock, (sockaddr*)&localAddr, &addrLen) == -1) {
            close(sock);
            return "127.0.0.1";
        }
        
        // Convert to string
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &localAddr.sin_addr, buffer, INET_ADDRSTRLEN);
        
        close(sock);
        localIP = buffer;
        return localIP;
    } catch (...) {
        return "127.0.0.1";
    }
}

void ConnectionMonitor::addToActiveConnections(const std::string& app, const std::string& remoteIP, 
                                          int remotePort, const std::string& protocol) {
    // Add to active connections list (for display in UI)
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    ConnectionInfo info;
    info.application = app;
    info.remoteIP = remoteIP;
    info.remotePort = remotePort;
    info.protocol = protocol;
    info.timestamp = std::time(nullptr);
    
    // Get country code if GeoIP is available
    info.country = Geo::LocationManager::getInstance().getCountryCode(remoteIP);
    
    // Add to front of list (most recent first)
    activeConnections_.push_front(info);
    
    // Keep list at reasonable size
    if (activeConnections_.size() > 100) {
        activeConnections_.pop_back();
    }
}

void ConnectionMonitor::addToRecentBlocks(const std::string& app, const std::string& remoteIP, 
                                     int remotePort, const std::string& reason) {
    // Add to blocked connections list (for display in UI)
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    ConnectionInfo info;
    info.application = app;
    info.remoteIP = remoteIP;
    info.remotePort = remotePort;
    info.protocol = "BLOCKED";
    info.timestamp = std::time(nullptr);
    info.reason = reason;
    
    // Get country code if GeoIP is available
    info.country = Geo::LocationManager::getInstance().getCountryCode(remoteIP);
    
    // Add to front of list (most recent first)
    blockedConnections_.push_front(info);
    
    // Keep list at reasonable size
    if (blockedConnections_.size() > 100) {
        blockedConnections_.pop_back();
    }
}

void ConnectionMonitor::updateTrafficStats(size_t packetSize) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    // Update current stats
    currentStats_.bytesTotal += packetSize;
    currentStats_.packetsTotal += 1;
    
    // Calculate rates in the stats collector thread
}

void ConnectionMonitor::startStatsCollection() {
    statsRunning_ = true;
    statsThread_ = std::thread([this]() {
        while (statsRunning_) {
            collectStats();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
}

void ConnectionMonitor::stopStatsCollection() {
    statsRunning_ = false;
    if (statsThread_.joinable()) {
        statsThread_.join();
    }
}

void ConnectionMonitor::collectStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    // Calculate rates based on difference from last collection time
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastStatsTime_).count();
    
    if (elapsed > 0) {
        // Calculate bytes per second
        double seconds = elapsed / 1000.0;
        currentStats_.bytesPerSecond = (currentStats_.bytesTotal - lastStats_.bytesTotal) / seconds;
        currentStats_.packetsPerSecond = (currentStats_.packetsTotal - lastStats_.packetsTotal) / seconds;
        
        // Update historical data for graphs (keep last hour of data)
        trafficHistory_.push_back(currentStats_);
        if (trafficHistory_.size() > 3600) { // One hour at 1-second intervals
            trafficHistory_.pop_front();
        }
        
        // Update last stats
        lastStats_ = currentStats_;
        lastStatsTime_ = now;
    }
}

const std::deque<ConnectionInfo>& ConnectionMonitor::getActiveConnections() const {
    return activeConnections_;
}

const std::deque<ConnectionInfo>& ConnectionMonitor::getBlockedConnections() const {
    return blockedConnections_;
}

const TrafficStats& ConnectionMonitor::getCurrentStats() const {
    return currentStats_;
}

const std::deque<TrafficStats>& ConnectionMonitor::getTrafficHistory() const {
    return trafficHistory_;
}

} // namespace Firewall
