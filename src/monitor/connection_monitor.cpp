// #include "../../include/monitor/connection_monitor.hpp"
// #include "../../include/utils/logger.hpp"
// #include "../../include/utils/config.hpp"
// #include <stdexcept>
// #include <iostream>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <arpa/inet.h>
// #include <pcap/pcap.h>

// namespace Firewall {

//     ConnectionMonitor::ConnectionMonitor() 
//         : handle_(nullptr), running_(false), ruleManager_(std::make_unique<RuleManager>()) {
//     }
    
//     ConnectionMonitor::~ConnectionMonitor() {
//         stop();
//     }
    
    // bool ConnectionMonitor::start() {
    //     char errbuf[PCAP_ERRBUF_SIZE];
    //     pcap_if_t *devices;
        
    //     // Find all available devices
    //     if (pcap_findalldevs(&devices, errbuf) == -1) {
    //         Logger::get()->error("Failed to find network devices: {}", errbuf);
    //         return false;
    //     }
    
    //     // Use the first device if available
    //     if (!devices) {
    //         Logger::get()->error("No network devices found");
    //         return false;
    //     }
    
    //     handle_ = pcap_open_live(devices->name, BUFSIZ, 1, 1000, errbuf);
    //     pcap_freealldevs(devices);  // Free the device list
    
    //     if (handle_ == nullptr) {
    //         Logger::get()->error("Failed to open device: {}", errbuf);
    //         return false;
    //     }
    
    //     // Set filter to capture only IP packets
    //     struct bpf_program fp;
    //     char filter_exp[] = "ip";
    //     if (pcap_compile(handle_, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    //         Logger::get()->error("Failed to compile filter: {}", pcap_geterr(handle_));
    //         return false;
    //     }
    
    //     if (pcap_setfilter(handle_, &fp) == -1) {
    //         Logger::get()->error("Failed to set filter: {}", pcap_geterr(handle_));
    //         return false;
    //     }
    
    //     running_ = true;
    //     pcap_loop(handle_, -1, packetCallback, reinterpret_cast<u_char*>(this));
    //     return true;
    // }

    // bool ConnectionMonitor::start() {
    //     std::cout << "Debug: ConnectionMonitor::start() called\n";
    //     char errbuf[PCAP_ERRBUF_SIZE];
    //     pcap_if_t *devices;
        
    //     // Find all available devices
    //     if (pcap_findalldevs(&devices, errbuf) == -1) {
    //         std::cout << "Debug: Failed to find network devices: " << errbuf << std::endl;
    //         Logger::get()->error("Failed to find network devices: {}", errbuf);
    //         return false;
    //     }
    
    //     // Use the first device if available
    //     if (!devices) {
    //         std::cout << "Debug: No network devices found\n";
    //         Logger::get()->error("No network devices found");
    //         return false;
    //     }
    
    //     // Print available devices for debugging
    //     std::cout << "Debug: Available network devices:\n";
    //     pcap_if_t *d;
    //     int i = 0;
    //     for(d = devices; d; d = d->next) {
    //         std::cout << "Debug:   " << i++ << ": " << d->name;
    //         if (d->description)
    //             std::cout << " (" << d->description << ")";
    //         std::cout << std::endl;
    //     }
    
    //     // Allow override of interface via config
    //     std::string interface = devices->name; // Default to first device
        
    //     try {
    //         interface = Config::getInstance().get<std::string>("interface", devices->name);
    //         std::cout << "Debug: Using interface from config: " << interface << std::endl;
    //     } catch (const std::exception& e) {
    //         std::cout << "Debug: Error getting interface from config: " << e.what() << std::endl;
    //     }
        
    //     std::cout << "Debug: Opening device: " << interface << std::endl;
    //     handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    //     pcap_freealldevs(devices);  // Free the device list
    
    //     if (handle_ == nullptr) {
    //         std::cout << "Debug: Failed to open device: " << errbuf << std::endl;
    //         Logger::get()->error("Failed to open device: {}", errbuf);
    //         return false;
    //     }
    
    //     // Check datalink type
    //     int linktype = pcap_datalink(handle_);
    //     std::cout << "Debug: Device link layer type: " << linktype;
    //     switch(linktype) {
    //         case DLT_EN10MB:
    //             std::cout << " (Ethernet)";
    //             break;
    //         case DLT_IEEE802_11:
    //             std::cout << " (Wireless)";
    //             break;
    //         case DLT_NULL:
    //             std::cout << " (Loopback)";
    //             break;
    //         case DLT_LINUX_SLL:
    //             std::cout << " (Linux cooked)";
    //             break;
    //         default:
    //             std::cout << " (Other)";
    //     }
    //     std::cout << std::endl;
    
    //     // Set filter to capture only IP packets
    //     struct bpf_program fp;
    //     char filter_exp[] = "ip";
    //     std::cout << "Debug: Compiling filter: " << filter_exp << std::endl;
    //     if (pcap_compile(handle_, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    //         std::cout << "Debug: Failed to compile filter: " << pcap_geterr(handle_) << std::endl;
    //         Logger::get()->error("Failed to compile filter: {}", pcap_geterr(handle_));
    //         return false;
    //     }
    
    //     std::cout << "Debug: Setting filter\n";
    //     if (pcap_setfilter(handle_, &fp) == -1) {
    //         std::cout << "Debug: Failed to set filter: " << pcap_geterr(handle_) << std::endl;
    //         Logger::get()->error("Failed to set filter: {}", pcap_geterr(handle_));
    //         return false;
    //     }
    
    //     running_ = true;
    //     std::cout << "Debug: Connection monitoring started on interface: " << interface << std::endl;
    //     Logger::get()->info("Connection monitoring started on interface: {}", interface);
        
    //     std::cout << "Debug: Starting packet capture loop\n";
    //     // Start packet capture - this is a blocking call
    //     pcap_loop(handle_, -1, packetCallback, reinterpret_cast<u_char*>(this));
        
    //     std::cout << "Debug: pcap_loop exited\n";
    //     return true;
    // }
#include "../../include/monitor/connection_monitor.hpp"
#include "../../include/utils/logger.hpp"
#include "../../include/utils/config.hpp"
#include <stdexcept>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

namespace Firewall {

    ConnectionMonitor::ConnectionMonitor() 
        : handle_(nullptr), running_(false), ruleManager_(std::make_unique<RuleManager>()) {
    }
    
    ConnectionMonitor::~ConnectionMonitor() {
        stop();
    }
    
    bool ConnectionMonitor::start() {
        std::cout << "Debug: ConnectionMonitor::start() called\n";
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *devices;
        
        // Find all available devices
        if (pcap_findalldevs(&devices, errbuf) == -1) {
            std::cout << "Debug: Failed to find network devices: " << errbuf << std::endl;
            Logger::get()->error("Failed to find network devices: {}", errbuf);
            return false;
        }
    
        // Use the first device if available
        if (!devices) {
            std::cout << "Debug: No network devices found\n";
            Logger::get()->error("No network devices found");
            return false;
        }
    
        // Print available devices for debugging
        std::cout << "Debug: Available network devices:\n";
        pcap_if_t *d;
        int i = 0;
        for(d = devices; d; d = d->next) {
            std::cout << "Debug:   " << i++ << ": " << d->name;
            if (d->description)
                std::cout << " (" << d->description << ")";
            std::cout << std::endl;
        }
    
        // Hardcode to en0 as a temporary fix - replace this with proper config loading later
        std::string interface = "en0";
        std::cout << "Debug: Using hardcoded interface: " << interface << std::endl;
        
        std::cout << "Debug: Opening device: " << interface << std::endl;
        handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        
        if (handle_ == nullptr) {
            std::cout << "Debug: Failed to open en0, falling back to first available device" << std::endl;
            interface = devices->name;
            handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        }
        
        pcap_freealldevs(devices);  // Free the device list
    
        if (handle_ == nullptr) {
            std::cout << "Debug: Failed to open device: " << errbuf << std::endl;
            Logger::get()->error("Failed to open device: {}", errbuf);
            return false;
        }
    
        // Check datalink type
        int linktype = pcap_datalink(handle_);
        std::cout << "Debug: Device link layer type: " << linktype;
        switch(linktype) {
            case DLT_EN10MB:
                std::cout << " (Ethernet)";
                break;
            case DLT_IEEE802_11:
                std::cout << " (Wireless)";
                break;
            case DLT_NULL:
                std::cout << " (Loopback)";
                break;
            case DLT_LINUX_SLL:
                std::cout << " (Linux cooked)";
                break;
            default:
                std::cout << " (Other)";
        }
        std::cout << std::endl;
    
        // Set filter to capture only IP packets
        struct bpf_program fp;
        char filter_exp[] = "ip";
        std::cout << "Debug: Compiling filter: " << filter_exp << std::endl;
        if (pcap_compile(handle_, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cout << "Debug: Failed to compile filter: " << pcap_geterr(handle_) << std::endl;
            Logger::get()->error("Failed to compile filter: {}", pcap_geterr(handle_));
            return false;
        }
    
        std::cout << "Debug: Setting filter\n";
        if (pcap_setfilter(handle_, &fp) == -1) {
            std::cout << "Debug: Failed to set filter: " << pcap_geterr(handle_) << std::endl;
            Logger::get()->error("Failed to set filter: {}", pcap_geterr(handle_));
            return false;
        }
    
        running_ = true;
        std::cout << "Debug: Connection monitoring started on interface: " << interface << std::endl;
        Logger::get()->info("Connection monitoring started on interface: {}", interface);
        
        std::cout << "Debug: Starting packet capture loop\n";
        // Start packet capture - this is a blocking call
        pcap_loop(handle_, -1, packetCallback, reinterpret_cast<u_char*>(this));
        
        std::cout << "Debug: pcap_loop exited\n";
        return true;
    }
    
    void ConnectionMonitor::stop() {
        if (running_ && handle_) {
            pcap_breakloop(handle_);
            pcap_close(handle_);
            handle_ = nullptr;
            running_ = false;
        }
    }
    
    bool ConnectionMonitor::isRunning() const {
        return running_;
    }
    
    void ConnectionMonitor::packetCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        static int count = 0;
        if (count++ % 100 == 0) {  // Only print every 100 packets to avoid console spam
            std::cout << "Debug: Packet #" << count << " received, length: " << pkthdr->len << std::endl;
        }
        
        auto* monitor = reinterpret_cast<ConnectionMonitor*>(user);
        try {
            monitor->processPacket(pkthdr, packet);
        } catch (const std::exception& e) {
            std::cout << "Debug: Exception in processPacket: " << e.what() << std::endl;
        }
    }
    
    void ConnectionMonitor::processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        // Skip ethernet header - FIXED: Use ::ip to refer to global namespace
        const struct ::ip* ip = reinterpret_cast<const struct ::ip*>(packet + 14);
        
        char srcIP[INET_ADDRSTRLEN];
        char dstIP[INET_ADDRSTRLEN];
        
        inet_ntop(AF_INET, &(ip->ip_src), srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->ip_dst), dstIP, INET_ADDRSTRLEN);
    
        // For TCP packets, get port information
        if (ip->ip_p == IPPROTO_TCP) {
            const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + 14 + (ip->ip_hl << 2));
            
            // Handle different tcphdr struct variations across systems
            int srcPort, dstPort;
            #ifdef __APPLE__
                srcPort = ntohs(tcp->th_sport);
                dstPort = ntohs(tcp->th_dport);
            #else
                // Linux might use different field names
                srcPort = ntohs(tcp->source);
                dstPort = ntohs(tcp->dest);
            #endif
    
            Logger::get()->debug("TCP Connection: {}:{} -> {}:{}", 
                srcIP, srcPort, dstIP, dstPort);
    
            // Evaluate connection against rules
            if (!ruleManager_->evaluateConnection("unknown", dstIP, dstPort)) {
                Logger::get()->info("Blocked connection to {}:{}", dstIP, dstPort);
                // Implement blocking mechanism here
            }
        }
    }

    // PUBLIC RULE MANAGER ACCESS METHODS - IMPLEMENTATION
    bool ConnectionMonitor::addRule(const Rule& rule) {
        if (ruleManager_) {
            return ruleManager_->addRule(rule);
        }
        return false;
    }

    bool ConnectionMonitor::removeRule(const std::string& application) {
        if (ruleManager_) {
            return ruleManager_->removeRule(application);
        }
        return false;
    }

    bool ConnectionMonitor::loadRules(const std::string& filename) {
        if (ruleManager_) {
            return ruleManager_->loadRules(filename);
        }
        return false;
    }

    bool ConnectionMonitor::saveRules(const std::string& filename) {
        if (ruleManager_) {
            return ruleManager_->saveRules(filename);
        }
        return false;
    }

    const std::vector<Rule>& ConnectionMonitor::getRules() const {
        if (ruleManager_) {
            return ruleManager_->getRules();
        }
        // Return empty static vector if no rule manager
        static std::vector<Rule> empty_rules;
        return empty_rules;
    }

    bool ConnectionMonitor::hasRuleManager() const {
        return ruleManager_ != nullptr;
    }

    // Stub implementations for missing methods
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

    void ConnectionMonitor::staticPacketCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        packetCallback(user, pkthdr, packet);
    }

    // Stub implementations for protected methods - FIXED: Use ::ip 
    void ConnectionMonitor::processTCPPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, 
                                           const struct ::ip* ip, const char* srcIP, const char* dstIP) {
        // Implementation placeholder
    }

    void ConnectionMonitor::processUDPPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, 
                                           const struct ::ip* ip, const char* srcIP, const char* dstIP) {
        // Implementation placeholder
    }

    std::string ConnectionMonitor::getLocalIPAddress() {
        return "127.0.0.1"; // Placeholder
    }

    void ConnectionMonitor::addToActiveConnections(const std::string& app, const std::string& remoteIP, 
                                                 int remotePort, const std::string& protocol) {
        // Implementation placeholder
    }

    void ConnectionMonitor::addToRecentBlocks(const std::string& app, const std::string& remoteIP, 
                                            int remotePort, const std::string& reason) {
        // Implementation placeholder
    }

    void ConnectionMonitor::updateTrafficStats(size_t packetSize) {
        // Implementation placeholder
    }

    void ConnectionMonitor::startStatsCollection() {
        // Implementation placeholder
    }

    void ConnectionMonitor::stopStatsCollection() {
        // Implementation placeholder
    }

    void ConnectionMonitor::collectStats() {
        // Implementation placeholder
    }

    } // namespace Firewall