#include "../../include/monitor/connection_monitor.hpp"
#include "../../include/utils/logger.hpp"
#include <stdexcept>
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
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *devices;
        
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
    
        handle_ = pcap_open_live(devices->name, BUFSIZ, 1, 1000, errbuf);
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
        pcap_loop(handle_, -1, packetCallback, reinterpret_cast<u_char*>(this));
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
    
        // For TCP packets, get port information
        if (ip->ip_p == IPPROTO_TCP) {
            const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + 14 + (ip->ip_hl << 2));
            int srcPort = ntohs(tcp->th_sport);
            int dstPort = ntohs(tcp->th_dport);
    
            Logger::get()->debug("TCP Connection: {}:{} -> {}:{}", 
                srcIP, srcPort, dstIP, dstPort);
    
            // Evaluate connection against rules
            if (!ruleManager_->evaluateConnection("unknown", dstIP, dstPort)) {
                Logger::get()->info("Blocked connection to {}:{}", dstIP, dstPort);
                // Implement blocking mechanism here
            }
        }
    }
    
    } // namespace Firewall