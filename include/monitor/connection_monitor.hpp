#pragma once

#include <string>
#include <vector>
#include <memory>
#include <pcap.h>
#include "rules/rule_manager.hpp"

namespace Firewall{
    class ConnectionMonitor{
        public:
            ConnectionMonitor();
            ~ConnectionMonitor();

            bool start();
            void stop();
            bool isRunning() const;
        private:
            static void packetCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
            void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
            pcap_t* handle_;
            bool running_;
            std::unique_ptr<RuleManager> ruleManager_;
    }; 
}