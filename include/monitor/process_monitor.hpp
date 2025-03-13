#pragma once

#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <tuple>

namespace Firewall{

    using ConnectionKey = std::tuple<std::string, std::string, int, int>;

    class ProcessMonitor{
        public:
            static ProcessMonitor& getInstance();

            void start();
            void stop();

            std::string getProcessForConnection(const std::string& local_ip, int local_port, const std::string& remote_ip, int remote_port);
            std::string getExecutablePath(int pid);

        private:
            ProcessMonitor();
            ~ProcessMonitor();

            void refreshConnections();

            std::map<ConnectionKey, std::string> connections_;
            std::mutex mutex_;
            std::thread monitor_thread_;
            std::atomic<bool> running_;
    };

}