#pragma once

#include <string>
#include <memory>
#include "../monitor/connection_monitor.hpp"

namespace Firewall{
    namespace CLI{
        class Interface{
            public:
                Interface(int argc, char* argv[]);
                ~Interface() = default;

                int run();

            private:
                void showHelp();
                void startMonitoring();
                void addRule(const std::string& app, const std::string& action);
                void listRules();
                void showStatus();

                std::unique_ptr<ConnectionMonitor> monitor_;
                int argc_;
                char** argv_;
        };
    }
}