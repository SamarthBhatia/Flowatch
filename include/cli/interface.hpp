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
                // void addRule(const std::string& app, const std::string& action);
                void addRule(const std::string& app, const std::string& action, 
                    const std::string& address, int port);
                void blockCountry(const std::string& countryCode);
                void listRules();
                void showStatus();
                void setConfig(const std::string& key, const std::string& value);

                void printInteractiveHelp();
                void printStatus();
                void printRules();
                void parseInteractiveAddRule(const std::string& args);
                void parseInteractiveConfig(const std::string& args);
                std::string getDefaultConfigPath();
                std::string getDefaultRulesPath();

                std::unique_ptr<ConnectionMonitor> monitor_;
                int argc_;
                char** argv_;
        };
    }
}