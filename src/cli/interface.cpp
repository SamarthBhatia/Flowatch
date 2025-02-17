#include "../../include/cli/interface.hpp"
#include "../../include/utils/logger.hpp"
#include <iostream>
#include <string>
#include <thread>

namespace Firewall{
    namespace CLI{
        Interface::Interface(int argc, char* argv[])
            : monitor_(std::make_unique<ConnectionMonitor>()),argc_(argc),argv_(argv){}
        
            int Interface::run(){
                if (argc_ < 2){
                    showHelp();
                    return 1;
                }
                std::string command = argv_[1];
                try{
                    if (command == "start") {
                        startMonitoring();
                    }
                    else if (command == "add-rule" && argc_ >= 4) {
                        addRule(argv_[2], argv_[3]);
                    }
                    else if (command == "list-rules") {
                        listRules();
                    }
                    else if (command == "status") {
                        showStatus();
                    }
                    else if (command == "help") {
                        showHelp();
                    }
                    else {
                        std::cout << "Unknown command: " << command << std::endl;
                        showHelp();
                        return 1;
                    }
                }
                catch (const std::exception& e) {
                    Logger::get()->error("Error executing command: {}", e.what());
                    return 1;
                }
            
                return 0;
            }

            void Interface::showHelp(){
                std::cout << "Network Firewall Usage:\n"
              << "  firewall start              - Start monitoring\n"
              << "  firewall add-rule APP ACTION - Add a rule\n"
              << "  firewall list-rules         - List all rules\n"
              << "  firewall status             - Show firewall status\n"
              << "  firewall help               - Show this help message\n";
            }

            void Interface::startMonitoring() {
                std::cout << "Starting network monitoring...\n";
                
                // Start monitoring in a separate thread
                std::thread monitorThread([this]() {
                    monitor_->start();
                });
            
                // Keep the main thread alive and handling user input
                std::string input;
                while (true) {
                    std::getline(std::cin, input);
                    if (input == "quit" || input == "exit") {
                        break;
                    }
                }
            
                monitor_->stop();
                if (monitorThread.joinable()) {
                    monitorThread.join();
                }
            }
            
            void Interface::addRule(const std::string& app, const std::string& action) {
                Rule rule;
                rule.application = app;
                rule.action = action;
                rule.enabled = true;
                
                
                Logger::get()->info("Adding rule for {}: {}", app, action);
            
            }
            
            void Interface::listRules() {
                std::cout << "Current Firewall Rules:\n"
                          << "------------------------\n";
                
            }
            
            void Interface::showStatus() {
                std::cout << "Firewall Status:\n"
                          << "---------------\n"
                          << "Running: " << (monitor_->isRunning() ? "Yes" : "No") << "\n";
                
            }
    }
}