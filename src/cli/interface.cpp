#include "../../include/cli/interface.hpp"
#include "../../include/utils/logger.hpp"
#include "../../include/utils/config.hpp"
#include "../../include/monitor/process_monitor.hpp"
#include "../../include/geo/location_manager.hpp"
#include <iostream>
#include <string>
#include <thread>
#include <sstream>



namespace Firewall {
    namespace CLI {
    
        Interface::Interface(int argc, char* argv[]) 
        : monitor_(std::make_unique<ConnectionMonitor>()), 
          argc_(argc), 
          argv_(argv) {
        
        // Initialize config
        std::string configPath = getDefaultConfigPath();
        
        // Try to load existing config
        bool configLoaded = Config::getInstance().load(configPath);
        
        // If config couldn't be loaded, initialize with defaults
        if (!configLoaded) {
            Logger::get()->info("Creating default configuration");
            
            // Set default values using proper std::string objects
            Config::getInstance().set<std::string>("default_policy", std::string("allow"));
            Config::getInstance().set<std::string>("rules_file", getDefaultRulesPath());
            Config::getInstance().set<std::string>("log_level", std::string("info"));
            
            std::string homePath = getenv("HOME") ? std::string(getenv("HOME")) : std::string("/tmp");
            std::string profilesPath = homePath + "/.config/firewall/behavior_profiles.json";
            Config::getInstance().set<std::string>("behavior_profiles", profilesPath);
            
            Config::getInstance().set<int>("behavior_learning_period", 60);
            Config::getInstance().set<bool>("enable_behavior_monitoring", true);
            Config::getInstance().set<bool>("enable_geoip_filtering", true);
            Config::getInstance().set<bool>("prompt_for_unknown_connections", true);
            Config::getInstance().set<int>("blocked_count", 0);
            
            // Find default interface - this is critical to fix your issue
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_if_t* devices;
            if (pcap_findalldevs(&devices, errbuf) != -1 && devices != nullptr) {
                Config::getInstance().set<std::string>("interface", std::string(devices->name));
                pcap_freealldevs(devices);
            } else {
                // Fallback to a reasonable default if we can't find interfaces
                Config::getInstance().set<std::string>("interface", std::string("en0")); // Common default on macOS
            }
            
            // Save the config
            Config::getInstance().save(configPath);
        }
    }
    
    int Interface::run() {
        if (argc_ < 2) {
            showHelp();
            return 1;
        }
    
        std::string command = argv_[1];
    
        try {
            if (command == "start") {
                startMonitoring();
            }
            else if (command == "add-rule" && argc_ >= 5) {
                // add-rule <app> <action> <address> <port>
                addRule(argv_[2], argv_[3], argv_[4], argc_ >= 6 ? std::stoi(argv_[5]) : 0);
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
    
    void Interface::showHelp() {
        std::cout << "Network Firewall Usage:\n"
                  << "  firewall start              - Start monitoring\n"
                  << "  firewall add-rule APP ACTION - Add a rule\n"
                  << "  firewall list-rules         - List all rules\n"
                  << "  firewall status             - Show firewall status\n"
                  << "  firewall help               - Show this help message\n";
    }

    std::string Interface::getDefaultConfigPath() {
        std::string homePath;
        const char* homeEnv = getenv("HOME");
        if (homeEnv) {
            homePath = homeEnv;
        } else {
            homePath = "/tmp";
        }
        
        // return homePath + "/.config/firewall/config.json";
        return "/Users/samarthbhatia/Developer/Systems/flowatch/config/firewall/config.json";
    }
    
    std::string Interface::getDefaultRulesPath() {
        std::string homePath;
        const char* homeEnv = getenv("HOME");
        if (homeEnv) {
            homePath = homeEnv;
        } else {
            homePath = "/tmp";
        }
        
        // return homePath + "/.config/firewall/rules.json";
        return "/Users/samarthbhatia/Developer/Systems/flowatch/config/firewall/config.json";
    }

    void Interface::printInteractiveHelp() {
        std::cout << "Firewall Interactive Commands:\n"
                  << "  help                     - Show this help message\n"
                  << "  add-rule <app> <action> <address> <port> - Add a rule\n"
                  << "  block-country <code>    - Block a country by two-letter code\n"
                  << "  list-rules              - List all rules\n"
                  << "  status                  - Show firewall status\n"
                  << "  config <key> <value>    - Set configuration option\n"
                  << "  exit, quit              - Exit firewall\n";
    }

    void Interface::printRules() {
        std::cout << "Current Firewall Rules:\n"
                  << "------------------------\n"
                  << "App\t\tAction\tDirection\tProtocol\tAddress\t\tPort\tEnabled\n"
                  << "----------------------------------------------------------------------------\n";
        
        // In a real implementation, this would access the actual rules from the rule manager
        if (monitor_->ruleManager_) {
            // Just print a message for now since getRules() might not be implemented
            std::cout << "No rules to display at this time.\n";
            
            /* Uncomment this when getRules() is properly implemented
            const auto& rules = monitor_->ruleManager_->getRules();
            for (const auto& rule : rules) {
                std::cout << rule.application << "\t"
                          << rule.action << "\t"
                          << rule.direction << "\t\t"
                          << rule.protocol << "\t\t"
                          << rule.remote_address << "\t"
                          << rule.remote_port << "\t"
                          << (rule.enabled ? "Yes" : "No") << "\n";
            }
            */
        }
    }

    void Interface::blockCountry(const std::string& countryCode) {
        if (countryCode.length() != 2) {
            std::cout << "Invalid country code. Please use ISO 3166-1 alpha-2 code (e.g., US, CN).\n";
            return;
        }
        
        // Add a rule to block traffic to/from the specified country
        Rule rule;
        rule.application = "*";
        rule.action = "block";
        rule.direction = "both";
        rule.protocol = "*";
        rule.remote_address = "country:" + countryCode;
        rule.remote_port = 0;
        rule.enabled = true;
        
        bool success = monitor_->ruleManager_->addRule(rule);
        
        if (success) {
            std::cout << "Added rule to block traffic for country: " << countryCode << "\n";
            
            // Add country to blocked countries list in config
            auto blockedCountries = Config::getInstance().get<std::vector<std::string>>("blocked_countries", 
                                                                                      std::vector<std::string>());
            if (std::find(blockedCountries.begin(), blockedCountries.end(), countryCode) == blockedCountries.end()) {
                blockedCountries.push_back(countryCode);
                Config::getInstance().set("blocked_countries", blockedCountries);
                
                std::string configPath = getDefaultConfigPath();
                Config::getInstance().save(configPath);
            }
            
            // Save rules to file
            // std::string rulesFile = Config::getInstance().get<std::string>("rules_file", getDefaultRulesPath());
            // monitor_->ruleManager_->saveRules(rulesFile);

            std::string rulesFile = getDefaultRulesPath();
            monitor_->ruleManager_->saveRules(rulesFile);
        } else {
            std::cout << "Failed to add country blocking rule.\n";
        }
    }

    void Interface::parseInteractiveAddRule(const std::string& args) {
        std::istringstream iss(args);
        std::string app, action, address;
        int port = 0;
        
        if (!(iss >> app >> action >> address)) {
            std::cout << "Invalid rule format. Usage: add-rule <app> <action> <address> [port]\n";
            return;
        }
        
        // Optional port
        iss >> port;
        
        addRule(app, action, address, port);
    }
    void Interface::setConfig(const std::string& key, const std::string& value) {
        // Simple implementation for now
        std::cout << "Setting configuration: " << key << " = " << value << std::endl;
        
        // Uncomment the following when Config is fully working
        /*
        Config::getInstance().set(key, value);
        std::string configPath = getDefaultConfigPath();
        Config::getInstance().save(configPath);
        
        // If it's the rules_file config, reload rules
        if (key == "rules_file" && monitor_->ruleManager_) {
            bool success = monitor_->ruleManager_->loadRules(value);
            if (success) {
                std::cout << "Rules reloaded from new file location.\n";
            } else {
                std::cout << "Failed to load rules from new file location.\n";
            }
        }
        
        // If it's the geoip_file config, reload the database
        if (key == "geoip_file") {
            bool success = Geo::LocationManager::getInstance().loadDatabase(value);
            if (success) {
                std::cout << "GeoIP database loaded successfully.\n";
            } else {
                std::cout << "Failed to load GeoIP database.\n";
            }
        }
        */
    }

    void Interface::parseInteractiveConfig(const std::string& args) {
        std::istringstream iss(args);
        std::string key, value;
        
        if (!(iss >> key >> value)) {
            std::cout << "Invalid config format. Usage: config <key> <value>\n";
            return;
        }
        
        setConfig(key, value);
    }

    void Interface::printStatus() {
        std::cout << "Firewall Status:\n"
                  << "---------------\n"
                  << "Running: " << (monitor_->isRunning() ? "Yes" : "No") << "\n";
        
        // Print active connections
        std::cout << "Active Connections (limited to 10 most recent):\n";
        // In a real implementation, you'd track and display actual connections here
        
        // Print blocked connections count
        std::cout << "Blocked Connections: " << Config::getInstance().get<int>("blocked_count", 0) << "\n";
        
        // Print config info
        std::cout << "\nConfiguration:\n";
        std::cout << "  Rules File: " << Config::getInstance().get<std::string>("rules_file", getDefaultRulesPath()) << "\n";
        std::cout << "  Default Policy: " << Config::getInstance().get<std::string>("default_policy", "allow") << "\n";
        std::cout << "  Log Level: " << Config::getInstance().get<std::string>("log_level", "info") << "\n";
        
        // Print GeoIP status
        std::string geoipFile = Config::getInstance().get<std::string>("geoip_file", "");
        if (!geoipFile.empty()) {
            std::cout << "  GeoIP Database: " << geoipFile << "\n";
            auto blockedCountries = Config::getInstance().get<std::vector<std::string>>("blocked_countries", 
                                                                                      std::vector<std::string>());
            if (!blockedCountries.empty()) {
                std::cout << "  Blocked Countries: ";
                for (size_t i = 0; i < blockedCountries.size(); i++) {
                    std::cout << blockedCountries[i];
                    if (i < blockedCountries.size() - 1) {
                        std::cout << ", ";
                    }
                }
                std::cout << "\n";
            }
        } else {
            std::cout << "  GeoIP Database: Not configured\n";
        }
    }
    
    // void Interface::startMonitoring() {
    //     std::cout << "Starting network monitoring...\n";
        
    //     // Start monitoring in a separate thread
    //     std::thread monitorThread([this]() {
    //         monitor_->start();
    //     });
    
    //     // Keep the main thread alive and handling user input
    //     std::string input;
    //     while (true) {
    //         std::getline(std::cin, input);
    //         if (input == "quit" || input == "exit") {
    //             break;
    //         }
    //     }
    
    //     monitor_->stop();
    //     if (monitorThread.joinable()) {
    //         monitorThread.join();
    //     }
    // }
    void Interface::startMonitoring() {
        std::cout << "Starting network monitoring...\n";
        std::cout << "Debug: Initializing process monitor...\n";
        
        // Start process monitor
        ProcessMonitor::getInstance().start();
        
        std::cout << "Debug: Loading rules...\n";
        // Load rules from default location
        std::string rulesFile = Config::getInstance().get<std::string>("rules_file", getDefaultRulesPath());
        std::cout << "Debug: Using rules file: " << rulesFile << "\n";
        
        bool rulesLoaded = monitor_->ruleManager_->loadRules(rulesFile);
        if (!rulesLoaded) {
            std::cout << "Debug: Failed to load rules from " << rulesFile << ". Using default rules.\n";
            Logger::get()->warn("Failed to load rules from {}. Using default rules.", rulesFile);
        } else {
            std::cout << "Debug: Rules loaded successfully.\n";
        }
        
        // Load GeoIP database if configured
        std::string geoipFile = Config::getInstance().get<std::string>("geoip_file", "");
        if (!geoipFile.empty()) {
            std::cout << "Debug: Loading GeoIP database from " << geoipFile << "\n";
            bool geoipLoaded = Geo::LocationManager::getInstance().loadDatabase(geoipFile);
            if (!geoipLoaded) {
                std::cout << "Debug: Failed to load GeoIP database.\n";
                Logger::get()->warn("Failed to load GeoIP database from {}", geoipFile);
            } else {
                std::cout << "Debug: GeoIP database loaded successfully.\n";
            }
        }
        
        std::cout << "Debug: Starting monitoring thread...\n";
        // Start monitoring in a separate thread
        std::thread monitorThread([this]() {
            std::cout << "Debug: In monitor thread, calling monitor->start()...\n";
            try {
                bool startResult = monitor_->start();
                std::cout << "Debug: monitor->start() returned " << (startResult ? "true" : "false") << "\n";
            } catch (const std::exception& e) {
                std::cout << "Debug: Exception in monitor thread: " << e.what() << "\n";
            }
        });
    
        // Give the monitor thread a moment to initialize
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        std::cout << "Debug: Entering interactive mode...\n";
        // Keep the main thread alive and handling user input
        printInteractiveHelp();
        
        std::string input;
        std::cout << "firewall> ";
        std::cout.flush(); // Make sure prompt is displayed
        
        while (true) {
            if (!std::getline(std::cin, input)) {
                std::cout << "Debug: Error reading from stdin\n";
                break;
            }
            
            std::cout << "Debug: Received input: '" << input << "'\n";
            
            if (input == "quit" || input == "exit") {
                std::cout << "Debug: Exiting...\n";
                break;
            } else if (input == "help") {
                printInteractiveHelp();
            } else if (input == "status") {
                printStatus();
            } else if (input.substr(0, 9) == "add-rule ") {
                parseInteractiveAddRule(input.substr(9));
            } else if (input.substr(0, 13) == "block-country ") {
                blockCountry(input.substr(13));
            } else if (input == "list-rules") {
                printRules();
            } else if (input.substr(0, 7) == "config ") {
                parseInteractiveConfig(input.substr(7));
            } else if (!input.empty()) {
                std::cout << "Unknown command. Type 'help' for available commands.\n";
            }
            
            std::cout << "firewall> ";
            std::cout.flush(); // Make sure prompt is displayed
        }
    
        std::cout << "Debug: Stopping monitors...\n";
        monitor_->stop();
        ProcessMonitor::getInstance().stop();
        
        if (monitorThread.joinable()) {
            std::cout << "Debug: Joining monitor thread...\n";
            monitorThread.join();
            std::cout << "Debug: Monitor thread joined.\n";
        }
        
        // Save rules before exiting
        std::cout << "Debug: Saving rules...\n";
        monitor_->ruleManager_->saveRules(rulesFile);
        std::cout << "Debug: Monitoring stopped.\n";
    }


    void Interface::addRule(const std::string& app, const std::string& action, 
        const std::string& address, int port) {
        Rule rule;
        rule.application = app;
        rule.action = action;
        rule.direction = "outbound"; // Default direction
        rule.protocol = "tcp";       // Default protocol
        rule.remote_address = address;
        rule.remote_port = port;
        rule.enabled = true;

        bool success = monitor_->ruleManager_->addRule(rule);

        if (success) {
        std::cout << "Rule added successfully.\n";
        // Save rules to file
        std::string rulesFile = Config::getInstance().get<std::string>("rules_file", getDefaultRulesPath());
        monitor_->ruleManager_->saveRules(rulesFile);
        } else {
        std::cout << "Failed to add rule.\n";
        }
    }
    
    void Interface::listRules() {
        std::cout << "Current Firewall Rules:\n"
                  << "------------------------\n";
        // Implement rule listing here
    }
    
    void Interface::showStatus() {
        std::cout << "Firewall Status:\n"
                  << "---------------\n"
                  << "Running: " << (monitor_->isRunning() ? "Yes" : "No") << "\n";
        // Add more status information here
    }
    
    } // namespace CLI
    } // namespace Firewall