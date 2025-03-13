#include "../../include/cli/interface.hpp"
#include "../../include/utils/logger.hpp"
#include "../../include/utils/config.hpp"
#include "../../include/monitor/process_monitor.hpp"
#include "../../include/geo/location_manager.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <filesystem>

namespace Firewall {
namespace CLI {

Interface::Interface(int argc, char* argv[]) 
    : monitor_(std::make_unique<ConnectionMonitor>()), 
      argc_(argc), 
      argv_(argv) {
    
    // Initialize config
    std::string configPath = getDefaultConfigPath();
    Config::getInstance().load(configPath);
    
    // Set default config values if needed
    if (Config::getInstance().get<std::string>("rules_file", "") == "") {
        Config::getInstance().set("rules_file", getDefaultRulesPath());
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
        else if (command == "block-country" && argc_ >= 3) {
            blockCountry(argv_[2]);
        }
        else if (command == "list-rules") {
            listRules();
        }
        else if (command == "status") {
            showStatus();
        }
        else if (command == "config" && argc_ >= 4) {
            setConfig(argv_[2], argv_[3]);
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
              << "  firewall start                          - Start monitoring\n"
              << "  firewall add-rule <app> <action> <address> <port> - Add a rule\n"
              << "  firewall block-country <country_code>    - Block a country by two-letter code\n"
              << "  firewall list-rules                     - List all rules\n"
              << "  firewall status                         - Show firewall status\n"
              << "  firewall config <key> <value>            - Set configuration option\n"
              << "  firewall help                           - Show this help message\n";
}

void Interface::startMonitoring() {
    std::cout << "Starting network monitoring...\n";
    
    // Start process monitor
    ProcessMonitor::getInstance().start();
    
    // Load rules from default location
    std::string rulesFile = Config::getInstance().get<std::string>("rules_file", getDefaultRulesPath());
    bool rulesLoaded = monitor_->ruleManager_->loadRules(rulesFile);
    if (!rulesLoaded) {
        Logger::get()->warn("Failed to load rules from {}. Using default rules.", rulesFile);
    }
    
    // Load GeoIP database if configured
    std::string geoipFile = Config::getInstance().get<std::string>("geoip_file", "");
    if (!geoipFile.empty()) {
        bool geoipLoaded = Geo::LocationManager::getInstance().loadDatabase(geoipFile);
        if (!geoipLoaded) {
            Logger::get()->warn("Failed to load GeoIP database from {}", geoipFile);
        }
    }
    
    // Start monitoring in a separate thread
    std::thread monitorThread([this]() {
        monitor_->start();
    });

    // Keep the main thread alive and handling user input
    printInteractiveHelp();
    
    std::string input;
    while (true) {
        std::cout << "firewall> ";
        std::getline(std::cin, input);
        
        if (input == "quit" || input == "exit") {
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
        } else {
            std::cout << "Unknown command. Type 'help' for available commands.\n";
        }
    }

    monitor_->stop();
    ProcessMonitor::getInstance().stop();
    
    if (monitorThread.joinable()) {
        monitorThread.join();
    }
    
    // Save rules before exiting
    monitor_->ruleManager_->saveRules(rulesFile);
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
        std::string rulesFile = Config::getInstance().get<std::string>("rules_file", getDefaultRulesPath());
        monitor_->ruleManager_->saveRules(rulesFile);
    } else {
        std::cout << "Failed to add country blocking rule.\n";
    }
}

void Interface::listRules() {
    printRules();
}

void Interface::showStatus() {
    printStatus();
}

void Interface::setConfig(const std::string& key, const std::string& value) {
    Config::getInstance().set(key, value);
    std::string configPath = getDefaultConfigPath();
    Config::getInstance().save(configPath);
    std::cout << "Configuration set: " << key << " = " << value << "\n";
    
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

void Interface::printRules() {
    std::cout << "Current Firewall Rules:\n"
              << "------------------------\n"
              << "App\t\tAction\tDirection\tProtocol\tAddress\t\tPort\tEnabled\n"
              << "----------------------------------------------------------------------------\n";
    
    // In a real implementation, this would access the actual rules from the rule manager
    if (monitor_->ruleManager_) {
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

void Interface::parseInteractiveConfig(const std::string& args) {
    std::istringstream iss(args);
    std::string key, value;
    
    if (!(iss >> key >> value)) {
        std::cout << "Invalid config format. Usage: config <key> <value>\n";
        return;
    }
    
    setConfig(key, value);
}

std::string Interface::getDefaultConfigPath() {
    std::string homePath;
    const char* homeEnv = getenv("HOME");
    if (homeEnv) {
        homePath = homeEnv;
    } else {
        homePath = "/tmp";
    }
    
    return homePath + "/.config/firewall/config.json";
}

std::string Interface::getDefaultRulesPath() {
    std::string homePath;
    const char* homeEnv = getenv("HOME");
    if (homeEnv) {
        homePath = homeEnv;
    } else {
        homePath = "/tmp";
    }
    
    return homePath + "/.config/firewall/rules.json";
}

} // namespace CLI
} // namespace Firewall
