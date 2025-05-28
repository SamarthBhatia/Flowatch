// #include "../../include/rules/rule_manager.hpp"
// #include "../../include/utils/logger.hpp"

// #include <filesystem>
// #include <fstream>

// namespace Firewall {

// RuleManager::RuleManager() {
//     // Initialize with default rules if needed
// }

// bool RuleManager::loadRules(const std::string& filename) {
//     try {
//         std::ifstream file(filename);
//         if (!file.is_open()) {
//             Logger::get()->error("Failed to open rule file: {}", filename);
//             return false;
//         }
        
//         // Simple rule parsing implementation
//         std::string line;
//         while (std::getline(file, line)) {
//             // Parse the line and create a rule
//             // This is a simple placeholder
//         }
        
//         return true;
//     } catch (const std::exception& e) {
//         Logger::get()->error("Error loading rules: {}", e.what());
//         return false;
//     }
// }

// bool RuleManager::saveRules(const std::string& filename) {
//     try {

//         std::filesystem::path filePath(filename);
//         std::filesystem::create_directories(filePath.parent_path());
        

//         std::ofstream file(filename);
//         if (!file.is_open()) {
//             Logger::get()->error("Failed to open rule file for writing: {}", filename);
//             return false;
//         }
        
//         // Write rules to file
//         for (const auto& rule : rules_) {
//             file << rule.application << "," 
//                  << rule.action << "," 
//                  << rule.remote_address << "," 
//                  << rule.remote_port << "\n";
//         }
        
//         return true;
//     } catch (const std::exception& e) {
//         Logger::get()->error("Error saving rules: {}", e.what());
//         return false;
//     }
// }

// bool RuleManager::evaluateConnection(const std::string& app, const std::string& address, int port) {
//     // For now, allow all connections
//     Logger::get()->debug("Evaluating connection from {} to {}:{}", app, address, port);
    
//     // In a real implementation, you would search through rules and apply them
//     for (const auto& rule : rules_) {
//         if (rule.application == app || rule.application == "*") {
//             if (rule.remote_address == address || rule.remote_address == "*") {
//                 if (rule.remote_port == port || rule.remote_port == 0) {
//                     return rule.action == "allow";
//                 }
//             }
//         }
//     }
    
//     // Default: allow connections if no matching rule is found
//     return true;
// }

// bool RuleManager::addRule(const Rule& rule) {
//     try {
//         // Check if rule already exists (same app, direction, protocol, address, port)
//         for (size_t i = 0; i < rules_.size(); i++) {
//             if (rules_[i].application == rule.application &&
//                 rules_[i].direction == rule.direction &&
//                 rules_[i].protocol == rule.protocol &&
//                 rules_[i].remote_address == rule.remote_address &&
//                 rules_[i].remote_port == rule.remote_port) {
                
//                 // Update existing rule
//                 rules_[i] = rule;
//                 Logger::get()->info("Updated rule for {}", rule.application);
//                 return true;
//             }
//         }
        
//         // Add new rule
//         rules_.push_back(rule);
//         Logger::get()->info("Added new rule for {}", rule.application);
//         return true;
//     } catch (const std::exception& e) {
//         Logger::get()->error("Error adding rule: {}", e.what());
//         return false;
//     }
// }

// const std::vector<Rule>& RuleManager::getRules() const {
//     return rules_;
// }

// } // namespace Firewall

#include "../../include/rules/rule_manager.hpp"
#include "../../include/utils/logger.hpp"
#include "../../include/utils/config.hpp"

#include <fstream>
#include <algorithm>
#include <sys/stat.h>
#include <sys/types.h>
#include <string>

namespace Firewall {

// Helper functions to replace std::filesystem
bool fileExists(const std::string& filename) {
    struct stat st;
    return stat(filename.c_str(), &st) == 0;
}

bool createDirectory(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return mkdir(path.c_str(), 0755) == 0;
    }
    return S_ISDIR(st.st_mode);
}

std::string getDirectoryPath(const std::string& filepath) {
    size_t lastSlash = filepath.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        return filepath.substr(0, lastSlash);
    }
    return "."; // Current directory if no path separator found
}

bool createDirectoriesRecursive(const std::string& path) {
    if (path.empty() || path == "." || path == "/") {
        return true;
    }
    
    // Check if directory already exists
    struct stat st;
    if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        return true;
    }
    
    // Get parent directory
    std::string parentPath = getDirectoryPath(path);
    if (parentPath != path) {
        // Recursively create parent directories
        if (!createDirectoriesRecursive(parentPath)) {
            return false;
        }
    }
    
    // Create this directory
    return mkdir(path.c_str(), 0755) == 0;
}

RuleManager::RuleManager() {
    // Initialize with default rules if needed
    Rule defaultRule;
    defaultRule.application = "*";
    defaultRule.action = "allow";
    defaultRule.direction = "outbound";
    defaultRule.protocol = "tcp";
    defaultRule.remote_address = "*";
    defaultRule.remote_port = 0;
    defaultRule.enabled = true;
    
    rules_.push_back(defaultRule);
}

bool RuleManager::loadRules(const std::string& filename) {
    try {
        if (!fileExists(filename)) {
            Logger::get()->warn("Rule file does not exist: {}", filename);
            return false;
        }
        
        std::ifstream file(filename);
        if (!file.is_open()) {
            Logger::get()->error("Failed to open rule file: {}", filename);
            return false;
        }
        
        // Parse the JSON file
        nlohmann::json rulesJson;
        file >> rulesJson;
        
        // Clear existing rules and load from JSON
        rules_.clear();
        
        for (const auto& ruleJson : rulesJson) {
            Rule rule;
            rule.application = ruleJson.value("application", "*");
            rule.action = ruleJson.value("action", "allow");
            rule.direction = ruleJson.value("direction", "outbound");
            rule.protocol = ruleJson.value("protocol", "tcp");
            rule.remote_address = ruleJson.value("remote_address", "*");
            rule.remote_port = ruleJson.value("remote_port", 0);
            rule.enabled = ruleJson.value("enabled", true);
            
            if (isValidRule(rule)) {
                rules_.push_back(rule);
            }
        }
        
        Logger::get()->info("Loaded {} rules from {}", rules_.size(), filename);
        return true;
    } catch (const std::exception& e) {
        Logger::get()->error("Error loading rules: {}", e.what());
        return false;
    }
}

bool RuleManager::saveRules(const std::string& filename) {
    try {
        // Create directory structure if it doesn't exist - FIXED VERSION
        std::string dirPath = getDirectoryPath(filename);
        if (!dirPath.empty() && dirPath != ".") {
            if (!createDirectoriesRecursive(dirPath)) {
                Logger::get()->error("Failed to create directory: {}", dirPath);
                return false;
            }
        }
        
        std::ofstream file(filename);
        if (!file.is_open()) {
            Logger::get()->error("Failed to open rule file for writing: {}", filename);
            return false;
        }
        
        // Create JSON array from rules
        nlohmann::json rulesJson = nlohmann::json::array();
        
        for (const auto& rule : rules_) {
            nlohmann::json ruleJson;
            ruleJson["application"] = rule.application;
            ruleJson["action"] = rule.action;
            ruleJson["direction"] = rule.direction;
            ruleJson["protocol"] = rule.protocol;
            ruleJson["remote_address"] = rule.remote_address;
            ruleJson["remote_port"] = rule.remote_port;
            ruleJson["enabled"] = rule.enabled;
            
            rulesJson.push_back(ruleJson);
        }
        
        // Write pretty-printed JSON to file
        file << std::setw(4) << rulesJson << std::endl;
        
        Logger::get()->info("Saved {} rules to {}", rules_.size(), filename);
        return true;
    } catch (const std::exception& e) {
        Logger::get()->error("Error saving rules: {}", e.what());
        return false;
    }
}

bool RuleManager::addRule(const Rule& rule) {
    try {
        if (!isValidRule(rule)) {
            Logger::get()->error("Invalid rule provided");
            return false;
        }
        
        // Check if rule already exists (same app, direction, protocol, address, port)
        for (size_t i = 0; i < rules_.size(); i++) {
            if (rules_[i].application == rule.application &&
                rules_[i].direction == rule.direction &&
                rules_[i].protocol == rule.protocol &&
                rules_[i].remote_address == rule.remote_address &&
                rules_[i].remote_port == rule.remote_port) {
                
                // Update existing rule
                rules_[i] = rule;
                Logger::get()->info("Updated rule for {}", rule.application);
                return true;
            }
        }
        
        // Add new rule
        rules_.push_back(rule);
        Logger::get()->info("Added new rule for {}", rule.application);
        return true;
    } catch (const std::exception& e) {
        Logger::get()->error("Error adding rule: {}", e.what());
        return false;
    }
}

bool RuleManager::removeRule(const std::string& application) {
    try {
        auto it = std::remove_if(rules_.begin(), rules_.end(),
            [&application](const Rule& rule) {
                return rule.application == application;
            });
        
        if (it != rules_.end()) {
            rules_.erase(it, rules_.end());
            Logger::get()->info("Removed rule(s) for {}", application);
            return true;
        }
        
        Logger::get()->warn("No rules found for {}", application);
        return false;
    } catch (const std::exception& e) {
        Logger::get()->error("Error removing rule: {}", e.what());
        return false;
    }
}

bool RuleManager::evaluateConnection(const std::string& app, const std::string& address, int port) {
    Logger::get()->debug("Evaluating connection from {} to {}:{}", app, address, port);
    
    // Search for specific rules first
    for (const auto& rule : rules_) {
        if (!rule.enabled) {
            continue; // Skip disabled rules
        }
        
        bool appMatch = (rule.application == app || rule.application == "*");
        bool addrMatch = (rule.remote_address == address || rule.remote_address == "*");
        bool portMatch = (rule.remote_port == port || rule.remote_port == 0);
        
        if (appMatch && addrMatch && portMatch) {
            Logger::get()->debug("Rule match found: {}", rule.action);
            return rule.action == "allow";
        }
    }
    
    // Default policy from config
    auto defaultPolicy = Config::getInstance().get<std::string>("default_policy", "allow");
    Logger::get()->debug("No matching rule, using default policy: {}", defaultPolicy);
    return defaultPolicy == "allow";
}

size_t RuleManager::getEnabledRuleCount() const {
    return std::count_if(rules_.begin(), rules_.end(),
        [](const Rule& rule) { return rule.enabled; });
}

bool RuleManager::enableRule(const std::string& application) {
    bool found = false;
    for (auto& rule : rules_) {
        if (rule.application == application) {
            rule.enabled = true;
            found = true;
        }
    }
    
    if (found) {
        Logger::get()->info("Enabled rule(s) for {}", application);
    }
    return found;
}

bool RuleManager::disableRule(const std::string& application) {
    bool found = false;
    for (auto& rule : rules_) {
        if (rule.application == application) {
            rule.enabled = false;
            found = true;
        }
    }
    
    if (found) {
        Logger::get()->info("Disabled rule(s) for {}", application);
    }
    return found;
}

bool RuleManager::ruleExists(const std::string& application) const {
    return std::any_of(rules_.begin(), rules_.end(),
        [&application](const Rule& rule) {
            return rule.application == application;
        });
}

std::vector<Rule> RuleManager::getRulesByApplication(const std::string& application) const {
    std::vector<Rule> result;
    std::copy_if(rules_.begin(), rules_.end(), std::back_inserter(result),
        [&application](const Rule& rule) {
            return rule.application == application;
        });
    return result;
}

std::vector<Rule> RuleManager::getRulesByAction(const std::string& action) const {
    std::vector<Rule> result;
    std::copy_if(rules_.begin(), rules_.end(), std::back_inserter(result),
        [&action](const Rule& rule) {
            return rule.action == action;
        });
    return result;
}

std::vector<Rule> RuleManager::getEnabledRules() const {
    std::vector<Rule> result;
    std::copy_if(rules_.begin(), rules_.end(), std::back_inserter(result),
        [](const Rule& rule) {
            return rule.enabled;
        });
    return result;
}

bool RuleManager::isValidRule(const Rule& rule) const {
    // Basic validation
    if (rule.application.empty()) return false;
    if (rule.action != "allow" && rule.action != "block") return false;
    if (rule.direction != "inbound" && rule.direction != "outbound" && 
        rule.direction != "both" && rule.direction != "*") return false;
    if (rule.protocol != "tcp" && rule.protocol != "udp" && 
        rule.protocol != "icmp" && rule.protocol != "*") return false;
    if (rule.remote_port < 0 || rule.remote_port > 65535) return false;
    
    return true;
}

void RuleManager::sortRulesByPriority() {
    // Sort rules by specificity (more specific rules first)
    std::sort(rules_.begin(), rules_.end(),
        [](const Rule& a, const Rule& b) {
            // Rules with specific applications come before wildcards
            if (a.application != "*" && b.application == "*") return true;
            if (a.application == "*" && b.application != "*") return false;
            
            // Rules with specific addresses come before wildcards
            if (a.remote_address != "*" && b.remote_address == "*") return true;
            if (a.remote_address == "*" && b.remote_address != "*") return false;
            
            // Rules with specific ports come before wildcards
            if (a.remote_port != 0 && b.remote_port == 0) return true;
            if (a.remote_port == 0 && b.remote_port != 0) return false;
            
            // Block rules come before allow rules
            if (a.action == "block" && b.action == "allow") return true;
            if (a.action == "allow" && b.action == "block") return false;
            
            return false; // Equal priority
        });
}

} // namespace Firewall