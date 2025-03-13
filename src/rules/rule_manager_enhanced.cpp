#include "../../include/rules/rule_manager.hpp"
#include "../../include/utils/logger.hpp"
#include "../../include/utils/config.hpp"

#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace Firewall {

RuleManager::RuleManager() {
    // Initialize with default rules
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
        if (!std::filesystem::exists(filename)) {
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
            
            rules_.push_back(rule);
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
        // Create directory if it doesn't exist
        std::filesystem::path filePath(filename);
        std::filesystem::create_directories(filePath.parent_path());
        
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

} // namespace Firewall
