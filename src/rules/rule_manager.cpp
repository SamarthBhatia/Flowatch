#include "../../include/rules/rule_manager.hpp"
#include "../../include/utils/logger.hpp"

#include <filesystem>
#include <fstream>

namespace Firewall {

RuleManager::RuleManager() {
    // Initialize with default rules if needed
}

bool RuleManager::loadRules(const std::string& filename) {
    try {
        std::ifstream file(filename);
        if (!file.is_open()) {
            Logger::get()->error("Failed to open rule file: {}", filename);
            return false;
        }
        
        // Simple rule parsing implementation
        std::string line;
        while (std::getline(file, line)) {
            // Parse the line and create a rule
            // This is a simple placeholder
        }
        
        return true;
    } catch (const std::exception& e) {
        Logger::get()->error("Error loading rules: {}", e.what());
        return false;
    }
}

bool RuleManager::saveRules(const std::string& filename) {
    try {

        std::filesystem::path filePath(filename);
        std::filesystem::create_directories(filePath.parent_path());
        

        std::ofstream file(filename);
        if (!file.is_open()) {
            Logger::get()->error("Failed to open rule file for writing: {}", filename);
            return false;
        }
        
        // Write rules to file
        for (const auto& rule : rules_) {
            file << rule.application << "," 
                 << rule.action << "," 
                 << rule.remote_address << "," 
                 << rule.remote_port << "\n";
        }
        
        return true;
    } catch (const std::exception& e) {
        Logger::get()->error("Error saving rules: {}", e.what());
        return false;
    }
}

bool RuleManager::evaluateConnection(const std::string& app, const std::string& address, int port) {
    // For now, allow all connections
    Logger::get()->debug("Evaluating connection from {} to {}:{}", app, address, port);
    
    // In a real implementation, you would search through rules and apply them
    for (const auto& rule : rules_) {
        if (rule.application == app || rule.application == "*") {
            if (rule.remote_address == address || rule.remote_address == "*") {
                if (rule.remote_port == port || rule.remote_port == 0) {
                    return rule.action == "allow";
                }
            }
        }
    }
    
    // Default: allow connections if no matching rule is found
    return true;
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

const std::vector<Rule>& RuleManager::getRules() const {
    return rules_;
}

} // namespace Firewall