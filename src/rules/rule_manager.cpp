#include "../../include/rules/rule_manager.hpp"
#include "../../include/utils/logger.hpp"


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

} // namespace Firewall