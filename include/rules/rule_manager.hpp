// #pragma once

// #include <string>
// #include <vector>
// #include <nlohmann/json.hpp>

// namespace Firewall{
//     struct Rule{
//         std::string application;
//         std::string action;
//         std::string direction;
//         std::string protocol;
//         std::string remote_address;
//         int remote_port;
//         bool enabled;
//     };


// class RuleManager{
//     public:
//         RuleManager();

//         bool loadRules(const std::string& filename);
//         bool saveRules(const std::string& filename);
//         bool addRule(const Rule& rule);
//         bool removeRule(const std::string& application);
//         bool evaluateConnection(const std::string& app,const std::string& address, int port);

//         const std::vector<Rule>& getRules() const;

    
//     private:
//         std::vector<Rule> rules_;
//         nlohmann::json rulesJson_;
// };
// }

#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace Firewall{
    struct Rule{
        std::string application;
        std::string action;
        std::string direction;
        std::string protocol;
        std::string remote_address;
        int remote_port;
        bool enabled;
        
        Rule() : remote_port(0), enabled(true) {}
        
        Rule(const std::string& app, const std::string& act, const std::string& dir,
             const std::string& proto, const std::string& addr, int port, bool en = true)
            : application(app), action(act), direction(dir), protocol(proto),
              remote_address(addr), remote_port(port), enabled(en) {}
    };

    class RuleManager{
        public:
            RuleManager();

            bool loadRules(const std::string& filename);
            bool saveRules(const std::string& filename);
            bool addRule(const Rule& rule);
            bool removeRule(const std::string& application);
            bool evaluateConnection(const std::string& app,const std::string& address, int port);

            // Getter method for accessing rules (needed for CLI interface)
            const std::vector<Rule>& getRules() const { return rules_; }
            
            // Rule statistics
            size_t getRuleCount() const { return rules_.size(); }
            size_t getEnabledRuleCount() const;
            
            // Rule management helpers
            bool enableRule(const std::string& application);
            bool disableRule(const std::string& application);
            bool ruleExists(const std::string& application) const;
            
            // Rule searching and filtering
            std::vector<Rule> getRulesByApplication(const std::string& application) const;
            std::vector<Rule> getRulesByAction(const std::string& action) const;
            std::vector<Rule> getEnabledRules() const;

        private:
            std::vector<Rule> rules_;
            nlohmann::json rulesJson_;
            
            // Helper methods
            bool isValidRule(const Rule& rule) const;
            void sortRulesByPriority();
    };
}