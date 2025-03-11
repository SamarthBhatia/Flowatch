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
    };


class RuleManager{
    public:
        RuleManager();

        bool loadRules(const std::string& filename);
        bool saveRules(const std::string& filename);
        bool addRule(const RuleManager& rule);
        bool removeRule(const std::string& application);
        bool evaluateConnection(const std::string& app,const std::string& address, int port);
    
    private:
        std::vector<Rule> rules_;
        nlohmann::json rulesJson_;
};
}

