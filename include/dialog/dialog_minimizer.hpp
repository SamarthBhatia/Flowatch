#pragma once

#include "dialog_tree.hpp"
#include "../utils/logger.hpp"
#include <functional>
#include <set>
#include <random>
#include <chrono>
#include <map>

namespace Firewall {
namespace Dialog {

// Reset button implementation for independent tests
class ResetButton {
public:
    virtual ~ResetButton() = default;
    virtual bool reset() = 0;
    virtual std::string getDescription() const = 0;
};

// IP rotation reset button using VPN or multiple interfaces
class IPRotationReset : public ResetButton {
public:
    IPRotationReset(const std::vector<std::string>& ip_pool) 
        : ip_pool_(ip_pool), current_index_(0) {}
    
    bool reset() override {
        if (current_index_ >= ip_pool_.size()) {
            Logger::get()->warn("IP pool exhausted for reset");
            return false;
        }
        current_ip_ = ip_pool_[current_index_++];
        return true;
    }
    
    std::string getCurrentIP() const { return current_ip_; }
    std::string getDescription() const override { return "IP rotation reset"; }

private:
    std::vector<std::string> ip_pool_;
    size_t current_index_;
    std::string current_ip_;
};

// Test configuration for minimization
struct TestConfig {
    std::shared_ptr<NetworkDialogTree> dialog_tree;
    std::set<size_t> included_nodes;  // Node indices to include in test
    std::string target_ip;
    uint16_t target_port;
};

// Delta debugging implementation for network dialogs
class NetworkDeltaDebugger {
public:
    NetworkDeltaDebugger(std::shared_ptr<GoalFunction> goal_func,
                        std::shared_ptr<ResetButton> reset_button)
        : goal_function_(goal_func), reset_button_(reset_button) {}

    // Main minimization entry point
    std::shared_ptr<NetworkDialogTree> minimize(
        std::shared_ptr<NetworkDialogTree> original_tree);

private:
    std::shared_ptr<GoalFunction> goal_function_;
    std::shared_ptr<ResetButton> reset_button_;
    
    // Delta debugging levels
    std::shared_ptr<NetworkDialogTree> minimizeConnections(
        std::shared_ptr<NetworkDialogTree> tree);
    std::shared_ptr<NetworkDialogTree> minimizeMessages(
        std::shared_ptr<NetworkDialogTree> tree);
    std::shared_ptr<NetworkDialogTree> minimizeFields(
        std::shared_ptr<NetworkDialogTree> tree);
    
    // Message field minimization
    std::shared_ptr<MessageNode> minimizeMessageFields(
        std::shared_ptr<MessageNode> message);
    
    // Core delta debugging algorithm
    std::vector<std::shared_ptr<DialogNode>> deltaDebug(
        const std::vector<std::shared_ptr<DialogNode>>& nodes,
        std::function<bool(const std::vector<std::shared_ptr<DialogNode>>&)> test_func);
    
    // Test execution
    bool executeTest(const TestConfig& config);
    
    // Utility functions for tree creation
    std::shared_ptr<NetworkDialogTree> createTestTree(
        std::shared_ptr<NetworkDialogTree> original,
        const std::vector<std::shared_ptr<DialogNode>>& included_nodes);
    
    std::shared_ptr<NetworkDialogTree> createTestTreeWithMessages(
        std::shared_ptr<NetworkDialogTree> original,
        const std::vector<std::shared_ptr<DialogNode>>& included_messages);
    
    std::shared_ptr<MessageNode> createTestMessage(
        std::shared_ptr<MessageNode> original,
        const std::vector<std::shared_ptr<DialogNode>>& included_fields);
        
    void logMinimizationStep(const std::string& level, 
                           size_t original_count, size_t minimized_count);
};

// Dialog replayer for testing minimized dialogs
class DialogReplayer {
public:
    DialogReplayer() = default;
    
    struct ReplayResult {
        bool success = false;
        std::vector<uint8_t> response_data;
        std::string error_message;
        std::chrono::milliseconds duration{0};
    };
    
    ReplayResult replay(std::shared_ptr<NetworkDialogTree> dialog_tree,
                       const std::string& target_ip = "",
                       uint16_t target_port = 0);

private:
    ReplayResult replayConnection(std::shared_ptr<ConnectionNode> connection,
                                 const std::string& override_ip = "",
                                 uint16_t override_port = 0);
    
    ReplayResult sendHTTPMessage(std::shared_ptr<MessageNode> message,
                                int socket_fd);
    
    std::vector<uint8_t> reconstructMessage(std::shared_ptr<MessageNode> message);
    int createSocket(const std::string& ip, uint16_t port, const std::string& protocol);
};

} // namespace Dialog
} // namespace Firewall