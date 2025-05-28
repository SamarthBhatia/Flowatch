#pragma once

#include "dialog_tree.hpp"
#include "../utils/logger.hpp"
#include <functional>
#include <set>
#include <random>

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
    
    // Core delta debugging algorithm
    std::vector<std::shared_ptr<DialogNode>> deltaDebug(
        const std::vector<std::shared_ptr<DialogNode>>& nodes,
        std::function<bool(const std::vector<std::shared_ptr<DialogNode>>&)> test_func);
    
    // Test execution
    bool executeTest(const TestConfig& config);
    bool replayDialog(std::shared_ptr<NetworkDialogTree> test_tree);
    
    // Utility functions
    std::shared_ptr<NetworkDialogTree> createTestTree(
        std::shared_ptr<NetworkDialogTree> original,
        const std::vector<std::shared_ptr<DialogNode>>& included_nodes);
        
    void logMinimizationStep(const std::string& level, 
                           size_t original_count, size_t minimized_count);
};

// Dialog replayer for testing minimized dialogs
class DialogReplayer {
public:
    DialogReplayer() = default;
    
    struct ReplayResult {
        bool success;
        std::vector<uint8_t> response_data;
        std::string error_message;
        std::chrono::milliseconds duration;
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

// Implementation of NetworkDeltaDebugger methods
inline std::shared_ptr<NetworkDialogTree> NetworkDeltaDebugger::minimize(
    std::shared_ptr<NetworkDialogTree> original_tree) {
    
    Logger::get()->info("Starting network dialog minimization");
    
    auto current_tree = original_tree;
    
    // Level 1: Minimize connections
    Logger::get()->info("Level 1: Minimizing connections");
    current_tree = minimizeConnections(current_tree);
    
    // Level 2: Minimize messages
    Logger::get()->info("Level 2: Minimizing messages");
    current_tree = minimizeMessages(current_tree);
    
    // Level 3: Minimize fields
    Logger::get()->info("Level 3: Minimizing fields");
    current_tree = minimizeFields(current_tree);
    
    Logger::get()->info("Dialog minimization completed");
    return current_tree;
}

inline std::shared_ptr<NetworkDialogTree> NetworkDeltaDebugger::minimizeConnections(
    std::shared_ptr<NetworkDialogTree> tree) {
    
    auto connections = tree->getConnections();
    if (connections.size() <= 1) {
        Logger::get()->debug("Only one connection, skipping connection minimization");
        return tree;
    }
    
    Logger::get()->debug("Minimizing {} connections", connections.size());
    
    // Convert to DialogNode vector for delta debugging
    std::vector<std::shared_ptr<DialogNode>> connection_nodes;
    for (auto& conn : connections) {
        connection_nodes.push_back(std::static_pointer_cast<DialogNode>(conn));
    }
    
    auto test_func = [this, tree](const std::vector<std::shared_ptr<DialogNode>>& nodes) -> bool {
        auto test_tree = createTestTree(tree, nodes);
        return executeTest({test_tree, {}, "", 0});
    };
    
    auto minimized_connections = deltaDebug(connection_nodes, test_func);
    
    logMinimizationStep("connections", connections.size(), minimized_connections.size());
    
    return createTestTree(tree, minimized_connections);
}

inline std::shared_ptr<NetworkDialogTree> NetworkDeltaDebugger::minimizeMessages(
    std::shared_ptr<NetworkDialogTree> tree) {
    
    // Collect all messages from all connections
    std::vector<std::shared_ptr<DialogNode>> all_messages;
    
    for (auto& conn : tree->getConnections()) {
        for (auto& child : conn->getChildren()) {
            if (child->getType() == DialogNode::NodeType::MESSAGE) {
                all_messages.push_back(child);
            }
        }
    }
    
    if (all_messages.size() <= 1) {
        Logger::get()->debug("Only one message, skipping message minimization");
        return tree;
    }
    
    Logger::get()->debug("Minimizing {} messages", all_messages.size());
    
    auto test_func = [this, tree](const std::vector<std::shared_ptr<DialogNode>>& nodes) -> bool {
        auto test_tree = createTestTree(tree, nodes);
        return executeTest({test_tree, {}, "", 0});
    };
    
    auto minimized_messages = deltaDebug(all_messages, test_func);
    
    logMinimizationStep("messages", all_messages.size(), minimized_messages.size());
    
    return createTestTree(tree, minimized_messages);
}

inline std::shared_ptr<NetworkDialogTree> NetworkDeltaDebugger::minimizeFields(
    std::shared_ptr<NetworkDialogTree> tree) {
    
    // Field minimization is more complex as we need to maintain message structure
    // For now, implement basic field removal for HTTP headers
    
    Logger::get()->info("Field minimization completed (placeholder implementation)");
    return tree;
}

inline std::vector<std::shared_ptr<DialogNode>> NetworkDeltaDebugger::deltaDebug(
    const std::vector<std::shared_ptr<DialogNode>>& nodes,
    std::function<bool(const std::vector<std::shared_ptr<DialogNode>>&)> test_func) {
    
    if (nodes.empty()) return nodes;
    
    std::vector<std::shared_ptr<DialogNode>> current_config = nodes;
    size_t n = 2; // Initial partition count
    
    while (true) {
        Logger::get()->debug("Delta debugging with {} partitions", n);
        
        // Step 1: Reduce to subset
        for (size_t i = 0; i < n && i < current_config.size(); i++) {
            size_t partition_size = current_config.size() / n;
            size_t start = i * partition_size;
            size_t end = (i == n - 1) ? current_config.size() : (i + 1) * partition_size;
            
            std::vector<std::shared_ptr<DialogNode>> subset(
                current_config.begin() + start, current_config.begin() + end);
            
            if (!reset_button_->reset()) {
                Logger::get()->error("Failed to reset for test");
                break;
            }
            
            if (test_func(subset)) {
                Logger::get()->debug("Subset {} passed, reducing configuration", i);
                current_config = subset;
                n = 2; // Reset granularity
                goto continue_outer;
            }
        }
        
        // Step 2: Reduce to complement
        for (size_t i = 0; i < n && i < current_config.size(); i++) {
            size_t partition_size = current_config.size() / n;
            size_t start = i * partition_size;
            size_t end = (i == n - 1) ? current_config.size() : (i + 1) * partition_size;
            
            std::vector<std::shared_ptr<DialogNode>> complement;
            complement.insert(complement.end(), current_config.begin(), current_config.begin() + start);
            complement.insert(complement.end(), current_config.begin() + end, current_config.end());
            
            if (!reset_button_->reset()) {
                Logger::get()->error("Failed to reset for test");
                break;
            }
            
            if (test_func(complement)) {
                Logger::get()->debug("Complement {} passed, reducing configuration", i);
                current_config = complement;
                n = 2; // Reset granularity
                goto continue_outer;
            }
        }
        
        // Step 3: Increase granularity
        if (n >= current_config.size()) {
            Logger::get()->debug("Cannot increase granularity further, done");
            break;
        }
        
        n = std::min(n * 2, current_config.size());
        
        continue_outer:;
    }
    
    Logger::get()->debug("Delta debugging completed with {} elements", current_config.size());
    return current_config;
}

inline bool NetworkDeltaDebugger::executeTest(const TestConfig& config) {
    if (!config.dialog_tree) {
        return false;
    }
    
    DialogReplayer replayer;
    auto result = replayer.replay(config.dialog_tree, config.target_ip, config.target_port);
    
    if (!result.success) {
        Logger::get()->debug("Replay failed: {}", result.error_message);
        return false;
    }
    
    return goal_function_->evaluate(result.response_data);
}

inline void NetworkDeltaDebugger::logMinimizationStep(
    const std::string& level, size_t original_count, size_t minimized_count) {
    
    double reduction = original_count > 0 ? 
        (1.0 - static_cast<double>(minimized_count) / original_count) * 100.0 : 0.0;
    
    Logger::get()->info("Level {}: {} -> {} ({}% reduction)", 
                      level, original_count, minimized_count, reduction);
}

} // namespace Dialog
} // namespace Firewall