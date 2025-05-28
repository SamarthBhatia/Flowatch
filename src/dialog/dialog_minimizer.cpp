#include "../../include/dialog/dialog_minimizer.hpp"
#include "../../include/utils/logger.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>
#include <random>
#include <limits>

namespace Firewall {
namespace Dialog {

// NetworkDeltaDebugger Implementation

std::shared_ptr<NetworkDialogTree> NetworkDeltaDebugger::minimize(
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

std::shared_ptr<NetworkDialogTree> NetworkDeltaDebugger::minimizeConnections(
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
    
    // Create test function that captures this instance
    auto test_func = [this, tree](const std::vector<std::shared_ptr<DialogNode>>& nodes) -> bool {
        auto test_tree = createTestTree(tree, nodes);
        if (!test_tree) return false;
        
        TestConfig config;
        config.dialog_tree = test_tree;
        return executeTest(config);
    };
    
    auto minimized_connections = deltaDebug(connection_nodes, test_func);
    
    logMinimizationStep("connections", connections.size(), minimized_connections.size());
    
    return createTestTree(tree, minimized_connections);
}

std::shared_ptr<NetworkDialogTree> NetworkDeltaDebugger::minimizeMessages(
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
    
    // Create test function that captures this instance  
    auto test_func = [this, tree](const std::vector<std::shared_ptr<DialogNode>>& nodes) -> bool {
        auto test_tree = createTestTreeWithMessages(tree, nodes);
        if (!test_tree) return false;
        
        TestConfig config;
        config.dialog_tree = test_tree;
        return executeTest(config);
    };
    
    auto minimized_messages = deltaDebug(all_messages, test_func);
    
    logMinimizationStep("messages", all_messages.size(), minimized_messages.size());
    
    return createTestTreeWithMessages(tree, minimized_messages);
}

std::shared_ptr<NetworkDialogTree> NetworkDeltaDebugger::minimizeFields(
    std::shared_ptr<NetworkDialogTree> tree) {
    
    Logger::get()->debug("Starting field minimization");
    
    // For each message, minimize its fields
    auto current_tree = tree;
    
    for (auto& conn : current_tree->getConnections()) {
        for (auto& child : conn->getChildren()) {
            if (child->getType() == DialogNode::NodeType::MESSAGE) {
                auto message = std::static_pointer_cast<MessageNode>(child);
                auto minimized_message = minimizeMessageFields(message);
                if (minimized_message) {
                    // Replace the message in the tree
                    // Note: This is a simplified implementation
                    // In practice, you'd need to rebuild the tree properly
                }
            }
        }
    }
    
    Logger::get()->info("Field minimization completed");
    return current_tree;
}

std::shared_ptr<MessageNode> NetworkDeltaDebugger::minimizeMessageFields(
    std::shared_ptr<MessageNode> message) {
    
    auto fields = message->getChildren();
    if (fields.empty()) {
        return message;
    }
    
    Logger::get()->debug("Minimizing {} fields in message", fields.size());
    
    // Create test function that captures this instance and message
    auto test_func = [this, message](const std::vector<std::shared_ptr<DialogNode>>& nodes) -> bool {
        auto test_message = createTestMessage(message, nodes);
        if (!test_message) return false;
        
        // Create a minimal tree for testing this message
        auto test_tree = std::make_shared<NetworkDialogTree>();
        auto conn = test_tree->addConnection("127.0.0.1", 80, "target", 80, "tcp", "http");
        conn->addChild(test_message);
        
        TestConfig config;
        config.dialog_tree = test_tree;
        return executeTest(config);
    };
    
    auto minimized_fields = deltaDebug(fields, test_func);
    
    Logger::get()->debug("Field minimization: {} -> {} fields", 
                        fields.size(), minimized_fields.size());
    
    return createTestMessage(message, minimized_fields);
}

bool NetworkDeltaDebugger::executeTest(const TestConfig& config) {
    if (!config.dialog_tree) {
        Logger::get()->debug("Test config has no dialog tree");
        return false;
    }
    
    if (!reset_button_->reset()) {
        Logger::get()->error("Failed to reset for test");
        return false;
    }
    
    DialogReplayer replayer;
    auto result = replayer.replay(config.dialog_tree, config.target_ip, config.target_port);
    
    if (!result.success) {
        Logger::get()->debug("Replay failed: {}", result.error_message);
        return false;
    }
    
    bool goal_reached = goal_function_->evaluate(result.response_data);
    Logger::get()->debug("Test result: goal {}", goal_reached ? "REACHED" : "NOT REACHED");
    
    return goal_reached;
}

std::shared_ptr<NetworkDialogTree> NetworkDeltaDebugger::createTestTree(
    std::shared_ptr<NetworkDialogTree> original,
    const std::vector<std::shared_ptr<DialogNode>>& included_nodes) {
    
    auto test_tree = std::make_shared<NetworkDialogTree>();
    
    // Copy peers from original
    for (const auto& peer : original->getRoot()->getPeers()) {
        test_tree->getRoot()->addPeer(peer.first, peer.second);
    }
    
    // Add included connections
    for (auto& node : included_nodes) {
        if (node->getType() == DialogNode::NodeType::CONNECTION) {
            auto conn = std::static_pointer_cast<ConnectionNode>(node);
            auto new_conn = test_tree->addConnection(
                conn->getSrcIP(), conn->getSrcPort(),
                conn->getDstIP(), conn->getDstPort(),
                conn->getProtocol(), conn->getAppProtocol()
            );
            
            // Copy all children (messages)
            for (auto& child : conn->getChildren()) {
                new_conn->addChild(child);
            }
        }
    }
    
    return test_tree;
}

std::shared_ptr<NetworkDialogTree> NetworkDeltaDebugger::createTestTreeWithMessages(
    std::shared_ptr<NetworkDialogTree> original,
    const std::vector<std::shared_ptr<DialogNode>>& included_messages) {
    
    auto test_tree = std::make_shared<NetworkDialogTree>();
    
    // Copy peers
    for (const auto& peer : original->getRoot()->getPeers()) {
        test_tree->getRoot()->addPeer(peer.first, peer.second);
    }
    
    // Group messages by their parent connection
    std::map<std::shared_ptr<ConnectionNode>, std::vector<std::shared_ptr<DialogNode>>> conn_messages;
    
    for (auto& msg_node : included_messages) {
        // Find parent connection in original tree
        for (auto& conn : original->getConnections()) {
            for (auto& child : conn->getChildren()) {
                if (child == msg_node) {
                    conn_messages[conn].push_back(msg_node);
                    break;
                }
            }
        }
    }
    
    // Create connections with their included messages
    for (const auto& [orig_conn, messages] : conn_messages) {
        auto new_conn = test_tree->addConnection(
            orig_conn->getSrcIP(), orig_conn->getSrcPort(),
            orig_conn->getDstIP(), orig_conn->getDstPort(),
            orig_conn->getProtocol(), orig_conn->getAppProtocol()
        );
        
        for (auto& msg : messages) {
            new_conn->addChild(msg);
        }
    }
    
    return test_tree;
}

std::shared_ptr<MessageNode> NetworkDeltaDebugger::createTestMessage(
    std::shared_ptr<MessageNode> original,
    const std::vector<std::shared_ptr<DialogNode>>& included_fields) {
    
    auto test_message = std::make_shared<MessageNode>(
        original->getDirection(), original->getSenderIP()
    );
    
    // Reconstruct message with included fields
    if (included_fields.empty()) {
        // If no fields included, use original raw data
        test_message->setRawData(original->getRawData());
    } else {
        // Rebuild message from fields
        std::vector<uint8_t> reconstructed_data;
        
        // Sort fields by offset
        auto sorted_fields = included_fields;
        std::sort(sorted_fields.begin(), sorted_fields.end(),
            [](const std::shared_ptr<DialogNode>& a, const std::shared_ptr<DialogNode>& b) {
                auto field_a = std::static_pointer_cast<FieldNode>(a);
                auto field_b = std::static_pointer_cast<FieldNode>(b);
                return field_a->getStartOffset() < field_b->getStartOffset();
            });
        
        // Reconstruct message data from fields
        for (auto& field_node : sorted_fields) {
            auto field = std::static_pointer_cast<FieldNode>(field_node);
            
            // Add field value to reconstructed data
            std::string field_value = field->getValue();
            reconstructed_data.insert(reconstructed_data.end(), 
                                    field_value.begin(), field_value.end());
        }
        
        test_message->setRawData(reconstructed_data);
        
        // Add fields as children
        for (auto& field : included_fields) {
            test_message->addChild(field);
        }
    }
    
    return test_message;
}

std::vector<std::shared_ptr<DialogNode>> NetworkDeltaDebugger::deltaDebug(
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

void NetworkDeltaDebugger::logMinimizationStep(
    const std::string& level, size_t original_count, size_t minimized_count) {
    
    double reduction = original_count > 0 ? 
        (1.0 - static_cast<double>(minimized_count) / original_count) * 100.0 : 0.0;
    
    Logger::get()->info("Level {}: {} -> {} ({}% reduction)", 
                      level, original_count, minimized_count, reduction);
}

// DialogReplayer Implementation

DialogReplayer::ReplayResult DialogReplayer::replay(
    std::shared_ptr<NetworkDialogTree> dialog_tree,
    const std::string& target_ip,
    uint16_t target_port) {
    
    ReplayResult result;
    result.success = false;
    
    auto start_time = std::chrono::steady_clock::now();
    
    try {
        auto connections = dialog_tree->getConnections();
        if (connections.empty()) {
            result.error_message = "No connections to replay";
            return result;
        }
        
        Logger::get()->debug("Replaying dialog with {} connections", connections.size());
        
        // Replay each connection in order
        for (auto& connection : connections) {
            std::string actual_target_ip = target_ip.empty() ? 
                connection->getDstIP() : target_ip;
            uint16_t actual_target_port = target_port == 0 ? 
                connection->getDstPort() : target_port;
            
            auto conn_result = replayConnection(connection, actual_target_ip, actual_target_port);
            
            if (!conn_result.success) {
                result.error_message = conn_result.error_message;
                return result;
            }
            
            // Accumulate response data
            result.response_data.insert(result.response_data.end(),
                                      conn_result.response_data.begin(),
                                      conn_result.response_data.end());
        }
        
        result.success = true;
        
    } catch (const std::exception& e) {
        result.error_message = std::string("Exception during replay: ") + e.what();
    }
    
    auto end_time = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    Logger::get()->debug("Dialog replay completed in {}ms", result.duration.count());
    
    return result;
}

DialogReplayer::ReplayResult DialogReplayer::replayConnection(
    std::shared_ptr<ConnectionNode> connection,
    const std::string& override_ip,
    uint16_t override_port) {
    
    ReplayResult result;
    result.success = false;
    
    std::string target_ip = override_ip.empty() ? connection->getDstIP() : override_ip;
    uint16_t target_port = override_port == 0 ? connection->getDstPort() : override_port;
    
    Logger::get()->debug("Connecting to {}:{}", target_ip, target_port);
    
    // Create socket
    int sock_fd = createSocket(target_ip, target_port, connection->getProtocol());
    if (sock_fd < 0) {
        result.error_message = "Failed to create socket";
        return result;
    }
    
    try {
        // Send all request messages in this connection
        for (auto& child : connection->getChildren()) {
            if (child->getType() == DialogNode::NodeType::MESSAGE) {
                auto message = std::static_pointer_cast<MessageNode>(child);
                
                if (message->getDirection() == MessageNode::Direction::REQUEST) {
                    Logger::get()->debug("Sending request message");
                    
                    auto msg_result = sendHTTPMessage(message, sock_fd);
                    if (!msg_result.success) {
                        close(sock_fd);
                        result.error_message = msg_result.error_message;
                        return result;
                    }
                }
            }
        }
        
        // Receive response
        char buffer[8192];
        ssize_t bytes_received = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received > 0) {
            result.response_data.assign(buffer, buffer + bytes_received);
            result.success = true;
            Logger::get()->debug("Received {} bytes in response", bytes_received);
        } else if (bytes_received == 0) {
            result.error_message = "Connection closed by peer";
        } else {
            result.error_message = "Error receiving response";
        }
        
    } catch (const std::exception& e) {
        result.error_message = std::string("Exception in connection replay: ") + e.what();
    }
    
    close(sock_fd);
    return result;
}

DialogReplayer::ReplayResult DialogReplayer::sendHTTPMessage(
    std::shared_ptr<MessageNode> message, int socket_fd) {
    
    ReplayResult result;
    result.success = false;
    
    auto message_data = reconstructMessage(message);
    if (message_data.empty()) {
        result.error_message = "Empty message data";
        return result;
    }
    
    Logger::get()->debug("Sending {} bytes", message_data.size());
    
    ssize_t bytes_sent = send(socket_fd, message_data.data(), message_data.size(), 0);
    
    if (bytes_sent == static_cast<ssize_t>(message_data.size())) {
        result.success = true;
        Logger::get()->debug("Message sent successfully");
    } else if (bytes_sent < 0) {
        result.error_message = "Error sending message";
    } else {
        result.error_message = "Partial message sent";
    }
    
    return result;
}

std::vector<uint8_t> DialogReplayer::reconstructMessage(std::shared_ptr<MessageNode> message) {
    auto raw_data = message->getRawData();
    
    if (!raw_data.empty()) {
        return raw_data;
    }
    
    // Reconstruct from fields if no raw data
    std::string reconstructed;
    
    for (auto& child : message->getChildren()) {
        if (child->getType() == DialogNode::NodeType::FIELD) {
            auto field = std::static_pointer_cast<FieldNode>(child);
            reconstructed += field->getValue();
        }
    }
    
    return std::vector<uint8_t>(reconstructed.begin(), reconstructed.end());
}

int DialogReplayer::createSocket(const std::string& ip, uint16_t port, const std::string& protocol) {
    int sock_fd;
    
    if (protocol == "tcp") {
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    } else if (protocol == "udp") {
        sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    } else {
        Logger::get()->error("Unsupported protocol: {}", protocol);
        return -1;
    }
    
    if (sock_fd < 0) {
        Logger::get()->error("Failed to create socket");
        return -1;
    }
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 10;  // 10 second timeout
    timeout.tv_usec = 0;
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Connect to target
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
        Logger::get()->error("Invalid IP address: {}", ip);
        close(sock_fd);
        return -1;
    }
    
    if (protocol == "tcp") {
        if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            Logger::get()->error("Failed to connect to {}:{}", ip, port);
            close(sock_fd);
            return -1;
        }
    }
    
    return sock_fd;
}

} // namespace Dialog
} // namespace Firewall