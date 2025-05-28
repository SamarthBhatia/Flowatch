#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <unordered_map>
#include <map>

namespace Firewall {
namespace Dialog {

// Forward declarations
class DialogNode;
class ConnectionNode;
class MessageNode;
class FieldNode;

// Base dialog tree node
class DialogNode {
public:
    enum class NodeType {
        ROOT,
        CONNECTION,
        MESSAGE,
        FIELD
    };

    DialogNode(NodeType type) : type_(type), timestamp_(std::chrono::steady_clock::now()) {}
    virtual ~DialogNode() = default;

    NodeType getType() const { return type_; }
    void addChild(std::shared_ptr<DialogNode> child) { children_.push_back(child); }
    const std::vector<std::shared_ptr<DialogNode>>& getChildren() const { return children_; }
    
    std::chrono::steady_clock::time_point getTimestamp() const { return timestamp_; }
    void setTimestamp(std::chrono::steady_clock::time_point ts) { timestamp_ = ts; }

protected:
    NodeType type_;
    std::vector<std::shared_ptr<DialogNode>> children_;
    std::chrono::steady_clock::time_point timestamp_;
};

// Root node representing complete dialog
class RootNode : public DialogNode {
public:
    RootNode() : DialogNode(NodeType::ROOT) {}
    
    void addPeer(const std::string& ip, const std::string& domain = "") {
        peers_[ip] = domain;
    }
    
    const std::unordered_map<std::string, std::string>& getPeers() const { return peers_; }

private:
    std::unordered_map<std::string, std::string> peers_; // IP -> domain mapping
};

// Connection node
class ConnectionNode : public DialogNode {
public:
    ConnectionNode(const std::string& src_ip, uint16_t src_port,
                   const std::string& dst_ip, uint16_t dst_port,
                   const std::string& protocol, const std::string& app_protocol)
        : DialogNode(NodeType::CONNECTION), src_ip_(src_ip), src_port_(src_port),
          dst_ip_(dst_ip), dst_port_(dst_port), protocol_(protocol), 
          app_protocol_(app_protocol) {}

    const std::string& getSrcIP() const { return src_ip_; }
    const std::string& getDstIP() const { return dst_ip_; }
    uint16_t getSrcPort() const { return src_port_; }
    uint16_t getDstPort() const { return dst_port_; }
    const std::string& getProtocol() const { return protocol_; }
    const std::string& getAppProtocol() const { return app_protocol_; }

private:
    std::string src_ip_, dst_ip_;
    uint16_t src_port_, dst_port_;
    std::string protocol_;      // TCP/UDP
    std::string app_protocol_;  // HTTP/SIP/etc
};

// Message node  
class MessageNode : public DialogNode {
public:
    enum class Direction {
        REQUEST,
        RESPONSE
    };

    MessageNode(Direction direction, const std::string& sender_ip)
        : DialogNode(NodeType::MESSAGE), direction_(direction), sender_ip_(sender_ip) {}

    Direction getDirection() const { return direction_; }
    const std::string& getSenderIP() const { return sender_ip_; }
    
    void setRawData(const std::vector<uint8_t>& data) { raw_data_ = data; }
    const std::vector<uint8_t>& getRawData() const { return raw_data_; }

private:
    Direction direction_;
    std::string sender_ip_;
    std::vector<uint8_t> raw_data_;
};

// Field node for message fields
class FieldNode : public DialogNode {
public:
    FieldNode(const std::string& name, const std::string& value, 
              size_t start_offset, size_t end_offset)
        : DialogNode(NodeType::FIELD), name_(name), value_(value),
          start_offset_(start_offset), end_offset_(end_offset) {}

    const std::string& getName() const { return name_; }
    const std::string& getValue() const { return value_; }
    size_t getStartOffset() const { return start_offset_; }
    size_t getEndOffset() const { return end_offset_; }
    
    void setValue(const std::string& value) { value_ = value; }

private:
    std::string name_;
    std::string value_;
    size_t start_offset_;
    size_t end_offset_;
};

// Network Dialog Tree
class NetworkDialogTree {
public:
    NetworkDialogTree() : root_(std::make_shared<RootNode>()) {}

    std::shared_ptr<RootNode> getRoot() { return root_; }
    
    // Add a new connection
    std::shared_ptr<ConnectionNode> addConnection(
        const std::string& src_ip, uint16_t src_port,
        const std::string& dst_ip, uint16_t dst_port,
        const std::string& protocol, const std::string& app_protocol);
    
    // Add a message to a connection
    std::shared_ptr<MessageNode> addMessage(
        std::shared_ptr<ConnectionNode> connection,
        MessageNode::Direction direction, 
        const std::string& sender_ip,
        const std::vector<uint8_t>& data);
    
    // Add a field to a message
    std::shared_ptr<FieldNode> addField(
        std::shared_ptr<MessageNode> message,
        const std::string& name, const std::string& value,
        size_t start_offset, size_t end_offset);
    
    // Tree traversal and analysis
    void traverse(std::function<void(std::shared_ptr<DialogNode>)> visitor);
    size_t getNodeCount() const;
    std::vector<std::shared_ptr<ConnectionNode>> getConnections() const;

private:
    std::shared_ptr<RootNode> root_;
    
    void traverseHelper(std::shared_ptr<DialogNode> node, 
                       std::function<void(std::shared_ptr<DialogNode>)> visitor);
};

// Goal function interface for dialog minimization
class GoalFunction {
public:
    virtual ~GoalFunction() = default;
    virtual bool evaluate(const std::vector<uint8_t>& response_data) = 0;
    virtual std::string getDescription() const = 0;
};

// Example goal functions
class MalwareDownloadGoal : public GoalFunction {
public:
    bool evaluate(const std::vector<uint8_t>& response_data) override;
    std::string getDescription() const override { return "Download malware binary"; }
};

class LoginSuccessGoal : public GoalFunction {
public:
    LoginSuccessGoal(const std::string& username) : username_(username) {}
    bool evaluate(const std::vector<uint8_t>& response_data) override;
    std::string getDescription() const override { return "Successful login for " + username_; }

private:
    std::string username_;
};

} // namespace Dialog
} // namespace Firewall