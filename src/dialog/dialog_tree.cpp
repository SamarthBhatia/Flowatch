#include "../../include/dialog/dialog_tree.hpp"
#include "../../include/utils/logger.hpp"
#include <algorithm>
#include <sstream>
#include <regex>

namespace Firewall {
namespace Dialog {

// NetworkDialogTree Implementation

std::shared_ptr<ConnectionNode> NetworkDialogTree::addConnection(
    const std::string& src_ip, uint16_t src_port,
    const std::string& dst_ip, uint16_t dst_port,
    const std::string& protocol, const std::string& app_protocol) {
    
    auto connection = std::make_shared<ConnectionNode>(
        src_ip, src_port, dst_ip, dst_port, protocol, app_protocol);
    
    root_->addChild(connection);
    
    // Add peers to root
    root_->addPeer(src_ip);
    root_->addPeer(dst_ip);
    
    Logger::get()->debug("Added connection: {}:{} -> {}:{} ({})", 
                        src_ip, src_port, dst_ip, dst_port, app_protocol);
    
    return connection;
}

std::shared_ptr<MessageNode> NetworkDialogTree::addMessage(
    std::shared_ptr<ConnectionNode> connection,
    MessageNode::Direction direction,
    const std::string& sender_ip,
    const std::vector<uint8_t>& data) {
    
    if (!connection) {
        Logger::get()->error("Cannot add message to null connection");
        return nullptr;
    }
    
    auto message = std::make_shared<MessageNode>(direction, sender_ip);
    message->setRawData(data);
    
    connection->addChild(message);
    
    Logger::get()->debug("Added message from {} ({} bytes)", 
                        sender_ip, data.size());
    
    return message;
}

std::shared_ptr<FieldNode> NetworkDialogTree::addField(
    std::shared_ptr<MessageNode> message,
    const std::string& name, const std::string& value,
    size_t start_offset, size_t end_offset) {
    
    if (!message) {
        Logger::get()->error("Cannot add field to null message");
        return nullptr;
    }
    
    auto field = std::make_shared<FieldNode>(name, value, start_offset, end_offset);
    message->addChild(field);
    
    Logger::get()->debug("Added field: {} = {} [{}-{}]", 
                        name, value, start_offset, end_offset);
    
    return field;
}

void NetworkDialogTree::traverse(std::function<void(std::shared_ptr<DialogNode>)> visitor) {
    traverseHelper(root_, visitor);
}

void NetworkDialogTree::traverseHelper(std::shared_ptr<DialogNode> node,
                                      std::function<void(std::shared_ptr<DialogNode>)> visitor) {
    if (!node) return;
    
    visitor(node);
    
    for (auto& child : node->getChildren()) {
        traverseHelper(child, visitor);
    }
}

size_t NetworkDialogTree::getNodeCount() const {
    size_t count = 0;
    const_cast<NetworkDialogTree*>(this)->traverse([&count](std::shared_ptr<DialogNode> node) {
        count++;
    });
    return count;
}

std::vector<std::shared_ptr<ConnectionNode>> NetworkDialogTree::getConnections() const {
    std::vector<std::shared_ptr<ConnectionNode>> connections;
    
    for (auto& child : root_->getChildren()) {
        if (child->getType() == DialogNode::NodeType::CONNECTION) {
            connections.push_back(std::static_pointer_cast<ConnectionNode>(child));
        }
    }
    
    return connections;
}

// MalwareDownloadGoal Implementation
bool MalwareDownloadGoal::evaluate(const std::vector<uint8_t>& response_data) {
    if (response_data.size() < 4) {
        return false;
    }
    
    // Check for PE header (Windows executable)
    if (response_data[0] == 0x4D && response_data[1] == 0x5A) {
        Logger::get()->debug("Detected PE executable (MZ header)");
        return true;
    }
    
    // Check for ELF header (Linux executable)
    if (response_data.size() >= 4 && 
        response_data[0] == 0x7F && response_data[1] == 'E' && 
        response_data[2] == 'L' && response_data[3] == 'F') {
        Logger::get()->debug("Detected ELF executable");
        return true;
    }
    
    // Check for Mach-O header (macOS executable)
    if (response_data.size() >= 4) {
        uint32_t magic = *reinterpret_cast<const uint32_t*>(response_data.data());
        if (magic == 0xfeedface || magic == 0xfeedfacf || 
            magic == 0xcefaedfe || magic == 0xcffaedfe) {
            Logger::get()->debug("Detected Mach-O executable");
            return true;
        }
    }
    
    // Check for common archive formats that might contain malware
    if (response_data.size() >= 4) {
        // ZIP signature
        if (response_data[0] == 0x50 && response_data[1] == 0x4B &&
            (response_data[2] == 0x03 || response_data[2] == 0x05)) {
            Logger::get()->debug("Detected ZIP archive");
            return true;
        }
        
        // RAR signature
        if (response_data.size() >= 7 &&
            response_data[0] == 0x52 && response_data[1] == 0x61 && 
            response_data[2] == 0x72 && response_data[3] == 0x21 &&
            response_data[4] == 0x1A && response_data[5] == 0x07) {
            Logger::get()->debug("Detected RAR archive");
            return true;
        }
    }
    
    // Check for suspicious file size (likely binary)
    if (response_data.size() > 10000) {  // 10KB+
        // Look for high entropy indicating compiled code
        std::map<uint8_t, int> byte_freq;
        for (uint8_t byte : response_data) {
            byte_freq[byte]++;
        }
        
        // Calculate entropy
        double entropy = 0.0;
        for (const auto& pair : byte_freq) {
            double p = static_cast<double>(pair.second) / response_data.size();
            if (p > 0) {
                entropy -= p * log2(p);
            }
        }
        
        if (entropy > 7.0) {  // High entropy suggests compiled code
            Logger::get()->debug("High entropy content detected (entropy: {})", entropy);
            return true;
        }
    }
    
    return false;
}

// LoginSuccessGoal Implementation
bool LoginSuccessGoal::evaluate(const std::vector<uint8_t>& response_data) {
    if (response_data.empty()) {
        return false;
    }
    
    // Convert response to string for text analysis
    std::string response_text(response_data.begin(), response_data.end());
    
    // Convert to lowercase for case-insensitive matching
    std::transform(response_text.begin(), response_text.end(), 
                   response_text.begin(), ::tolower);
    
    // Look for username in the response (indicates successful login)
    std::string lower_username = username_;
    std::transform(lower_username.begin(), lower_username.end(), 
                   lower_username.begin(), ::tolower);
    
    if (response_text.find(lower_username) != std::string::npos) {
        Logger::get()->debug("Found username '{}' in response", username_);
        return true;
    }
    
    // Look for common login success indicators
    std::vector<std::string> success_indicators = {
        "welcome", "dashboard", "profile", "logout", "settings",
        "account", "home", "main", "portal", "authenticated",
        "login successful", "welcome back", "signed in"
    };
    
    for (const auto& indicator : success_indicators) {
        if (response_text.find(indicator) != std::string::npos) {
            Logger::get()->debug("Found login success indicator: '{}'", indicator);
            return true;
        }
    }
    
    // Check for redirect to authenticated areas
    if (response_text.find("location:") != std::string::npos) {
        std::vector<std::string> auth_paths = {
            "/dashboard", "/home", "/profile", "/account", "/main", "/portal"
        };
        
        for (const auto& path : auth_paths) {
            if (response_text.find(path) != std::string::npos) {
                Logger::get()->debug("Found redirect to authenticated area: '{}'", path);
                return true;
            }
        }
    }
    
    // Check for authentication cookies
    if (response_text.find("set-cookie:") != std::string::npos) {
        std::vector<std::string> auth_cookies = {
            "session", "auth", "token", "login", "user", "id"
        };
        
        for (const auto& cookie : auth_cookies) {
            if (response_text.find(cookie) != std::string::npos) {
                Logger::get()->debug("Found authentication cookie containing: '{}'", cookie);
                return true;
            }
        }
    }
    
    return false;
}

} // namespace Dialog
} // namespace Firewall