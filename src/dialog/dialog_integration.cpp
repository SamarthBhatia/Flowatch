#include "../../include/dialog/dialog_integration.hpp"
#include "../../include/monitor/behavior_monitor.hpp"
#include "../../include/geo/location_manager.hpp"
#include <regex>
#include <chrono>
#include <algorithm>

namespace Firewall {
namespace Dialog {

// DialogAnalysisMonitor Implementation

bool DialogAnalysisMonitor::start() {
    Logger::get()->info("Starting enhanced dialog analysis monitor");
    
    // Load configuration
    enable_minimization_ = Config::getInstance().get<bool>("dialog_analysis.enable_dialog_minimization", false);
    enable_diffing_ = Config::getInstance().get<bool>("dialog_analysis.enable_dialog_diffing", false);
    enable_attack_detection_ = Config::getInstance().get<bool>("dialog_analysis.enable_attack_detection", true);
    
    Logger::get()->info("Dialog analysis features - Minimization: {}, Diffing: {}, Attack Detection: {}",
                       enable_minimization_, enable_diffing_, enable_attack_detection_);
    
    // Load attack patterns
    loadAttackPatterns();
    
    return ConnectionMonitor::start();
}

void DialogAnalysisMonitor::stop() {
    Logger::get()->info("Stopping dialog analysis monitor");
    
    // Finalize any pending dialogs
    finalizeDialog();
    
    // Save attack patterns
    saveAttackPatterns();
    
    ConnectionMonitor::stop();
}

void DialogAnalysisMonitor::processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Call parent implementation first
    ConnectionMonitor::processPacket(pkthdr, packet);
    
    // Enhanced processing for dialog tree construction
    const struct ip* ip = reinterpret_cast<const struct ip*>(packet + 14);
    
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(ip->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dstIP, INET_ADDRSTRLEN);
    
    // Process based on protocol
    if (ip->ip_p == IPPROTO_TCP) {
        processHTTPPacket(pkthdr, packet, ip, srcIP, dstIP);
    }
    // Add UDP processing if needed
}

void DialogAnalysisMonitor::processHTTPPacket(const struct pcap_pkthdr* pkthdr, 
                                            const u_char* packet,
                                            const struct ip* ip, 
                                            const char* srcIP, 
                                            const char* dstIP) {
    
    const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + 14 + (ip->ip_hl << 2));
    int srcPort = ntohs(tcp->th_sport);
    int dstPort = ntohs(tcp->th_dport);
    
    std::string conn_key = getConnectionKey(srcIP, srcPort, dstIP, dstPort);
    
    // Start new dialog if needed
    if (current_dialog_->getConnections().empty()) {
        startNewDialog(srcIP, dstIP);
    }
    
    // Get or create connection node
    auto conn_it = active_connections_.find(conn_key);
    if (conn_it == active_connections_.end()) {
        auto connection = current_dialog_->addConnection(srcIP, srcPort, dstIP, dstPort, "tcp", "http");
        active_connections_[conn_key] = connection;
        Logger::get()->debug("Created new connection node for {}", conn_key);
    }
    
    // Extract HTTP message from packet
    size_t tcp_header_len = tcp->th_off * 4;
    size_t ip_header_len = ip->ip_hl * 4;
    size_t payload_offset = 14 + ip_header_len + tcp_header_len;
    
    if (pkthdr->len > payload_offset) {
        // Determine message direction
        std::string local_ip = getLocalIPAddress();
        MessageNode::Direction direction = (std::string(srcIP) == local_ip) ? 
            MessageNode::Direction::REQUEST : MessageNode::Direction::RESPONSE;
        
        auto message = createHTTPMessage(packet + payload_offset, 
                                       pkthdr->len - payload_offset,
                                       srcIP, direction);
        
        if (message) {
            active_connections_[conn_key]->addChild(message);
            Logger::get()->debug("Added HTTP message to connection {}", conn_key);
        }
    }
    
    // Check if dialog should be finalized
    if (tcp->th_flags & (TH_FIN | TH_RST)) {
        finalizeDialog();
    }
}

void DialogAnalysisMonitor::startNewDialog(const std::string& src_ip, const std::string& dst_ip) {
    current_dialog_ = std::make_shared<NetworkDialogTree>();
    current_dialog_->getRoot()->addPeer(src_ip);
    current_dialog_->getRoot()->addPeer(dst_ip);
    
    Logger::get()->debug("Started new dialog between {} and {}", src_ip, dst_ip);
}

void DialogAnalysisMonitor::finalizeDialog() {
    if (!current_dialog_ || current_dialog_->getConnections().empty()) {
        return;
    }
    
    Logger::get()->info("Finalizing dialog with {} connections", 
                       current_dialog_->getConnections().size());
    
    // Store completed dialog
    completed_dialogs_.push_back(current_dialog_);
    
    // Keep only recent dialogs to avoid memory issues
    if (completed_dialogs_.size() > 100) {
        completed_dialogs_.erase(completed_dialogs_.begin());
    }
    
    // Perform analysis
    analyzeCompletedDialog(current_dialog_);
    
    // Start new dialog
    current_dialog_ = std::make_shared<NetworkDialogTree>();
    active_connections_.clear();
}

std::string DialogAnalysisMonitor::getConnectionKey(const std::string& src_ip, uint16_t src_port,
                                                  const std::string& dst_ip, uint16_t dst_port) {
    return src_ip + ":" + std::to_string(src_port) + "->" + dst_ip + ":" + std::to_string(dst_port);
}

std::shared_ptr<MessageNode> DialogAnalysisMonitor::createHTTPMessage(
    const u_char* packet, size_t packet_len,
    const std::string& sender_ip,
    MessageNode::Direction direction) {
    
    if (packet_len == 0) {
        return nullptr;
    }
    
    // Convert packet to vector
    std::vector<uint8_t> data(packet, packet + packet_len);
    
    // Create message node
    auto message = std::make_shared<MessageNode>(direction, sender_ip);
    message->setRawData(data);
    
    // Parse HTTP fields if this looks like HTTP
    std::string data_str(data.begin(), data.end());
    if (isHTTPMessage(data_str)) {
        parseHTTPFields(message, data_str);
    }
    
    return message;
}

bool DialogAnalysisMonitor::isHTTPMessage(const std::string& data) {
    // Check for HTTP request methods
    std::vector<std::string> http_methods = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "};
    for (const auto& method : http_methods) {
        if (data.substr(0, method.length()) == method) {
            return true;
        }
    }
    
    // Check for HTTP response
    if (data.substr(0, 4) == "HTTP") {
        return true;
    }
    
    return false;
}

void DialogAnalysisMonitor::parseHTTPFields(std::shared_ptr<MessageNode> message, const std::string& data) {
    std::istringstream stream(data);
    std::string line;
    size_t offset = 0;
    
    // Parse first line (request line or status line)
    if (std::getline(stream, line)) {
        auto field = std::make_shared<FieldNode>("request-line", line, offset, offset + line.length());
        message->addChild(field);
        offset += line.length() + 1; // +1 for newline
    }
    
    // Parse headers
    while (std::getline(stream, line) && !line.empty() && line != "\r") {
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string header_name = line.substr(0, colon_pos);
            std::string header_value = line.substr(colon_pos + 1);
            
            // Trim whitespace
            header_name.erase(0, header_name.find_first_not_of(" \t"));
            header_name.erase(header_name.find_last_not_of(" \t\r\n") + 1);
            header_value.erase(0, header_value.find_first_not_of(" \t"));
            header_value.erase(header_value.find_last_not_of(" \t\r\n") + 1);
            
            auto field = std::make_shared<FieldNode>(header_name, header_value, offset, offset + line.length());
            message->addChild(field);
        }
        offset += line.length() + 1;
    }
}

void DialogAnalysisMonitor::analyzeCompletedDialog(std::shared_ptr<NetworkDialogTree> dialog) {
    try {
        // Attack pattern detection
        if (enable_attack_detection_) {
            performAttackDetection(dialog);
        }
        
        // Dialog minimization
        if (enable_minimization_) {
            performDialogMinimization(dialog);
        }
        
        // Behavior analysis
        performBehaviorAnalysis(dialog);
        
    } catch (const std::exception& e) {
        Logger::get()->error("Error in dialog analysis: {}", e.what());
    }
}

void DialogAnalysisMonitor::performAttackDetection(std::shared_ptr<NetworkDialogTree> dialog) {
    Logger::get()->debug("Performing attack pattern detection");
    
    // Check against known attack patterns
    for (const auto& [pattern_name, pattern_dialog] : attack_patterns_) {
        double similarity = differ_->computeDialogSimilarity(dialog, pattern_dialog);
        
        if (similarity > 0.8) {  // High similarity threshold for attack detection
            Logger::get()->warn("Detected potential attack pattern '{}' with similarity {:.3f}", 
                               pattern_name, similarity);
            
            // Update blocked count
            int blockCount = Config::getInstance().get<int>("blocked_count", 0);
            Config::getInstance().set("blocked_count", blockCount + 1);
            
            // Add to recent blocks
            addToRecentBlocks("unknown", "unknown", 0, "Attack Pattern: " + pattern_name);
            break;
        }
    }
}

void DialogAnalysisMonitor::performDialogMinimization(std::shared_ptr<NetworkDialogTree> dialog) {
    Logger::get()->debug("Performing dialog minimization");
    
    try {
        auto minimized = minimizer_->minimize(dialog);
        minimized_dialogs_.push_back(minimized);
        
        // Keep only recent minimized dialogs
        if (minimized_dialogs_.size() > 50) {
            minimized_dialogs_.erase(minimized_dialogs_.begin());
        }
        
        Logger::get()->info("Dialog minimized: {} -> {} connections", 
                           dialog->getConnections().size(),
                           minimized->getConnections().size());
    } catch (const std::exception& e) {
        Logger::get()->error("Dialog minimization failed: {}", e.what());
    }
}

void DialogAnalysisMonitor::performBehaviorAnalysis(std::shared_ptr<NetworkDialogTree> dialog) {
    // Enhanced behavior analysis using dialog patterns
    DialogBehaviorMonitor::getInstance().recordDialog("unknown", dialog);
    
    // Check for anomalous behavior
    if (DialogBehaviorMonitor::getInstance().isAnomalousDialog("unknown", dialog)) {
        Logger::get()->warn("Anomalous dialog behavior detected");
        
        // Add to blocked connections
        addToRecentBlocks("unknown", "unknown", 0, "Anomalous Behavior");
    }
}

bool DialogAnalysisMonitor::isKnownAttackPattern(std::shared_ptr<NetworkDialogTree> dialog) {
    for (const auto& [pattern_name, pattern_dialog] : attack_patterns_) {
        double similarity = differ_->computeDialogSimilarity(dialog, pattern_dialog);
        if (similarity > 0.8) {
            return true;
        }
    }
    return false;
}

void DialogAnalysisMonitor::addAttackPattern(std::shared_ptr<NetworkDialogTree> pattern, const std::string& name) {
    attack_patterns_[name] = pattern;
    Logger::get()->info("Added attack pattern: {}", name);
}

void DialogAnalysisMonitor::loadAttackPatterns() {
    std::string patterns_file = Config::getInstance().get<std::string>(
        "dialog_analysis.attack_detection.signatures_file", 
        "~/.config/firewall/attack_signatures.json");
    
    Logger::get()->info("Loading attack patterns from {}", patterns_file);
    
    // Implementation would load patterns from file
    // For now, create some basic patterns
    
    // SQL Injection pattern (simplified)
    auto sql_injection_pattern = std::make_shared<NetworkDialogTree>();
    // ... create pattern ...
    attack_patterns_["sql_injection"] = sql_injection_pattern;
    
    Logger::get()->info("Loaded {} attack patterns", attack_patterns_.size());
}

void DialogAnalysisMonitor::saveAttackPatterns() {
    std::string patterns_file = Config::getInstance().get<std::string>(
        "dialog_analysis.attack_detection.signatures_file", 
        "~/.config/firewall/attack_signatures.json");
    
    Logger::get()->info("Saving attack patterns to {}", patterns_file);
    
    // Implementation would save patterns to file
    // This is a placeholder
}

void DialogAnalysisMonitor::updateBehaviorProfile(const std::string& app, std::shared_ptr<NetworkDialogTree> dialog) {
    DialogBehaviorMonitor::getInstance().recordDialog(app, dialog);
}

// SecurityGoalFunction Implementation

bool SecurityGoalFunction::evaluate(const std::vector<uint8_t>& response_data) {
    switch (goal_type_) {
        case SecurityGoalType::MALWARE_DOWNLOAD:
            return detectMalwareDownload(response_data);
        case SecurityGoalType::SQL_INJECTION:
            return detectSQLInjection(response_data);
        case SecurityGoalType::XSS_ATTACK:
            return detectXSS(response_data);
        case SecurityGoalType::AUTHENTICATION_BYPASS:
            return detectAuthBypass(response_data);
        case SecurityGoalType::COOKIE_REPLAY:
            return detectCookieReplay(response_data);
        case SecurityGoalType::COMMAND_INJECTION:
            return detectCommandInjection(response_data);
        default:
            return false;
    }
}

std::string SecurityGoalFunction::getDescription() const {
    switch (goal_type_) {
        case SecurityGoalType::MALWARE_DOWNLOAD:
            return "Detect malware download";
        case SecurityGoalType::SQL_INJECTION:
            return "Detect SQL injection";
        case SecurityGoalType::XSS_ATTACK:
            return "Detect XSS attack";
        case SecurityGoalType::AUTHENTICATION_BYPASS:
            return "Detect authentication bypass";
        case SecurityGoalType::COOKIE_REPLAY:
            return "Detect cookie replay";
        case SecurityGoalType::COMMAND_INJECTION:
            return "Detect command injection";
        default:
            return "Unknown security goal";
    }
}

bool SecurityGoalFunction::detectMalwareDownload(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return false;
    
    // Check for PE header (MZ signature)
    if (data[0] == 0x4D && data[1] == 0x5A) {
        return true;
    }
    
    // Check for ELF header
    if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E' && 
        data[2] == 'L' && data[3] == 'F') {
        return true;
    }
    
    return false;
}

bool SecurityGoalFunction::detectSQLInjection(const std::vector<uint8_t>& data) {
    std::string response(data.begin(), data.end());
    std::transform(response.begin(), response.end(), response.begin(), ::tolower);
    
    std::vector<std::string> sql_error_patterns = {
        "sql syntax", "mysql_fetch", "ora-", "sqlstate", "sqlite_", 
        "postgresql", "microsoft ole db", "odbc", "jdbc"
    };
    
    for (const auto& pattern : sql_error_patterns) {
        if (response.find(pattern) != std::string::npos) {
            Logger::get()->debug("SQL injection detected: found pattern '{}'", pattern);
            return true;
        }
    }
    
    return false;
}

bool SecurityGoalFunction::detectXSS(const std::vector<uint8_t>& data) {
    std::string response(data.begin(), data.end());
    
    std::vector<std::string> xss_patterns = {
        "<script", "javascript:", "onerror=", "onload=", "onclick=",
        "eval(", "alert(", "document.cookie"
    };
    
    for (const auto& pattern : xss_patterns) {
        if (response.find(pattern) != std::string::npos) {
            Logger::get()->debug("XSS detected: found pattern '{}'", pattern);
            return true;
        }
    }
    
    return false;
}

bool SecurityGoalFunction::detectAuthBypass(const std::vector<uint8_t>& data) {
    std::string response(data.begin(), data.end());
    std::transform(response.begin(), response.end(), response.begin(), ::tolower);
    
    std::vector<std::string> auth_success_patterns = {
        "welcome", "dashboard", "profile", "logout", "settings",
        "authenticated", "login successful", "signed in"
    };
    
    for (const auto& pattern : auth_success_patterns) {
        if (response.find(pattern) != std::string::npos) {
            Logger::get()->debug("Authentication bypass detected: found pattern '{}'", pattern);
            return true;
        }
    }
    
    return false;
}

bool SecurityGoalFunction::detectCookieReplay(const std::vector<uint8_t>& data) {
    std::string response(data.begin(), data.end());
    std::transform(response.begin(), response.end(), response.begin(), ::tolower);
    
    // Look for session-related content indicating successful cookie replay
    std::vector<std::string> session_patterns = {
        "session", "logged in", "welcome back", "user profile"
    };
    
    for (const auto& pattern : session_patterns) {
        if (response.find(pattern) != std::string::npos) {
            Logger::get()->debug("Cookie replay detected: found pattern '{}'", pattern);
            return true;
        }
    }
    
    return false;
}

bool SecurityGoalFunction::detectCommandInjection(const std::vector<uint8_t>& data) {
    std::string response(data.begin(), data.end());
    
    std::vector<std::string> command_patterns = {
        "total ", "drwx", "uid=", "gid=", "root:", "/bin/", "/usr/bin/",
        "command not found", "permission denied", "directory listing"
    };
    
    for (const auto& pattern : command_patterns) {
        if (response.find(pattern) != std::string::npos) {
            Logger::get()->debug("Command injection detected: found pattern '{}'", pattern);
            return true;
        }
    }
    
    return false;
}

// AttackSignatureGenerator Implementation

AttackSignatureGenerator::AttackSignature AttackSignatureGenerator::generateSignature(
    std::shared_ptr<NetworkDialogTree> attack_dialog, const std::string& attack_name) {
    
    AttackSignature signature;
    signature.name = attack_name;
    signature.confidence_threshold = 0.8;
    
    Logger::get()->info("Generating signature for attack: {}", attack_name);
    
    // Minimize the attack dialog first
    auto ip_pool = std::vector<std::string>{"127.0.0.1"};
    auto reset_button = std::make_shared<IPRotationReset>(ip_pool);
    auto goal_function = std::make_shared<SecurityGoalFunction>(
        SecurityGoalFunction::SecurityGoalType::MALWARE_DOWNLOAD);
    
    NetworkDeltaDebugger minimizer(goal_function, reset_button);
    
    try {
        signature.minimized_dialog = minimizer.minimize(attack_dialog);
    } catch (const std::exception& e) {
        Logger::get()->warn("Failed to minimize attack dialog: {}", e.what());
        signature.minimized_dialog = attack_dialog;
    }
    
    // Extract critical fields
    signature.critical_fields = extractCriticalFields(signature.minimized_dialog);
    
    // Extract payload patterns
    signature.payload_patterns = extractPayloadPatterns(signature.minimized_dialog);
    
    // Set requirements based on minimized dialog
    signature.min_connections = signature.minimized_dialog->getConnections().size();
    
    size_t total_messages = 0;
    for (auto& conn : signature.minimized_dialog->getConnections()) {
        total_messages += conn->getChildren().size();
    }
    signature.min_messages = total_messages;
    
    Logger::get()->info("Generated signature '{}' with {} connections, {} messages", 
                       attack_name, signature.min_connections, signature.min_messages);
    
    return signature;
}

std::vector<std::string> AttackSignatureGenerator::extractCriticalFields(
    std::shared_ptr<NetworkDialogTree> dialog) {
    
    std::vector<std::string> critical_fields;
    
    for (auto& conn : dialog->getConnections()) {
        for (auto& child : conn->getChildren()) {
            if (child->getType() == DialogNode::NodeType::MESSAGE) {
                auto message = std::static_pointer_cast<MessageNode>(child);
                
                for (auto& field_child : message->getChildren()) {
                    if (field_child->getType() == DialogNode::NodeType::FIELD) {
                        auto field = std::static_pointer_cast<FieldNode>(field_child);
                        critical_fields.push_back(field->getName());
                    }
                }
            }
        }
    }
    
    // Remove duplicates
    std::sort(critical_fields.begin(), critical_fields.end());
    critical_fields.erase(std::unique(critical_fields.begin(), critical_fields.end()), 
                         critical_fields.end());
    
    return critical_fields;
}

std::vector<std::string> AttackSignatureGenerator::extractPayloadPatterns(
    std::shared_ptr<NetworkDialogTree> dialog) {
    
    std::vector<std::string> patterns;
    
    for (auto& conn : dialog->getConnections()) {
        for (auto& child : conn->getChildren()) {
            if (child->getType() == DialogNode::NodeType::MESSAGE) {
                auto message = std::static_pointer_cast<MessageNode>(child);
                auto raw_data = message->getRawData();
                
                if (!raw_data.empty()) {
                    std::string data_str(raw_data.begin(), raw_data.end());
                    
                    // Extract suspicious patterns
                    std::regex sql_pattern(R"((union|select|insert|update|delete|drop)\s+)", 
                                         std::regex_constants::icase);
                    std::regex xss_pattern(R"(<script|javascript:|onerror=|onload=)", 
                                         std::regex_constants::icase);
                    std::regex cmd_pattern(R"(;|\||\&\&|\|\||`)", std::regex_constants::icase);
                    
                    std::smatch match;
                    if (std::regex_search(data_str, match, sql_pattern)) {
                        patterns.push_back("SQL:" + match.str());
                    }
                    if (std::regex_search(data_str, match, xss_pattern)) {
                        patterns.push_back("XSS:" + match.str());
                    }
                    if (std::regex_search(data_str, match, cmd_pattern)) {
                        patterns.push_back("CMD:" + match.str());
                    }
                }
            }
        }
    }
    
    return patterns;
}

bool AttackSignatureGenerator::matchesSignature(std::shared_ptr<NetworkDialogTree> dialog,
                                               const AttackSignature& signature) {
    
    // Check minimum requirements
    if (dialog->getConnections().size() < signature.min_connections) {
        return false;
    }
    
    size_t total_messages = 0;
    for (auto& conn : dialog->getConnections()) {
        total_messages += conn->getChildren().size();
    }
    
    if (total_messages < signature.min_messages) {
        return false;
    }
    
    // Check dialog similarity
    double similarity = differ_.computeDialogSimilarity(dialog, signature.minimized_dialog);
    
    return similarity >= signature.confidence_threshold;
}

// DialogBehaviorMonitor Implementation

void DialogBehaviorMonitor::recordDialog(const std::string& app, std::shared_ptr<NetworkDialogTree> dialog) {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    app_dialogs_[app].push_back(dialog);
    
    // Keep only recent dialogs to avoid memory issues
    if (app_dialogs_[app].size() > 100) {
        app_dialogs_[app].erase(app_dialogs_[app].begin());
    }
    
    Logger::get()->debug("Recorded dialog for app: {} (total: {})", app, app_dialogs_[app].size());
    
    // Trigger clustering if we have enough dialogs
    if (app_dialogs_[app].size() >= min_dialogs_for_profile_ && 
        app_dialogs_[app].size() % 10 == 0) {  // Every 10 new dialogs
        clusterApplicationDialogs(app);
    }
}

bool DialogBehaviorMonitor::isAnomalousDialog(const std::string& app, std::shared_ptr<NetworkDialogTree> dialog) {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    auto it = app_dialogs_.find(app);
    if (it == app_dialogs_.end() || it->second.size() < min_dialogs_for_profile_) {
        return false;  // Not enough data to determine anomaly
    }
    
    // Calculate average similarity to existing dialogs
    double total_similarity = 0.0;
    size_t count = 0;
    
    for (auto& existing_dialog : it->second) {
        double similarity = differ_.computeDialogSimilarity(dialog, existing_dialog);
        total_similarity += similarity;
        count++;
    }
    
    double avg_similarity = count > 0 ? total_similarity / count : 0.0;
    
    Logger::get()->debug("Dialog similarity for {}: {:.3f} (threshold: {:.3f})", 
                        app, avg_similarity, anomaly_threshold_);
    
    return avg_similarity < anomaly_threshold_;
}

void DialogBehaviorMonitor::clusterApplicationDialogs(const std::string& app) {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    auto it = app_dialogs_.find(app);
    if (it == app_dialogs_.end() || it->second.size() < min_dialogs_for_profile_) {
        return;
    }
    
    Logger::get()->info("Clustering dialogs for application: {}", app);
    
    auto clusters = clusterer_.aggressiveClustering(it->second);
    app_clusters_[app] = clusters;
    
    Logger::get()->info("Application {} clustered into {} groups", app, clusters.size());
}

std::vector<std::shared_ptr<NetworkDialogTree>> DialogBehaviorMonitor::getDialogProfile(const std::string& app) {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    auto it = app_dialogs_.find(app);
    if (it != app_dialogs_.end()) {
        return it->second;
    }
    
    return {};
}

} // namespace Dialog
} // namespace Firewall