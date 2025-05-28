#pragma once

#include "dialog_tree.hpp"
#include "dialog_minimizer.hpp"
#include "dialog_diffing.hpp"
#include "../monitor/connection_monitor.hpp"
#include "../utils/logger.hpp"
#include "../utils/config.hpp"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <map>
#include <mutex>
#include <deque>
#include <atomic>
#include <thread>

namespace Firewall {
namespace Dialog {

// Forward declarations to avoid circular dependencies
class DialogBehaviorMonitor;

// Enhanced connection monitor with dialog analysis capabilities
class DialogAnalysisMonitor : public ConnectionMonitor {
public:
    DialogAnalysisMonitor();
    ~DialogAnalysisMonitor() = default;

    // Enhanced monitoring with dialog tree construction
    bool start();
    void stop();

    // Dialog analysis features
    void enableDialogMinimization(bool enable) { enable_minimization_ = enable; }
    void enableDialogDiffing(bool enable) { enable_diffing_ = enable; }
    void enableAttackPatternDetection(bool enable) { enable_attack_detection_ = enable; }
    
    // Dialog analysis results
    const std::vector<std::shared_ptr<NetworkDialogTree>>& getDialogTrees() const { 
        return completed_dialogs_; 
    }
    
    const std::vector<std::shared_ptr<NetworkDialogTree>>& getMinimizedDialogs() const {
        return minimized_dialogs_;
    }
    
    // Attack pattern detection
    bool isKnownAttackPattern(std::shared_ptr<NetworkDialogTree> dialog);
    void addAttackPattern(std::shared_ptr<NetworkDialogTree> pattern, const std::string& name);
    
    // Behavioral analysis enhancement
    void updateBehaviorProfile(const std::string& app, std::shared_ptr<NetworkDialogTree> dialog);

protected:
    // Enhanced packet processing for dialog analysis
    void processEnhancedPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void processHTTPPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet,
                          const struct ip* ip, const char* srcIP, const char* dstIP);

private:
    // Dialog tree construction
    std::shared_ptr<NetworkDialogTree> current_dialog_;
    std::map<std::string, std::shared_ptr<ConnectionNode>> active_connections_;
    std::vector<std::shared_ptr<NetworkDialogTree>> completed_dialogs_;
    std::vector<std::shared_ptr<NetworkDialogTree>> minimized_dialogs_;
    
    // Analysis components
    std::unique_ptr<NetworkDeltaDebugger> minimizer_;
    std::unique_ptr<DialogDiffer> differ_;
    std::unique_ptr<DialogClusterer> clusterer_;
    
    // Known attack patterns
    std::map<std::string, std::shared_ptr<NetworkDialogTree>> attack_patterns_;
    
    // Configuration flags
    bool enable_minimization_ = false;
    bool enable_diffing_ = false;
    bool enable_attack_detection_ = false;
    
    // Dialog management
    void startNewDialog(const std::string& src_ip, const std::string& dst_ip);
    void finalizeDialog();
    std::string getConnectionKey(const std::string& src_ip, uint16_t src_port,
                               const std::string& dst_ip, uint16_t dst_port);
    
    // HTTP message reconstruction
    std::shared_ptr<MessageNode> createHTTPMessage(const u_char* packet, size_t packet_len,
                                                  const std::string& sender_ip,
                                                  MessageNode::Direction direction);
    
    // Dialog analysis workflows
    void analyzeCompletedDialog(std::shared_ptr<NetworkDialogTree> dialog);
    void performDialogMinimization(std::shared_ptr<NetworkDialogTree> dialog);
    void performBehaviorAnalysis(std::shared_ptr<NetworkDialogTree> dialog);
    void performAttackDetection(std::shared_ptr<NetworkDialogTree> dialog);
    
    // Attack pattern management
    void loadAttackPatterns();
    void saveAttackPatterns();
    
    // HTTP parsing helpers
    bool isHTTPMessage(const std::string& data);
    void parseHTTPFields(std::shared_ptr<MessageNode> message, const std::string& data);
};

// Specialized goal functions for security analysis
class SecurityGoalFunction : public GoalFunction {
public:
    enum class SecurityGoalType {
        MALWARE_DOWNLOAD,
        SQL_INJECTION,
        XSS_ATTACK,
        AUTHENTICATION_BYPASS,
        COOKIE_REPLAY,
        COMMAND_INJECTION
    };
    
    SecurityGoalFunction(SecurityGoalType type) : goal_type_(type) {}
    
    bool evaluate(const std::vector<uint8_t>& response_data) override;
    std::string getDescription() const override;

private:
    SecurityGoalType goal_type_;
    
    bool detectMalwareDownload(const std::vector<uint8_t>& data);
    bool detectSQLInjection(const std::vector<uint8_t>& data);
    bool detectXSS(const std::vector<uint8_t>& data);
    bool detectAuthBypass(const std::vector<uint8_t>& data);
    bool detectCookieReplay(const std::vector<uint8_t>& data);
    bool detectCommandInjection(const std::vector<uint8_t>& data);
};

// Attack pattern signature generator
class AttackSignatureGenerator {
public:
    struct AttackSignature {
        std::string name;
        std::shared_ptr<NetworkDialogTree> minimized_dialog;
        std::vector<std::string> critical_fields;
        double confidence_threshold;
        
        // Matching criteria
        size_t min_connections = 1;
        size_t min_messages = 1;
        std::vector<std::string> required_headers;
        std::vector<std::string> payload_patterns;
    };
    
    AttackSignatureGenerator() = default;
    
    // Generate signature from attack dialog
    AttackSignature generateSignature(std::shared_ptr<NetworkDialogTree> attack_dialog,
                                     const std::string& attack_name);
    
    // Match dialog against signatures
    bool matchesSignature(std::shared_ptr<NetworkDialogTree> dialog,
                         const AttackSignature& signature);
    
    // Signature database management
    void loadSignatures(const std::string& filename);
    void saveSignatures(const std::string& filename);
    void addSignature(const AttackSignature& signature);
    
    const std::vector<AttackSignature>& getSignatures() const { return signatures_; }

private:
    std::vector<AttackSignature> signatures_;
    DialogDiffer differ_;
    
    std::vector<std::string> extractCriticalFields(std::shared_ptr<NetworkDialogTree> dialog);
    std::vector<std::string> extractPayloadPatterns(std::shared_ptr<NetworkDialogTree> dialog);
};

// Enhanced behavior monitor using dialog analysis
class DialogBehaviorMonitor {
public:
    static DialogBehaviorMonitor& getInstance() {
        static DialogBehaviorMonitor instance;
        return instance;
    }
    
    // Enhanced behavior recording with dialog analysis
    void recordDialog(const std::string& app, std::shared_ptr<NetworkDialogTree> dialog);
    
    // Anomaly detection using dialog diffing
    bool isAnomalousDialog(const std::string& app, std::shared_ptr<NetworkDialogTree> dialog);
    
    // Behavioral clustering
    void clusterApplicationDialogs(const std::string& app);
    
    // Get dialog profiles for an application
    std::vector<std::shared_ptr<NetworkDialogTree>> getDialogProfile(const std::string& app);

private:
    DialogBehaviorMonitor() = default;
    
    // Dialog storage per application
    std::map<std::string, std::vector<std::shared_ptr<NetworkDialogTree>>> app_dialogs_;
    std::map<std::string, std::vector<DialogClusterer::Cluster>> app_clusters_;
    std::mutex profilesMutex_;
    
    DialogDiffer differ_;
    DialogClusterer clusterer_;
    
    // Anomaly detection thresholds
    double anomaly_threshold_ = 0.3;  // Low similarity indicates anomaly
    size_t min_dialogs_for_profile_ = 10;
};

} // namespace Dialog
} // namespace Firewall