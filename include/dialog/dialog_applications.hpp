#pragma once

#include "dialog_integration.hpp"
#include "dialog_minimizer.hpp"
#include "../cli/interface.hpp"
#include "../utils/logger.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <string>
#include <iomanip>

namespace Firewall {
namespace Dialog {

// Forward declarations
class DialogReplayer;
class SecurityGoalFunction;

// Malware sample structure (moved to public)
struct MalwareSample {
    std::string source_ip;
    std::vector<uint8_t> binary_data;
    std::string hash;
    std::chrono::system_clock::time_point collection_time;
    std::string exploit_kit;
};

// Drive-by download milker implementation
class DriveByDownloadMilker {
public:
    DriveByDownloadMilker(std::shared_ptr<NetworkDialogTree> minimized_dialog,
                         const std::vector<std::string>& target_ips,
                         std::chrono::minutes interval = std::chrono::minutes(60))
        : minimized_dialog_(minimized_dialog), target_ips_(target_ips), 
          collection_interval_(interval), running_(false) {}
    
    void start();
    void stop();
    
    const std::vector<MalwareSample>& getCollectedSamples() const { 
        return collected_samples_; 
    }

private:
    std::shared_ptr<NetworkDialogTree> minimized_dialog_;
    std::vector<std::string> target_ips_;
    std::chrono::minutes collection_interval_;
    std::atomic<bool> running_;
    std::thread collection_thread_;
    std::vector<MalwareSample> collected_samples_;
    
    void collectionLoop();
    bool isMalwareBinary(const std::vector<uint8_t>& data);
    void storeMalwareSample(const std::string& source_ip, const std::vector<uint8_t>& data);
    std::string computeHash(const std::vector<uint8_t>& data);
    void saveSampleToDisk(const MalwareSample& sample);
};

// Cookie replay vulnerability tester
class CookieReplayTester {
public:
    struct CookieTestResult {
        std::string domain;
        bool vulnerable = false;
        std::chrono::hours max_replay_duration{0};
        bool destroys_server_state = false;
        std::string vulnerability_details;
    };
    
    CookieReplayTester() = default;
    
    // Test a website for cookie replay vulnerabilities
    CookieTestResult testWebsite(const std::string& domain, 
                               const std::string& username,
                               const std::string& password);
    
    // Test multiple websites from Alexa top list
    std::vector<CookieTestResult> testAlexaTop100();

private:
    std::shared_ptr<NetworkDialogTree> captureLoginDialog(const std::string& domain,
                                                         const std::string& username,
                                                         const std::string& password);
    
    std::shared_ptr<NetworkDialogTree> minimizeLoginDialog(std::shared_ptr<NetworkDialogTree> dialog);
    
    CookieTestResult testCookieReplay(std::shared_ptr<NetworkDialogTree> dialog,
                                    const std::string& domain);
    
    std::vector<std::string> loadAlexaDomains();
};

// Enhanced CLI interface with dialog analysis commands
class DialogAnalysisCLI : public CLI::Interface {
public:
    DialogAnalysisCLI(int argc, char* argv[]) : CLI::Interface(argc, argv) {}
    
    int run() ;

private:
    void showEnhancedHelp();
    int minimizeDialogCommand(const std::string& input_file, const std::string& output_file);
    int diffDialogsCommand(const std::string& file1, const std::string& file2);
    int testCookiesCommand(const std::string& domain);
    int startMilkerCommand(const std::string& dialog_file, const std::string& targets_file);
    int clusterDialogsCommand(const std::string& dialogs_dir);
    
    // Helper methods
    std::shared_ptr<NetworkDialogTree> loadDialogFromFile(const std::string& filename);
    void saveDialogToFile(std::shared_ptr<NetworkDialogTree> dialog, const std::string& filename);
    std::vector<std::string> loadTargetIPs(const std::string& filename);
    std::vector<std::shared_ptr<NetworkDialogTree>> loadDialogsFromDirectory(const std::string& dir);
};

} // namespace Dialog
} // namespace Firewall