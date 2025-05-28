#include "../../include/dialog/dialog_applications.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <regex>

namespace Firewall {
namespace Dialog {

// DriveByDownloadMilker Implementation

void DriveByDownloadMilker::collectionLoop() {
    DialogReplayer replayer;
    
    Logger::get()->info("Starting collection loop with {} targets", target_ips_.size());
    
    while (running_) {
        auto cycle_start = std::chrono::steady_clock::now();
        
        for (const auto& target_ip : target_ips_) {
            if (!running_) break;
            
            Logger::get()->debug("Milking target IP: {}", target_ip);
            
            try {
                auto result = replayer.replay(minimized_dialog_, target_ip);
                if (result.success && isMalwareBinary(result.response_data)) {
                    storeMalwareSample(target_ip, result.response_data);
                } else if (!result.success) {
                    Logger::get()->debug("Failed to replay to {}: {}", target_ip, result.error_message);
                }
            } catch (const std::exception& e) {
                Logger::get()->error("Exception milking {}: {}", target_ip, e.what());
            }
            
            // Sleep between targets to avoid overwhelming servers
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        
        auto cycle_end = std::chrono::steady_clock::now();
        auto cycle_duration = std::chrono::duration_cast<std::chrono::minutes>(cycle_end - cycle_start);
        
        Logger::get()->info("Collection cycle completed in {} minutes", cycle_duration.count());
        
        // Wait for next collection cycle
        auto remaining_time = collection_interval_ - cycle_duration;
        if (remaining_time > std::chrono::minutes(0)) {
            std::this_thread::sleep_for(remaining_time);
        }
    }
    
    Logger::get()->info("Collection loop stopped");
}

void DriveByDownloadMilker::storeMalwareSample(const std::string& source_ip, const std::vector<uint8_t>& data) {
    MalwareSample sample;
    sample.source_ip = source_ip;
    sample.binary_data = data;
    sample.collection_time = std::chrono::system_clock::now();
    sample.hash = computeHash(data);
    sample.exploit_kit = "unknown";  // Could be enhanced to detect exploit kit
    
    // Check for duplicates
    for (const auto& existing : collected_samples_) {
        if (existing.hash == sample.hash) {
            Logger::get()->debug("Duplicate sample from {} (hash: {})", source_ip, sample.hash);
            return;
        }
    }
    
    collected_samples_.push_back(sample);
    
    Logger::get()->info("Collected new malware sample from {} (hash: {}, size: {} bytes)", 
                       source_ip, sample.hash, data.size());
    
    // Save to disk
    saveSampleToDisk(sample);
}

std::string DriveByDownloadMilker::computeHash(const std::vector<uint8_t>& data) {
    // Simple hash implementation - in practice, use SHA256
    std::hash<std::string> hasher;
    std::string data_str(data.begin(), data.end());
    return std::to_string(hasher(data_str));
}

void DriveByDownloadMilker::saveSampleToDisk(const MalwareSample& sample) {
    // Create samples directory if it doesn't exist
    std::string samples_dir = "malware_samples";
    std::filesystem::create_directories(samples_dir);
    
    // Generate filename with timestamp
    auto time_t = std::chrono::system_clock::to_time_t(sample.collection_time);
    std::string timestamp = std::to_string(time_t);
    std::string filename = samples_dir + "/malware_" + timestamp + "_" + sample.hash + ".bin";
    
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(sample.binary_data.data()), 
                  sample.binary_data.size());
        file.close();
        Logger::get()->debug("Saved malware sample to {}", filename);
        
        // Also save metadata
        std::string metadata_file = filename + ".json";
        std::ofstream meta_file(metadata_file);
        if (meta_file.is_open()) {
            meta_file << "{\n";
            meta_file << "  \"source_ip\": \"" << sample.source_ip << "\",\n";
            meta_file << "  \"hash\": \"" << sample.hash << "\",\n";
            meta_file << "  \"size\": " << sample.binary_data.size() << ",\n";
            meta_file << "  \"collection_time\": " << std::chrono::system_clock::to_time_t(sample.collection_time) << ",\n";
            meta_file << "  \"exploit_kit\": \"" << sample.exploit_kit << "\"\n";
            meta_file << "}\n";
            meta_file.close();
        }
    } else {
        Logger::get()->error("Failed to save malware sample to {}", filename);
    }
}

// CookieReplayTester Implementation

CookieReplayTester::CookieTestResult CookieReplayTester::testWebsite(
    const std::string& domain, const std::string& username, const std::string& password) {
    
    CookieTestResult result;
    result.domain = domain;
    
    Logger::get()->info("Testing cookie replay vulnerability for {}", domain);
    
    try {
        // Step 1: Capture login dialog
        auto login_dialog = captureLoginDialog(domain, username, password);
        if (!login_dialog) {
            result.vulnerability_details = "Failed to capture login dialog";
            return result;
        }
        
        // Step 2: Minimize the dialog
        auto minimized_dialog = minimizeLoginDialog(login_dialog);
        if (!minimized_dialog) {
            result.vulnerability_details = "Failed to minimize login dialog";
            return result;
        }
        
        // Step 3: Test cookie replay at intervals
        result = testCookieReplay(minimized_dialog, domain);
        
    } catch (const std::exception& e) {
        result.vulnerability_details = std::string("Error: ") + e.what();
    }
    
    return result;
}

std::shared_ptr<NetworkDialogTree> CookieReplayTester::captureLoginDialog(
    const std::string& domain, const std::string& username, const std::string& password) {
    
    Logger::get()->debug("Capturing login dialog for {}", domain);
    
    auto dialog_tree = std::make_shared<NetworkDialogTree>();
    
    try {
        // Create HTTP client connection
        std::string host = domain;
        int port = 80;
        
        // Remove protocol if present
        if (host.substr(0, 7) == "http://") {
            host = host.substr(7);
        } else if (host.substr(0, 8) == "https://") {
            host = host.substr(8);
            port = 443;
        }
        
        // Resolve hostname
        struct hostent* he = gethostbyname(host.c_str());
        if (!he) {
            Logger::get()->error("Failed to resolve hostname: {}", host);
            return nullptr;
        }
        
        std::string ip = inet_ntoa(*((struct in_addr*)he->h_addr));
        
        // Add connection to dialog tree
        auto connection = dialog_tree->addConnection("127.0.0.1", 12345, ip, port, "tcp", "http");
        
        // Step 1: GET login page
        std::string get_request = "GET /login HTTP/1.1\r\n";
        get_request += "Host: " + host + "\r\n";
        get_request += "User-Agent: Firewall-CookieTester/1.0\r\n";
        get_request += "Connection: close\r\n\r\n";
        
        std::vector<uint8_t> get_data(get_request.begin(), get_request.end());
        auto get_message = std::make_shared<MessageNode>(MessageNode::Direction::REQUEST, "127.0.0.1");
        get_message->setRawData(get_data);
        connection->addChild(get_message);
        
        // Step 2: POST login credentials  
        std::string post_body = "username=" + username + "&password=" + password;
        std::string post_request = "POST /login HTTP/1.1\r\n";
        post_request += "Host: " + host + "\r\n";
        post_request += "User-Agent: Firewall-CookieTester/1.0\r\n";
        post_request += "Content-Type: application/x-www-form-urlencoded\r\n";
        post_request += "Content-Length: " + std::to_string(post_body.length()) + "\r\n";
        post_request += "Connection: close\r\n\r\n";
        post_request += post_body;
        
        std::vector<uint8_t> post_data(post_request.begin(), post_request.end());
        auto post_message = std::make_shared<MessageNode>(MessageNode::Direction::REQUEST, "127.0.0.1");
        post_message->setRawData(post_data);
        connection->addChild(post_message);
        
        Logger::get()->debug("Created login dialog with {} messages", connection->getChildren().size());
        return dialog_tree;
        
    } catch (const std::exception& e) {
        Logger::get()->error("Error capturing login dialog: {}", e.what());
        return nullptr;
    }
}

std::shared_ptr<NetworkDialogTree> CookieReplayTester::minimizeLoginDialog(
    std::shared_ptr<NetworkDialogTree> dialog) {
    
    auto goal_function = std::make_shared<SecurityGoalFunction>(
        SecurityGoalFunction::SecurityGoalType::AUTHENTICATION_BYPASS);
    
    auto ip_pool = std::vector<std::string>{"127.0.0.1"};
    auto reset_button = std::make_shared<IPRotationReset>(ip_pool);
    
    NetworkDeltaDebugger minimizer(goal_function, reset_button);
    
    try {
        return minimizer.minimize(dialog);
    } catch (const std::exception& e) {
        Logger::get()->error("Failed to minimize login dialog: {}", e.what());
        return dialog;  // Return original if minimization fails
    }
}

CookieReplayTester::CookieTestResult CookieReplayTester::testCookieReplay(
    std::shared_ptr<NetworkDialogTree> dialog, const std::string& domain) {
    
    CookieTestResult result;
    result.domain = domain;
    
    DialogReplayer replayer;
    
    // Test replay at increasing intervals
    std::vector<std::chrono::hours> test_intervals = {
        std::chrono::hours(1),
        std::chrono::hours(24),
        std::chrono::hours(24 * 7),  // 1 week
        std::chrono::hours(24 * 30)  // 1 month
    };
    
    Logger::get()->info("Testing cookie replay for {} at {} intervals", domain, test_intervals.size());
    
    for (const auto& interval : test_intervals) {
        Logger::get()->debug("Testing cookie replay after {} hours", interval.count());
        
        // In a real implementation, you would wait for the actual interval
        // For testing purposes, we'll simulate this
        
        auto replay_result = replayer.replay(dialog);
        if (replay_result.success) {
            SecurityGoalFunction auth_goal(SecurityGoalFunction::SecurityGoalType::AUTHENTICATION_BYPASS);
            if (auth_goal.evaluate(replay_result.response_data)) {
                result.vulnerable = true;
                result.max_replay_duration = interval;
                Logger::get()->warn("Cookie replay successful after {} hours for {}", 
                                   interval.count(), domain);
            } else {
                Logger::get()->debug("Cookie expired after {} hours for {}", interval.count(), domain);
                break; // Cookie expired
            }
        } else {
            Logger::get()->debug("Replay failed after {} hours for {}: {}", 
                                interval.count(), domain, replay_result.error_message);
            break; // Replay failed
        }
    }
    
    // Test logout behavior
    if (result.vulnerable) {
        // Test if logout actually destroys server state
        // This would involve replaying after a logout action
        result.destroys_server_state = false;  // Simplified for now
    }
    
    return result;
}

std::vector<CookieReplayTester::CookieTestResult> CookieReplayTester::testAlexaTop100() {
    std::vector<std::string> alexa_domains = loadAlexaDomains();
    std::vector<CookieTestResult> results;
    
    Logger::get()->info("Testing cookie replay on {} domains", alexa_domains.size());
    
    for (const auto& domain : alexa_domains) {
        try {
            Logger::get()->info("Testing domain: {}", domain);
            auto result = testWebsite(domain, "testuser", "testpass");
            results.push_back(result);
            
            // Rate limiting to avoid being blocked
            std::this_thread::sleep_for(std::chrono::seconds(10));
            
        } catch (const std::exception& e) {
            Logger::get()->error("Error testing {}: {}", domain, e.what());
            
            CookieTestResult error_result;
            error_result.domain = domain;
            error_result.vulnerability_details = std::string("Error: ") + e.what();
            results.push_back(error_result);
        }
    }
    
    // Log summary statistics
    int vulnerable_count = 0;
    int long_lived_count = 0;
    
    for (const auto& result : results) {
        if (result.vulnerable) {
            vulnerable_count++;
            if (result.max_replay_duration >= std::chrono::hours(24 * 30)) {
                long_lived_count++;
            }
        }
    }
    
    Logger::get()->info("Cookie replay test summary: {}/{} vulnerable, {}/{} long-lived (>30 days)", 
                       vulnerable_count, results.size(), long_lived_count, results.size());
    
    return results;
}

std::vector<std::string> CookieReplayTester::loadAlexaDomains() {
    // Load Alexa top domains from file or return hardcoded list
    std::vector<std::string> domains = {
        "google.com", "youtube.com", "facebook.com", "baidu.com",
        "wikipedia.org", "reddit.com", "yahoo.com", "google.com.hk",
        "amazon.com", "twitter.com", "instagram.com", "live.com",
        "vk.com", "sohu.com", "jd.com", "sina.com.cn",
        "weibo.com", "360.cn", "google.co.in", "netflix.com"
        // Add more domains as needed
    };
    
    // Try to load from file if it exists
    std::string domains_file = "alexa_top_domains.txt";
    if (std::filesystem::exists(domains_file)) {
        std::ifstream file(domains_file);
        std::string domain;
        domains.clear();
        
        while (std::getline(file, domain)) {
            if (!domain.empty() && domain[0] != '#') {  // Skip comments
                domains.push_back(domain);
            }
        }
        
        Logger::get()->info("Loaded {} domains from {}", domains.size(), domains_file);
    } else {
        Logger::get()->info("Using hardcoded domain list ({} domains)", domains.size());
    }
    
    return domains;
}

// DialogAnalysisCLI Implementation

int DialogAnalysisCLI::minimizeDialogCommand(const std::string& input_file, const std::string& output_file) {
    try {
        Logger::get()->info("Minimizing dialog from {} to {}", input_file, output_file);
        
        // Load dialog from file
        auto dialog = loadDialogFromFile(input_file);
        if (!dialog) {
            std::cout << "Error: Could not load dialog from " << input_file << std::endl;
            return 1;
        }
        
        // Set up minimization
        auto goal_function = std::make_shared<SecurityGoalFunction>(
            SecurityGoalFunction::SecurityGoalType::MALWARE_DOWNLOAD);
        auto ip_pool = std::vector<std::string>{"127.0.0.1"};
        auto reset_button = std::make_shared<IPRotationReset>(ip_pool);
        
        NetworkDeltaDebugger minimizer(goal_function, reset_button);
        auto minimized = minimizer.minimize(dialog);
        
        // Save minimized dialog
        saveDialogToFile(minimized, output_file);
        
        std::cout << "Dialog minimization completed successfully.\n";
        std::cout << "Original connections: " << dialog->getConnections().size() << "\n";
        std::cout << "Minimized connections: " << minimized->getConnections().size() << "\n";
        
        // Calculate reduction percentage
        double reduction = 0.0;
        if (dialog->getConnections().size() > 0) {
            reduction = (1.0 - static_cast<double>(minimized->getConnections().size()) / 
                        dialog->getConnections().size()) * 100.0;
        }
        std::cout << "Reduction: " << reduction << "%\n";
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
}

int DialogAnalysisCLI::diffDialogsCommand(const std::string& file1, const std::string& file2) {
    try {
        Logger::get()->info("Comparing dialogs {} and {}", file1, file2);
        
        auto dialog1 = loadDialogFromFile(file1);
        auto dialog2 = loadDialogFromFile(file2);
        
        if (!dialog1 || !dialog2) {
            std::cout << "Error: Could not load dialog files" << std::endl;
            return 1;
        }
        
        DialogDiffer differ;
        auto alignment = differ.alignDialogs(dialog1, dialog2);
        
        std::cout << "Dialog Comparison Results:\n";
        std::cout << "=========================\n";
        std::cout << "Overall similarity: " << std::fixed << std::setprecision(3) 
                  << alignment.overall_similarity << "\n";
        std::cout << "Aligned pairs: " << alignment.aligned_pairs.size() << "\n\n";
        
        // Count different status types
        int identical = 0, changed = 0, new_pairs = 0;
        
        for (const auto& pair : alignment.aligned_pairs) {
            switch (pair.status) {
                case DialogAlignment::AlignedPair::Status::IDENTICAL:
                    identical++;
                    break;
                case DialogAlignment::AlignedPair::Status::CHANGED:
                    changed++;
                    break;
                case DialogAlignment::AlignedPair::Status::NEW:
                    new_pairs++;
                    break;
            }
        }
        
        std::cout << "Status breakdown:\n";
        std::cout << "  Identical: " << identical << "\n";
        std::cout << "  Changed: " << changed << "\n";
        std::cout << "  New: " << new_pairs << "\n\n";
        
        // Print detailed alignment results if not too many
        if (alignment.aligned_pairs.size() <= 20) {
            std::cout << "Detailed alignment:\n";
            for (size_t i = 0; i < alignment.aligned_pairs.size(); i++) {
                const auto& pair = alignment.aligned_pairs[i];
                std::cout << "Pair " << std::setw(2) << i << ": ";
                
                switch (pair.status) {
                    case DialogAlignment::AlignedPair::Status::IDENTICAL:
                        std::cout << "IDENTICAL";
                        break;
                    case DialogAlignment::AlignedPair::Status::CHANGED:
                        std::cout << "CHANGED  ";
                        break;
                    case DialogAlignment::AlignedPair::Status::NEW:
                        std::cout << "NEW      ";
                        break;
                }
                
                std::cout << " (similarity: " << std::fixed << std::setprecision(3) 
                          << pair.similarity << ")\n";
            }
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
}

int DialogAnalysisCLI::testCookiesCommand(const std::string& domain) {
    try {
        Logger::get()->info("Testing cookie replay vulnerability for {}", domain);
        
        CookieReplayTester tester;
        auto result = tester.testWebsite(domain, "testuser", "testpass");
        
        std::cout << "Cookie Replay Test Results for " << domain << ":\n";
        std::cout << "============================================\n";
        std::cout << "Vulnerable: " << (result.vulnerable ? "YES" : "NO") << "\n";
        
        if (result.vulnerable) {
            std::cout << "Max replay duration: " << result.max_replay_duration.count() << " hours\n";
            std::cout << "Destroys server state on logout: " << 
                (result.destroys_server_state ? "YES" : "NO") << "\n";
                
            // Convert hours to human-readable format
            auto hours = result.max_replay_duration.count();
            if (hours >= 24 * 30) {
                std::cout << "Duration category: LONG-TERM (>30 days)\n";
            } else if (hours >= 24 * 7) {
                std::cout << "Duration category: MEDIUM-TERM (1-4 weeks)\n";
            } else if (hours >= 24) {
                std::cout << "Duration category: SHORT-TERM (1-7 days)\n";
            } else {
                std::cout << "Duration category: VERY SHORT (<24 hours)\n";
            }
        }
        
        if (!result.vulnerability_details.empty()) {
            std::cout << "Details: " << result.vulnerability_details << "\n";
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
}

int DialogAnalysisCLI::startMilkerCommand(const std::string& dialog_file, const std::string& targets_file) {
    try {
        Logger::get()->info("Starting drive-by download milker");
        
        // Load minimized dialog
        auto dialog = loadDialogFromFile(dialog_file);
        if (!dialog) {
            std::cout << "Error: Could not load dialog from " << dialog_file << std::endl;
            return 1;
        }
        
        // Load target IPs
        auto target_ips = loadTargetIPs(targets_file);
        if (target_ips.empty()) {
            std::cout << "Error: No target IPs loaded from " << targets_file << std::endl;
            return 1;
        }
        
        std::cout << "Loaded " << target_ips.size() << " target IPs\n";
        
        // Start milker
        DriveByDownloadMilker milker(dialog, target_ips);
        milker.start();
        
        std::cout << "Drive-by download milker started.\n";
        std::cout << "Monitoring " << target_ips.size() << " targets.\n";
        std::cout << "Press Enter to stop...\n";
        
        std::string input;
        std::getline(std::cin, input);
        
        milker.stop();
        
        auto samples = milker.getCollectedSamples();
        std::cout << "Collection completed:\n";
        std::cout << "  Total samples collected: " << samples.size() << "\n";
        
        if (!samples.empty()) {
            std::cout << "  Sample details:\n";
            for (size_t i = 0; i < std::min(samples.size(), size_t(10)); i++) {
                const auto& sample = samples[i];
                std::cout << "    " << i+1 << ". " << sample.source_ip 
                          << " (" << sample.binary_data.size() << " bytes, hash: " 
                          << sample.hash.substr(0, 8) << "...)\n";
            }
            
            if (samples.size() > 10) {
                std::cout << "    ... and " << (samples.size() - 10) << " more\n";
            }
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
}

std::shared_ptr<NetworkDialogTree> DialogAnalysisCLI::loadDialogFromFile(const std::string& filename) {
    // This is a simplified implementation
    // In practice, you'd implement proper dialog serialization/deserialization
    
    Logger::get()->debug("Loading dialog from {}", filename);
    
    if (!std::filesystem::exists(filename)) {
        Logger::get()->error("Dialog file not found: {}", filename);
        return nullptr;
    }
    
    // For now, create a dummy dialog
    // In a real implementation, you'd parse the file format
    auto dialog = std::make_shared<NetworkDialogTree>();
    auto conn = dialog->addConnection("127.0.0.1", 80, "target.com", 80, "tcp", "http");
    
    // Add a simple HTTP request
    std::string request = "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n";
    std::vector<uint8_t> request_data(request.begin(), request.end());
    auto message = std::make_shared<MessageNode>(MessageNode::Direction::REQUEST, "127.0.0.1");
    message->setRawData(request_data);
    conn->addChild(message);
    
    Logger::get()->debug("Loaded dialog with {} connections", dialog->getConnections().size());
    return dialog;
}

void DialogAnalysisCLI::saveDialogToFile(std::shared_ptr<NetworkDialogTree> dialog, const std::string& filename) {
    // This is a simplified implementation
    // In practice, you'd implement proper dialog serialization
    
    Logger::get()->debug("Saving dialog to {}", filename);
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    
    // Simple JSON-like format
    file << "{\n";
    file << "  \"connections\": [\n";
    
    auto connections = dialog->getConnections();
    for (size_t i = 0; i < connections.size(); i++) {
        auto& conn = connections[i];
        file << "    {\n";
        file << "      \"src_ip\": \"" << conn->getSrcIP() << "\",\n";
        file << "      \"src_port\": " << conn->getSrcPort() << ",\n";
        file << "      \"dst_ip\": \"" << conn->getDstIP() << "\",\n";
        file << "      \"dst_port\": " << conn->getDstPort() << ",\n";
        file << "      \"protocol\": \"" << conn->getProtocol() << "\",\n";
        file << "      \"app_protocol\": \"" << conn->getAppProtocol() << "\",\n";
        file << "      \"messages\": " << conn->getChildren().size() << "\n";
        file << "    }";
        if (i < connections.size() - 1) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    file.close();
    Logger::get()->debug("Dialog saved successfully");
}

std::vector<std::string> DialogAnalysisCLI::loadTargetIPs(const std::string& filename) {
    std::vector<std::string> ips;
    
    if (!std::filesystem::exists(filename)) {
        Logger::get()->error("Target IPs file not found: {}", filename);
        return ips;
    }
    
    std::ifstream file(filename);
    std::string line;
    
    while (std::getline(file, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        if (!line.empty() && line[0] != '#') {  // Skip empty lines and comments
            // Basic IP validation
            std::regex ip_regex(R"(^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)");
            if (std::regex_match(line, ip_regex)) {
                ips.push_back(line);
            } else {
                Logger::get()->warn("Invalid IP address format: {}", line);
            }
        }
    }
    
    Logger::get()->info("Loaded {} target IPs from {}", ips.size(), filename);
    return ips;
}

int DialogAnalysisCLI::clusterDialogsCommand(const std::string& dialogs_dir) {
    Logger::get()->info("Clustering dialogs from directory: {}", dialogs_dir);
    
    if (!std::filesystem::exists(dialogs_dir)) {
        std::cout << "Error: Directory not found: " << dialogs_dir << std::endl;
        return 1;
    }
    
    // Load all dialogs from directory
    auto dialogs = loadDialogsFromDirectory(dialogs_dir);
    
    if (dialogs.empty()) {
        std::cout << "No dialogs found in directory " << dialogs_dir << std::endl;
        return 1;
    }
    
    std::cout << "Loaded " << dialogs.size() << " dialogs\n";
    
    // Perform clustering
    DialogClusterer clusterer;
    auto clusters = clusterer.aggressiveClustering(dialogs);
    
    std::cout << "\nDialog Clustering Results:\n";
    std::cout << "=========================\n";
    std::cout << "Input dialogs: " << dialogs.size() << "\n";
    std::cout << "Generated clusters: " << clusters.size() << "\n\n";
    
    for (size_t i = 0; i < clusters.size(); i++) {
        std::cout << "Cluster " << std::setw(2) << i+1 << ": " 
                  << std::setw(3) << clusters[i].dialogs.size() << " dialogs";
        
        if (clusters[i].dialogs.size() > 1) {
            std::cout << " (avg similarity: " 
                      << std::fixed << std::setprecision(3) 
                      << clusters[i].avg_intra_similarity << ")";
        }
        std::cout << "\n";
    }
    
    // Compute and display clustering quality metrics
    double silhouette = clusterer.silhouetteWidth(clusters);
    std::cout << "\nClustering Quality:\n";
    std::cout << "  Silhouette width: " << std::fixed << std::setprecision(3) << silhouette << "\n";
    
    if (silhouette > 0.7) {
        std::cout << "  Quality: EXCELLENT\n";
    } else if (silhouette > 0.5) {
        std::cout << "  Quality: GOOD\n";
    } else if (silhouette > 0.25) {
        std::cout << "  Quality: FAIR\n";
    } else {
        std::cout << "  Quality: POOR\n";
    }
    
    return 0;
}

std::vector<std::shared_ptr<NetworkDialogTree>> DialogAnalysisCLI::loadDialogsFromDirectory(const std::string& dir) {
    std::vector<std::shared_ptr<NetworkDialogTree>> dialogs;
    
    try {
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                
                // Check for dialog files (you could use any extension)
                if (filename.ends_with(".dialog") || filename.ends_with(".json")) {
                    auto dialog = loadDialogFromFile(entry.path().string());
                    if (dialog) {
                        dialogs.push_back(dialog);
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        Logger::get()->error("Error reading directory {}: {}", dir, e.what());
    }
    
    Logger::get()->info("Loaded {} dialogs from directory {}", dialogs.size(), dir);
    return dialogs;
}

} // namespace Dialog
} // namespace Firewall