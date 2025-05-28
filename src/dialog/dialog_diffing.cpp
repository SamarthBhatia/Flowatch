#include "../../include/dialog/dialog_diffing.hpp"
#include "../../include/utils/logger.hpp"
#include <sstream>
#include <regex>
#include <algorithm>
#include <numeric>
#include <set>
#include <random>

namespace Firewall {
namespace Dialog {

// HTTPMessageParser Implementation

HTTPMessageParser::HTTPRequest HTTPMessageParser::parseRequest(std::shared_ptr<MessageNode> message) {
    HTTPRequest request;
    
    if (!message || message->getDirection() != MessageNode::Direction::REQUEST) {
        return request;
    }
    
    auto raw_data = message->getRawData();
    if (raw_data.empty()) {
        return request;
    }
    
    std::string data(raw_data.begin(), raw_data.end());
    std::istringstream stream(data);
    std::string line;
    
    // Parse request line
    if (std::getline(stream, line)) {
        std::istringstream line_stream(line);
        std::string method, url, version;
        
        if (line_stream >> method >> url >> version) {
            request.method = method;
            request.url = url;
            
            // Extract path and parameters from URL
            size_t query_pos = url.find('?');
            if (query_pos != std::string::npos) {
                request.path = url.substr(0, query_pos);
                std::string query = url.substr(query_pos + 1);
                request.url_params = parseURLParams(query);
            } else {
                request.path = url;
            }
            
            request.filename = extractFilename(request.path);
        }
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
            
            request.headers[header_name] = header_value;
        }
    }
    
    Logger::get()->debug("Parsed HTTP request: {} {}", request.method, request.path);
    return request;
}

HTTPMessageParser::HTTPResponse HTTPMessageParser::parseResponse(std::shared_ptr<MessageNode> message) {
    HTTPResponse response;
    
    if (!message || message->getDirection() != MessageNode::Direction::RESPONSE) {
        return response;
    }
    
    auto raw_data = message->getRawData();
    if (raw_data.empty()) {
        return response;
    }
    
    std::string data(raw_data.begin(), raw_data.end());
    std::istringstream stream(data);
    std::string line;
    
    // Parse status line
    if (std::getline(stream, line)) {
        std::istringstream line_stream(line);
        std::string version, status_code_str;
        
        if (line_stream >> version >> status_code_str) {
            try {
                response.status_code = std::stoi(status_code_str);
                
                // Get remaining part as status text
                std::string remaining;
                std::getline(line_stream, remaining);
                response.status_text = remaining;
                
                // Trim whitespace
                response.status_text.erase(0, response.status_text.find_first_not_of(" \t"));
                response.status_text.erase(response.status_text.find_last_not_of(" \t\r\n") + 1);
                
            } catch (const std::exception& e) {
                Logger::get()->warn("Failed to parse status code: {}", status_code_str);
            }
        }
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
            
            response.headers[header_name] = header_value;
            
            // Extract content length
            if (header_name == "Content-Length" || header_name == "content-length") {
                try {
                    response.content_length = std::stoull(header_value);
                } catch (const std::exception& e) {
                    Logger::get()->warn("Failed to parse content length: {}", header_value);
                }
            }
        }
    }
    
    Logger::get()->debug("Parsed HTTP response: {} {}", response.status_code, response.status_text);
    return response;
}

std::map<std::string, std::string> HTTPMessageParser::parseURLParams(const std::string& query) {
    std::map<std::string, std::string> params;
    
    if (query.empty()) return params;
    
    std::istringstream stream(query);
    std::string param;
    
    while (std::getline(stream, param, '&')) {
        size_t eq_pos = param.find('=');
        if (eq_pos != std::string::npos) {
            std::string key = param.substr(0, eq_pos);
            std::string value = param.substr(eq_pos + 1);
            params[key] = value;
        } else {
            params[param] = "";  // Parameter without value
        }
    }
    
    return params;
}

std::string HTTPMessageParser::extractFilename(const std::string& path) {
    if (path.empty()) return "";
    
    size_t last_slash = path.find_last_of('/');
    if (last_slash == std::string::npos) {
        return path;
    }
    
    std::string filename = path.substr(last_slash + 1);
    
    // Remove query parameters if any
    size_t query_pos = filename.find('?');
    if (query_pos != std::string::npos) {
        filename = filename.substr(0, query_pos);
    }
    
    return filename;
}

// DialogDiffer Implementation

std::vector<RequestResponsePair> DialogDiffer::extractRRPs(std::shared_ptr<NetworkDialogTree> dialog) {
    std::vector<RequestResponsePair> rrps;
    
    for (auto& connection : dialog->getConnections()) {
        std::shared_ptr<MessageNode> current_request = nullptr;
        
        for (auto& child : connection->getChildren()) {
            if (child->getType() == DialogNode::NodeType::MESSAGE) {
                auto message = std::static_pointer_cast<MessageNode>(child);
                
                if (message->getDirection() == MessageNode::Direction::REQUEST) {
                    // Start new RRP
                    if (current_request) {
                        // Previous request without response
                        rrps.emplace_back(current_request, nullptr);
                    }
                    current_request = message;
                } else if (message->getDirection() == MessageNode::Direction::RESPONSE) {
                    // Complete current RRP
                    if (current_request) {
                        rrps.emplace_back(current_request, message);
                        current_request = nullptr;
                    } else {
                        // Response without request
                        rrps.emplace_back(nullptr, message);
                    }
                }
            }
        }
        
        // Handle dangling request
        if (current_request) {
            rrps.emplace_back(current_request, nullptr);
        }
    }
    
    Logger::get()->debug("Extracted {} RRPs from dialog", rrps.size());
    return rrps;
}

std::vector<std::pair<int, int>> DialogDiffer::hungarianAlignment(
    const std::vector<std::vector<double>>& similarity_matrix) {
    
    std::vector<std::pair<int, int>> alignment;
    size_t n = similarity_matrix.size();
    
    if (n == 0) return alignment;
    
    // Simple greedy assignment for now
    // In a full implementation, you'd use the actual Hungarian algorithm
    std::vector<bool> row_used(n, false);
    std::vector<bool> col_used(n, false);
    
    // Find the best matches greedily
    for (size_t round = 0; round < n; round++) {
        double best_similarity = -1.0;
        int best_i = -1, best_j = -1;
        
        for (size_t i = 0; i < n; i++) {
            if (row_used[i]) continue;
            
            for (size_t j = 0; j < n; j++) {
                if (col_used[j]) continue;
                
                if (similarity_matrix[i][j] > best_similarity) {
                    best_similarity = similarity_matrix[i][j];
                    best_i = i;
                    best_j = j;
                }
            }
        }
        
        if (best_i >= 0 && best_j >= 0) {
            alignment.emplace_back(best_i, best_j);
            row_used[best_i] = true;
            col_used[best_j] = true;
        }
    }
    
    Logger::get()->debug("Hungarian alignment completed with {} pairs", alignment.size());
    return alignment;
}

double DialogDiffer::computeDialogSimilarity(std::shared_ptr<NetworkDialogTree> dialog1,
                                           std::shared_ptr<NetworkDialogTree> dialog2) {
    auto alignment = alignDialogs(dialog1, dialog2);
    return alignment.overall_similarity;
}

// DialogClusterer Implementation

std::vector<DialogClusterer::Cluster> DialogClusterer::aggressiveClustering(
    const std::vector<std::shared_ptr<NetworkDialogTree>>& dialogs) {
    
    std::vector<Cluster> clusters;
    
    Logger::get()->info("Starting aggressive clustering of {} dialogs", dialogs.size());
    
    for (auto& dialog : dialogs) {
        bool added_to_cluster = false;
        
        // Try to add to existing cluster
        for (auto& cluster : clusters) {
            bool similar_to_all = true;
            
            for (auto& cluster_dialog : cluster.dialogs) {
                double similarity = differ_.computeDialogSimilarity(dialog, cluster_dialog);
                if (similarity < similarity_threshold_) {
                    similar_to_all = false;
                    break;
                }
            }
            
            if (similar_to_all) {
                cluster.dialogs.push_back(dialog);
                added_to_cluster = true;
                
                // Recompute cluster centroid and stats
                cluster.centroid = computeCentroid(cluster.dialogs);
                
                // Recompute average intra-cluster similarity
                double total_similarity = 0.0;
                int similarity_count = 0;
                
                for (size_t i = 0; i < cluster.dialogs.size(); i++) {
                    for (size_t j = i + 1; j < cluster.dialogs.size(); j++) {
                        total_similarity += differ_.computeDialogSimilarity(
                            cluster.dialogs[i], cluster.dialogs[j]);
                        similarity_count++;
                    }
                }
                
                cluster.avg_intra_similarity = similarity_count > 0 ? 
                    total_similarity / similarity_count : 1.0;
                
                break;
            }
        }
        
        // Create new cluster if dialog doesn't fit in any existing cluster
        if (!added_to_cluster) {
            Cluster new_cluster;
            new_cluster.dialogs.push_back(dialog);
            new_cluster.centroid = dialog;  // Single dialog is its own centroid
            new_cluster.avg_intra_similarity = 1.0;
            clusters.push_back(new_cluster);
        }
    }
    
    Logger::get()->info("Aggressive clustering completed: {} dialogs -> {} clusters", 
                       dialogs.size(), clusters.size());
    
    return clusters;
}

std::vector<DialogClusterer::Cluster> DialogClusterer::pamClustering(
    const std::vector<std::shared_ptr<NetworkDialogTree>>& dialogs, int k) {
    
    std::vector<Cluster> clusters;
    
    if (dialogs.empty() || k <= 0) {
        return clusters;
    }
    
    Logger::get()->info("Starting PAM clustering: {} dialogs into {} clusters", dialogs.size(), k);
    
    // Initialize k clusters with random medoids
    std::vector<std::shared_ptr<NetworkDialogTree>> medoids;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, dialogs.size() - 1);
    
    std::set<int> selected_indices;
    while (medoids.size() < static_cast<size_t>(k) && medoids.size() < dialogs.size()) {
        int idx = dis(gen);
        if (selected_indices.find(idx) == selected_indices.end()) {
            medoids.push_back(dialogs[idx]);
            selected_indices.insert(idx);
        }
    }
    
    // Initialize clusters
    for (auto& medoid : medoids) {
        Cluster cluster;
        cluster.centroid = medoid;
        clusters.push_back(cluster);
    }
    
    // Assign each dialog to closest medoid
    for (auto& dialog : dialogs) {
        double best_similarity = -1.0;
        int best_cluster = 0;
        
        for (size_t i = 0; i < clusters.size(); i++) {
            double similarity = differ_.computeDialogSimilarity(dialog, clusters[i].centroid);
            if (similarity > best_similarity) {
                best_similarity = similarity;
                best_cluster = i;
            }
        }
        
        clusters[best_cluster].dialogs.push_back(dialog);
    }
    
    // Compute cluster statistics
    for (auto& cluster : clusters) {
        if (cluster.dialogs.size() > 1) {
            double total_similarity = 0.0;
            int similarity_count = 0;
            
            for (size_t i = 0; i < cluster.dialogs.size(); i++) {
                for (size_t j = i + 1; j < cluster.dialogs.size(); j++) {
                    total_similarity += differ_.computeDialogSimilarity(
                        cluster.dialogs[i], cluster.dialogs[j]);
                    similarity_count++;
                }
            }
            
            cluster.avg_intra_similarity = similarity_count > 0 ? 
                total_similarity / similarity_count : 1.0;
        } else {
            cluster.avg_intra_similarity = 1.0;
        }
    }
    
    Logger::get()->info("PAM clustering completed");
    return clusters;
}

std::shared_ptr<NetworkDialogTree> DialogClusterer::computeCentroid(
    const std::vector<std::shared_ptr<NetworkDialogTree>>& dialogs) {
    
    if (dialogs.empty()) {
        return nullptr;
    }
    
    if (dialogs.size() == 1) {
        return dialogs[0];
    }
    
    // Find dialog with highest average similarity to all others
    double best_avg_similarity = -1.0;
    std::shared_ptr<NetworkDialogTree> best_centroid = dialogs[0];
    
    for (auto& candidate : dialogs) {
        double total_similarity = 0.0;
        
        for (auto& other : dialogs) {
            if (candidate != other) {
                total_similarity += differ_.computeDialogSimilarity(candidate, other);
            }
        }
        
        double avg_similarity = total_similarity / (dialogs.size() - 1);
        
        if (avg_similarity > best_avg_similarity) {
            best_avg_similarity = avg_similarity;
            best_centroid = candidate;
        }
    }
    
    return best_centroid;
}

double DialogClusterer::silhouetteWidth(const std::vector<Cluster>& clusters) {
    if (clusters.size() <= 1) {
        return 1.0;  // Perfect silhouette for single cluster
    }
    
    double total_silhouette = 0.0;
    int total_dialogs = 0;
    
    for (size_t cluster_idx = 0; cluster_idx < clusters.size(); cluster_idx++) {
        const auto& cluster = clusters[cluster_idx];
        
        for (auto& dialog : cluster.dialogs) {
            // Compute average intra-cluster distance
            double intra_distance = 0.0;
            int intra_count = 0;
            
            for (auto& other : cluster.dialogs) {
                if (dialog != other) {
                    double similarity = differ_.computeDialogSimilarity(dialog, other);
                    intra_distance += (1.0 - similarity);  // Convert to distance
                    intra_count++;
                }
            }
            
            double avg_intra_distance = intra_count > 0 ? intra_distance / intra_count : 0.0;
            
            // Compute minimum average inter-cluster distance
            double min_inter_distance = std::numeric_limits<double>::max();
            
            for (size_t other_cluster_idx = 0; other_cluster_idx < clusters.size(); other_cluster_idx++) {
                if (other_cluster_idx == cluster_idx) continue;
                
                const auto& other_cluster = clusters[other_cluster_idx];
                double inter_distance = 0.0;
                
                for (auto& other_dialog : other_cluster.dialogs) {
                    double similarity = differ_.computeDialogSimilarity(dialog, other_dialog);
                    inter_distance += (1.0 - similarity);
                }
                
                double avg_inter_distance = inter_distance / other_cluster.dialogs.size();
                min_inter_distance = std::min(min_inter_distance, avg_inter_distance);
            }
            
            // Compute silhouette for this dialog
            double silhouette = 0.0;
            if (avg_intra_distance > 0 || min_inter_distance > 0) {
                silhouette = (min_inter_distance - avg_intra_distance) / 
                           std::max(avg_intra_distance, min_inter_distance);
            }
            
            total_silhouette += silhouette;
            total_dialogs++;
        }
    }
    
    return total_dialogs > 0 ? total_silhouette / total_dialogs : 0.0;
}

void DialogClusterer::printClusteringStats(const std::vector<Cluster>& clusters) {
    Logger::get()->info("Clustering Statistics:");
    Logger::get()->info("  Total clusters: {}", clusters.size());
    
    int total_dialogs = 0;
    for (const auto& cluster : clusters) {
        total_dialogs += cluster.dialogs.size();
    }
    Logger::get()->info("  Total dialogs: {}", total_dialogs);
    
    double avg_cluster_size = clusters.empty() ? 0.0 : 
        static_cast<double>(total_dialogs) / clusters.size();
    Logger::get()->info("  Average cluster size: {:.2f}", avg_cluster_size);
    
    double silhouette = silhouetteWidth(clusters);
    Logger::get()->info("  Silhouette width: {:.3f}", silhouette);
    
    for (size_t i = 0; i < clusters.size(); i++) {
        const auto& cluster = clusters[i];
        Logger::get()->info("  Cluster {}: {} dialogs, avg similarity: {:.3f}", 
                           i, cluster.dialogs.size(), cluster.avg_intra_similarity);
    }
}

} // namespace Dialog
} // namespace Firewall