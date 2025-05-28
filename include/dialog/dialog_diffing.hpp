#pragma once

#include "dialog_tree.hpp"
#include "../utils/logger.hpp"
#include <algorithm>
#include <numeric>
#include <set>

namespace Firewall {
namespace Dialog {

// Request-Response Pair for HTTP analysis
struct RequestResponsePair {
    std::shared_ptr<MessageNode> request;
    std::shared_ptr<MessageNode> response;
    
    RequestResponsePair(std::shared_ptr<MessageNode> req = nullptr, 
                       std::shared_ptr<MessageNode> resp = nullptr)
        : request(req), response(resp) {}
};

// Dialog similarity features
struct SimilarityFeatures {
    bool same_request_type = false;      // Same HTTP method
    bool same_url_path = false;          // Same URL path
    bool same_url_filename = false;      // Same filename
    double url_params_similarity = 0.0;  // Jaccard index of URL parameters
    bool same_referer = false;           // Same Referer header
    bool same_response_type = false;     // Same response code
    bool same_server_header = false;     // Same Server header
    bool same_location_header = false;   // Same Location header
    bool same_content_type = false;      // Same Content-Type header
    double content_length_similarity = 0.0; // Content length similarity
    double response_headers_similarity = 0.0; // Jaccard index of response headers
    
    double computeOverallSimilarity() const {
        double boolean_features = 0.0;
        int boolean_count = 0;
        
        if (same_request_type) boolean_features += 1.0; boolean_count++;
        if (same_url_path) boolean_features += 1.0; boolean_count++;
        if (same_url_filename) boolean_features += 1.0; boolean_count++;
        if (same_referer) boolean_features += 1.0; boolean_count++;
        if (same_response_type) boolean_features += 1.0; boolean_count++;
        if (same_server_header) boolean_features += 1.0; boolean_count++;
        if (same_location_header) boolean_features += 1.0; boolean_count++;
        if (same_content_type) boolean_features += 1.0; boolean_count++;
        
        double total = boolean_features + url_params_similarity + 
                      content_length_similarity + response_headers_similarity;
        
        return total / (boolean_count + 3);
    }
};

// Dialog alignment result
struct DialogAlignment {
    struct AlignedPair {
        RequestResponsePair rrp1;
        RequestResponsePair rrp2;
        double similarity;
        
        enum class Status {
            IDENTICAL,   // similarity = 1.0
            CHANGED,     // similarity >= 0.7
            NEW          // similarity < 0.7
        } status;
    };
    
    std::vector<AlignedPair> aligned_pairs;
    double overall_similarity = 0.0;
};

// HTTP message parser for extracting features
class HTTPMessageParser {
public:
    struct HTTPRequest {
        std::string method;
        std::string url;
        std::string path;
        std::string filename;
        std::map<std::string, std::string> url_params;
        std::map<std::string, std::string> headers;
    };
    
    struct HTTPResponse {
        int status_code = 0;
        std::string status_text;
        std::map<std::string, std::string> headers;
        size_t content_length = 0;
    };
    
    static HTTPRequest parseRequest(std::shared_ptr<MessageNode> message);
    static HTTPResponse parseResponse(std::shared_ptr<MessageNode> message);

private:
    static std::map<std::string, std::string> parseHeaders(const std::string& raw_data);
    static std::map<std::string, std::string> parseURLParams(const std::string& url);
    static std::string extractFilename(const std::string& path);
};

// Main dialog diffing class
class DialogDiffer {
public:
    DialogDiffer(double similarity_threshold = 0.7) 
        : similarity_threshold_(similarity_threshold) {}
    
    // Main diffing functions
    DialogAlignment alignDialogs(std::shared_ptr<NetworkDialogTree> dialog1,
                                std::shared_ptr<NetworkDialogTree> dialog2);
    
    double computeDialogSimilarity(std::shared_ptr<NetworkDialogTree> dialog1,
                                  std::shared_ptr<NetworkDialogTree> dialog2);
    
    // RRP similarity computation
    double computeRRPSimilarity(const RequestResponsePair& rrp1,
                               const RequestResponsePair& rrp2);

private:
    double similarity_threshold_;
    
    // Extract RRPs from dialog tree
    std::vector<RequestResponsePair> extractRRPs(std::shared_ptr<NetworkDialogTree> dialog);
    
    // Compute similarity features
    SimilarityFeatures computeSimilarityFeatures(const RequestResponsePair& rrp1,
                                                const RequestResponsePair& rrp2);
    
    // Hungarian algorithm for optimal alignment
    std::vector<std::pair<int, int>> hungarianAlignment(
        const std::vector<std::vector<double>>& similarity_matrix);
    
    // Utility functions
    double jaccardIndex(const std::set<std::string>& set1, const std::set<std::string>& set2);
    double jaccardIndex(const std::map<std::string, std::string>& map1,
                       const std::map<std::string, std::string>& map2);
};

// Dialog clustering for behavioral analysis
class DialogClusterer {
public:
    struct Cluster {
        std::vector<std::shared_ptr<NetworkDialogTree>> dialogs;
        std::shared_ptr<NetworkDialogTree> centroid;
        double avg_intra_similarity = 0.0;
    };
    
    DialogClusterer(double similarity_threshold = 0.8, 
                   DialogDiffer differ = DialogDiffer())
        : similarity_threshold_(similarity_threshold), differ_(differ) {}
    
    // Clustering algorithms
    std::vector<Cluster> aggressiveClustering(
        const std::vector<std::shared_ptr<NetworkDialogTree>>& dialogs);
    
    std::vector<Cluster> pamClustering(
        const std::vector<std::shared_ptr<NetworkDialogTree>>& dialogs, int k);
    
    // Cluster quality metrics
    double silhouetteWidth(const std::vector<Cluster>& clusters);
    void printClusteringStats(const std::vector<Cluster>& clusters);

private:
    double similarity_threshold_;
    DialogDiffer differ_;
    
    std::shared_ptr<NetworkDialogTree> computeCentroid(const std::vector<std::shared_ptr<NetworkDialogTree>>& dialogs);
};

// Implementation of key methods
inline DialogAlignment DialogDiffer::alignDialogs(
    std::shared_ptr<NetworkDialogTree> dialog1,
    std::shared_ptr<NetworkDialogTree> dialog2) {
    
    auto rrps1 = extractRRPs(dialog1);
    auto rrps2 = extractRRPs(dialog2);
    
    Logger::get()->debug("Aligning dialogs with {} and {} RRPs", rrps1.size(), rrps2.size());
    
    // Build similarity matrix
    size_t max_size = std::max(rrps1.size(), rrps2.size());
    std::vector<std::vector<double>> similarity_matrix(max_size, std::vector<double>(max_size, 0.0));
    
    // Pad smaller dialog with dummy RRPs
    while (rrps1.size() < max_size) {
        rrps1.emplace_back(); // dummy RRP
    }
    while (rrps2.size() < max_size) {
        rrps2.emplace_back(); // dummy RRP
    }
    
    // Compute similarity matrix
    for (size_t i = 0; i < max_size; i++) {
        for (size_t j = 0; j < max_size; j++) {
            similarity_matrix[i][j] = computeRRPSimilarity(rrps1[i], rrps2[j]);
        }
    }
    
    // Find optimal alignment using Hungarian algorithm
    auto alignment = hungarianAlignment(similarity_matrix);
    
    // Build result
    DialogAlignment result;
    double total_similarity = 0.0;
    
    for (const auto& [i, j] : alignment) {
        DialogAlignment::AlignedPair pair;
        pair.rrp1 = rrps1[i];
        pair.rrp2 = rrps2[j];
        pair.similarity = similarity_matrix[i][j];
        
        if (pair.similarity >= 1.0) {
            pair.status = DialogAlignment::AlignedPair::Status::IDENTICAL;
        } else if (pair.similarity >= similarity_threshold_) {
            pair.status = DialogAlignment::AlignedPair::Status::CHANGED;
        } else {
            pair.status = DialogAlignment::AlignedPair::Status::NEW;
        }
        
        result.aligned_pairs.push_back(pair);
        total_similarity += pair.similarity;
    }
    
    result.overall_similarity = total_similarity / max_size;
    
    Logger::get()->debug("Dialog alignment completed with similarity {:.3f}", 
                        result.overall_similarity);
    return result;
}

inline double DialogDiffer::computeRRPSimilarity(const RequestResponsePair& rrp1,
                                               const RequestResponsePair& rrp2) {
    // Handle dummy RRPs (null requests/responses)
    if (!rrp1.request || !rrp2.request) {
        return 0.0;
    }
    
    auto features = computeSimilarityFeatures(rrp1, rrp2);
    return features.computeOverallSimilarity();
}

inline SimilarityFeatures DialogDiffer::computeSimilarityFeatures(
    const RequestResponsePair& rrp1, const RequestResponsePair& rrp2) {
    
    SimilarityFeatures features;
    
    if (!rrp1.request || !rrp2.request) {
        return features; // All features remain false/0.0
    }
    
    // Parse HTTP messages
    auto req1 = HTTPMessageParser::parseRequest(rrp1.request);
    auto req2 = HTTPMessageParser::parseRequest(rrp2.request);
    
    // Boolean features
    features.same_request_type = (req1.method == req2.method);
    features.same_url_path = (req1.path == req2.path);
    features.same_url_filename = (req1.filename == req2.filename);
    
    // Referer comparison
    auto referer1 = req1.headers.find("Referer");
    auto referer2 = req2.headers.find("Referer");
    features.same_referer = (referer1 != req1.headers.end() && 
                            referer2 != req2.headers.end() &&
                            referer1->second == referer2->second);
    
    // URL parameters similarity (Jaccard index)
    features.url_params_similarity = jaccardIndex(req1.url_params, req2.url_params);
    
    // Response features (if responses exist)
    if (rrp1.response && rrp2.response) {
        auto resp1 = HTTPMessageParser::parseResponse(rrp1.response);
        auto resp2 = HTTPMessageParser::parseResponse(rrp2.response);
        
        features.same_response_type = (resp1.status_code == resp2.status_code);
        
        // Header comparisons
        auto server1 = resp1.headers.find("Server");
        auto server2 = resp2.headers.find("Server");
        features.same_server_header = (server1 != resp1.headers.end() && 
                                      server2 != resp2.headers.end() &&
                                      server1->second == server2->second);
        
        auto location1 = resp1.headers.find("Location");
        auto location2 = resp2.headers.find("Location");
        features.same_location_header = (location1 != resp1.headers.end() && 
                                        location2 != resp2.headers.end() &&
                                        location1->second == location2->second);
        
        auto content_type1 = resp1.headers.find("Content-Type");
        auto content_type2 = resp2.headers.find("Content-Type");
        features.same_content_type = (content_type1 != resp1.headers.end() && 
                                     content_type2 != resp2.headers.end() &&
                                     content_type1->second == content_type2->second);
        
        // Content length similarity
        if (resp1.content_length > 0 && resp2.content_length > 0) {
            size_t max_len = std::max(resp1.content_length, resp2.content_length);
            size_t min_len = std::min(resp1.content_length, resp2.content_length);
            features.content_length_similarity = static_cast<double>(min_len) / max_len;
        }
        
        // Response headers similarity (Jaccard index)
        features.response_headers_similarity = jaccardIndex(resp1.headers, resp2.headers);
    }
    
    return features;
}

inline double DialogDiffer::jaccardIndex(const std::set<std::string>& set1, 
                                       const std::set<std::string>& set2) {
    if (set1.empty() && set2.empty()) return 1.0;
    
    std::set<std::string> intersection;
    std::set_intersection(set1.begin(), set1.end(),
                         set2.begin(), set2.end(),
                         std::inserter(intersection, intersection.begin()));
    
    std::set<std::string> union_set;
    std::set_union(set1.begin(), set1.end(),
                   set2.begin(), set2.end(),
                   std::inserter(union_set, union_set.begin()));
    
    return static_cast<double>(intersection.size()) / union_set.size();
}

inline double DialogDiffer::jaccardIndex(const std::map<std::string, std::string>& map1,
                                       const std::map<std::string, std::string>& map2) {
    std::set<std::string> keys1, keys2;
    for (const auto& pair : map1) keys1.insert(pair.first);
    for (const auto& pair : map2) keys2.insert(pair.first);
    
    return jaccardIndex(keys1, keys2);
}

} // namespace Dialog
} // namespace Firewall