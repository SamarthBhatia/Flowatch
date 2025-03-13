#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <mutex>

namespace Firewall {
namespace Geo {

struct IPRange {
    uint32_t start_ip;
    uint32_t end_ip;
    std::string country_code;
};

class LocationManager {
public:
    static LocationManager& getInstance();
    
    // Load GeoIP database from MaxMind CSV file
    bool loadDatabase(const std::string& filename);
    
    // Get country code for an IP address
    std::string getCountryCode(const std::string& ip_address);
    
    // Check if IP is in a specific country
    bool isInCountry(const std::string& ip_address, const std::string& country_code);
    
    // Check if IP is in any of the given countries
    bool isInCountries(const std::string& ip_address, const std::vector<std::string>& country_codes);
    
private:
    LocationManager();
    ~LocationManager() = default;
    
    // Convert IP string to uint32_t
    uint32_t ipToUint(const std::string& ip);
    
    std::vector<IPRange> ip_ranges_;
    std::mutex mutex_;
    bool database_loaded_;
};

} // namespace Geo
} // namespace Firewall
