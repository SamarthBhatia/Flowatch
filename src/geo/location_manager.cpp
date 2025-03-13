#include "../../include/geo/location_manager.hpp"
#include "../../include/utils/logger.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <arpa/inet.h>

namespace Firewall {
namespace Geo {

LocationManager& LocationManager::getInstance() {
    static LocationManager instance;
    return instance;
}

LocationManager::LocationManager() : database_loaded_(false) {
}

bool LocationManager::loadDatabase(const std::string& filename) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    try {
        std::ifstream file(filename);
        if (!file.is_open()) {
            Logger::get()->error("Failed to open GeoIP database: {}", filename);
            return false;
        }
        
        // Clear existing data
        ip_ranges_.clear();
        
        std::string line;
        // Skip header if it exists
        std::getline(file, line);
        
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string start_ip_str, end_ip_str, country_code;
            
            // Parse CSV line (format: start_ip,end_ip,country_code,...)
            if (!std::getline(iss, start_ip_str, ',') || 
                !std::getline(iss, end_ip_str, ',') || 
                !std::getline(iss, country_code, ',')) {
                continue;
            }
            
            // Convert IPs to integers
            IPRange range;
            try {
                range.start_ip = ipToUint(start_ip_str);
                range.end_ip = ipToUint(end_ip_str);
                range.country_code = country_code;
                
                ip_ranges_.push_back(range);
            } catch (const std::exception& e) {
                Logger::get()->warn("Failed to parse IP range: {} - {}", start_ip_str, end_ip_str);
                continue;
            }
        }
        
        // Sort by start_ip for binary search
        std::sort(ip_ranges_.begin(), ip_ranges_.end(), 
            [](const IPRange& a, const IPRange& b) {
                return a.start_ip < b.start_ip;
            });
        
        database_loaded_ = true;
        Logger::get()->info("Loaded {} IP ranges from GeoIP database", ip_ranges_.size());
        return true;
    } catch (const std::exception& e) {
        Logger::get()->error("Error loading GeoIP database: {}", e.what());
        return false;
    }
}

std::string LocationManager::getCountryCode(const std::string& ip_address) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!database_loaded_) {
        Logger::get()->warn("GeoIP database not loaded");
        return "UNKNOWN";
    }
    
    try {
        uint32_t ip = ipToUint(ip_address);
        
        // Binary search for the range containing this IP
        auto it = std::lower_bound(ip_ranges_.begin(), ip_ranges_.end(), IPRange{ip, 0, ""},
            [](const IPRange& range, const IPRange& value) {
                return range.start_ip < value.start_ip;
            });
        
        // Check if we found a range that might contain our IP
        if (it != ip_ranges_.begin()) {
            --it; // Go back one range since lower_bound gives us the first range with start > ip
        }
        
        // Check if IP is within this range
        if (it != ip_ranges_.end() && ip >= it->start_ip && ip <= it->end_ip) {
            return it->country_code;
        }
        
        return "UNKNOWN";
    } catch (const std::exception& e) {
        Logger::get()->error("Error getting country code for IP {}: {}", ip_address, e.what());
        return "UNKNOWN";
    }
}

bool LocationManager::isInCountry(const std::string& ip_address, const std::string& country_code) {
    return getCountryCode(ip_address) == country_code;
}

bool LocationManager::isInCountries(const std::string& ip_address, const std::vector<std::string>& country_codes) {
    std::string cc = getCountryCode(ip_address);
    return std::find(country_codes.begin(), country_codes.end(), cc) != country_codes.end();
}

uint32_t LocationManager::ipToUint(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        throw std::runtime_error("Invalid IP address format");
    }
    return ntohl(addr.s_addr);
}

} // namespace Geo
} // namespace Firewall
