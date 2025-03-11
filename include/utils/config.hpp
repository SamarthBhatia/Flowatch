#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace Firewall{
    class Config{
        public:
            static Config& getInstance();

            bool load(const std::string& filename);
            bool save(const std::string& filename);

            template<typename T>
            T get(const std::string& key, const T& defaultValue) const;
            
            template<typename T>
            void set(const std::string& key, const T& value);
        
        private:
            Config() = default;
            nlohmann::json config_;
    };
}