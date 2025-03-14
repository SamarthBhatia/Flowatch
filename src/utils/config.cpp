#include "../../include/utils/config.hpp"
#include "../../include/utils/logger.hpp"
#include <fstream>
#include <iostream>

namespace Firewall{

    Config& Config::getInstance(){
        static Config instance;
        return instance;
    }

    bool Config::load(const std::string& filename){
        try{
            std::ifstream file(filename);
            if (!file.is_open()){
                Logger::get() -> warn("Config file not found: {}", filename);
                return false;
            }

            file >> config_;
            Logger::get() -> info("Config loaded from: {}",filename);
            return true;
        } catch (const std::exception& e){
            Logger::get() -> error("Error loading config: {}",e.what());
            return false;
        }
    }

    bool Config::save(const std::string& filename){
        try{
            std::ofstream file(filename);
            if (!file.is_open()){
                Logger::get() -> error("Failed to open config file for writing: {}", filename);
                return false;
            }
            file << std::setw(4) << config_ <<std::endl;
            Logger::get() -> info("Config saved to: {}",filename);
            return true;
        } catch (const std::exception& e){
            Logger::get() -> error("Error saving config: {}", e.what());
            return false;
        }
    }

    // template<>
    // std::string Config::get<std::string>(const std::string& key, const std::string& defaultValue) const{
    //     try{
    //         if (config_.contains(key)){
    //             return config_[key].get<std::string>();
    //         } 
    //     }catch (const std::exception& e){
    //         Logger::get() -> warn("Error getting config value for {}: {}",key, e.what());
    //     }
    //     return defaultValue;
    // }
    template<>
    std::string Config::get<std::string>(const std::string& key, const std::string& defaultValue) const {
        try {
            if (config_.contains(key)) {
                return config_[key].get<std::string>();
            }
        } catch (const std::exception& e) {
            Logger::get()->warn("Error getting string config value for {}: {}", key, e.what());
        }
        return defaultValue;
    }

    template<>
    std::vector<std::string> Config::get<std::vector<std::string>>(
            const std::string& key, 
            const std::vector<std::string>& defaultValue) const {
        try {
            if (config_.contains(key)) {
                return config_[key].get<std::vector<std::string>>();
            }
        } catch (const std::exception& e) {
            Logger::get()->warn("Error getting vector config value for {}: {}", key, e.what());
        }
        return defaultValue;
    }

    template<>
    int Config::get<int>(const std::string& key, const int& defaultValue) const{
        try{
            if (config_.contains(key)){
                return config_[key].get<int>();
            } 
        }catch (const std::exception& e){
            Logger::get()->warn("Error getting config value for {}: {}",key,e.what());
        }
        return defaultValue;
    }

    template<>
    bool Config::get<bool>(const std::string &key, const bool& defaultValue) const{
        try{
            if (config_.contains(key)){
                return config_[key].get<bool>();
            } 
        }catch (const std::exception& e){
            Logger::get()->warn("Error getting config value for {}: {}", key, e.what());
        }
        return defaultValue;
    }

    template<>
    void Config::set<std::string>(const std::string& key, const std::string& value){
        config_[key]=value;
    }

    template<>
    void Config::set<int>(const std::string& key, const int& value){
        config_[key]=value;
    }

    template<>
    void Config::set<bool>(const std::string& key, const bool &value){
        config_[key]=value;
    }

    template<>
    void Config::set<std::vector<std::string>>(const std::string& key,const std::vector<std::string> &value){
        config_[key]=value;
    }

    std::string Config::getString(const std::string& key, const std::string& defaultValue) const {
        try {
            if (config_.contains(key)) {
                return config_[key].get<std::string>();
            }
        } catch (const std::exception& e) {
            Logger::get()->warn("Error getting string config value for {}: {}", key, e.what());
        }
        return defaultValue;
    }

    std::vector<std::string> Config::getStringVector(const std::string& key, const std::vector<std::string>& defaultValue) const {
        try {
            if (config_.contains(key)) {
                return config_[key].get<std::vector<std::string>>();
            }
        } catch (const std::exception& e) {
            Logger::get()->warn("Error getting vector config value for {}: {}", key, e.what());
        }
        return defaultValue;
    }

}