#include "../../include/utils/logger.hpp"
#include <spdlog/sinks/stdout_color_sinks.h>

namespace Firewall {

    std::shared_ptr<spdlog::logger> Logger::logger_ = nullptr;
    
    void Logger::init() {
        if (!logger_) {
            logger_ = spdlog::stdout_color_mt("firewall");
            logger_->set_level(spdlog::level::debug);
        }
    }
    
    std::shared_ptr<spdlog::logger> Logger::get() {
        if (!logger_) {
            init();
        }
        return logger_;
    }
    
    }