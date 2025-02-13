#pragma once

#include <spdlog/spdlog.h>

namespace Firewall{
    class Logger{
        public:
            static void init();
            static std::shared_ptr<spdlog::logger> get();
        private:
            static std::shared_ptr<spdlog::logger> logger_;
    };
}