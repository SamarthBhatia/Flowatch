

#include <iostream>
#include "../include/cli/interface.hpp"
#include "../include/monitor/connection_monitor.hpp"
#include "../include/utils/logger.hpp"
#include "../include/utils/config.hpp"

using namespace Firewall;  // Add this to use the Firewall namespace

int main(int argc, char* argv[]) {  // Fixed typo in argv
    try {
        std::cout << "Debug: Initializing logger..." << std::endl;
        Firewall::Logger::init();  // Explicitly use Firewall namespace
        
        std::cout << "Debug: Creating CLI interface..." << std::endl;
        Firewall::CLI::Interface cli(argc, argv);  // Explicitly use Firewall namespace
        
        std::cout << "Debug: Running CLI interface..." << std::endl;
        return cli.run();
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Fatal error: Unknown exception" << std::endl;
        return 1;
    }
}