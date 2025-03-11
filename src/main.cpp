#include <iostream>
#include "../include/cli/interface.hpp"
#include "../include/monitor/connection_monitor.hpp"
#include "../include/utils/logger.hpp"

using namespace Firewall;  // Add this to use the Firewall namespace

int main(int argc, char* argv[]) {  // Fixed typo in argv
    try {
        Firewall::Logger::init();  // Explicitly use Firewall namespace
        Firewall::CLI::Interface cli(argc, argv);  // Explicitly use Firewall namespace
        return cli.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}