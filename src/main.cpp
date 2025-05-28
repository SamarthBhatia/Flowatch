

// #include <iostream>
// #include "../include/cli/interface.hpp"
// #include "../include/monitor/connection_monitor.hpp"
// #include "../include/utils/logger.hpp"
// #include "../include/utils/config.hpp"

// using namespace Firewall;  // Add this to use the Firewall namespace

// int main(int argc, char* argv[]) {  // Fixed typo in argv
//     try {
//         std::cout << "Debug: Initializing logger..." << std::endl;
//         Firewall::Logger::init();  // Explicitly use Firewall namespace
        
//         std::cout << "Debug: Creating CLI interface..." << std::endl;
//         Firewall::CLI::Interface cli(argc, argv);  // Explicitly use Firewall namespace
        
//         std::cout << "Debug: Running CLI interface..." << std::endl;
//         return cli.run();
//     } catch (const std::exception& e) {
//         std::cerr << "Fatal error: " << e.what() << std::endl;
//         return 1;
//     } catch (...) {
//         std::cerr << "Fatal error: Unknown exception" << std::endl;
//         return 1;
//     }
// }

#include <iostream>
#include "../include/cli/interface.hpp"
#include "../include/dialog/dialog_applications.hpp"
#include "../include/monitor/connection_monitor.hpp"
#include "../include/utils/logger.hpp"
#include "../include/utils/config.hpp"

using namespace Firewall;

int main(int argc, char* argv[]) {
    try {
        std::cout << "Debug: Initializing logger..." << std::endl;
        Firewall::Logger::init();
        
        std::cout << "Debug: Creating CLI interface..." << std::endl;
        
        // Check if this is a dialog analysis command
        if (argc >= 2) {
            std::string command = argv[1];
            if (command == "minimize-dialog" || 
                command == "diff-dialogs" || 
                command == "test-cookies" ||
                command == "start-milker" ||
                command == "cluster-dialogs") {
                
                // Use the enhanced dialog analysis CLI
                Firewall::Dialog::DialogAnalysisCLI cli(argc, argv);
                return cli.run();
            }
        }
        
        // Use the standard CLI for other commands
        Firewall::CLI::Interface cli(argc, argv);
        return cli.run();
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Fatal error: Unknown exception" << std::endl;
        return 1;
    }
}