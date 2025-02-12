#include <iostream>
#include "cli/interface.hpp"
#include "monitor/connection_monitor.hpp"
#include "utils/logger.hpp"

int main(int argc, char* arv[]){
    try{
        Logger::init();
        CLI::Interface cli(argc,argv);
        return cli.run();
    } catch (const std::exception& e){
        std::cerr<<"Error: "<<e.what()<<std::endl;
        return 1;
    }
}