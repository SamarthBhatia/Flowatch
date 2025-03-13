#include "../../include/monitor/process_monitor.hpp"
#include "../../include/utils/logger.hpp"

#include <chrono>
#include <fstream>
#include <stdexcept>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>

namespace Firewall{
    ProcessMonitor& ProcessMonitor::getInstance(){
        static ProcessMonitor instance;
        return instance;
    }

    ProcessMonitor::ProcessMonitor() : running_(false){}

    ProcessMonitor::~ProcessMonitor(){
        stop();
    }

    void ProcessMonitor::start(){
        if (running_){
            return;
        }
        running_=true;
        monitor_thread_=std::thread(&ProcessMonitor::refreshConnections, this);
        Logger::get()->info("Process monitor started");
    }

    void ProcessMonitor::stop(){
        if (!running_){
            return;
        }
        running_=false;
        if (monitor_thread_.joinable()){
            monitor_thread_.join();
        }
        Logger::get()->info("Process monitor stopped");
    }

    std::string ProcessMonitor::getProcessForConnection(const std::string& local_ip,int local_port, const std::string& remote_ip, int remote_port){
        std::lock_guard<std::mutex> lock(mutex_);
        auto key=std::make_tuple(local_ip,remote_ip, local_port, remote_port);
        auto it=connections_.find(key);
        if (it != connections_.end()){
            return it->second;
        }
        return "unknown";
    }

    std::string ProcessMonitor::getExecutablePath(int pid){
        std::string path="/proc/" + std::to_string(pid) + "/exe";
        char buffer[PATH_MAX];
        ssize_t len=readlink(path.c_str(),buffer,sizeof(buffer)-1);
        if (len != -1){
            buffer[len]='\0';
            return std::string(buffer);
        }
        return "unknown";
    }

    void ProcessMonitor::refreshConnections() {
        while (running_) {
            try {
                std::map<ConnectionKey, std::string> new_connections;
                
                std::ifstream tcp_file("/proc/net/tcp");
                std::string line;

                std::getline(tcp_file, line); 
                
                while (std::getline(tcp_file, line)) {
    
                    std::istringstream iss(line);
                    std::string sl, local_addr, rem_addr, state, uid_str, inode_str;
                    iss >> sl >> local_addr >> rem_addr >> state;
                    
                    std::string skip;
                    for (int i = 0; i < 5; i++) {
                        iss >> skip;
                    }
                    
                    iss >> uid_str >> skip >> inode_str;
                    
                    
                    uint32_t local_ip, remote_ip;
                    uint16_t local_port, remote_port;
                    
                 
                    sscanf(local_addr.c_str(), "%x:%hx", &local_ip, &local_port);
                    sscanf(rem_addr.c_str(), "%x:%hx", &remote_ip, &remote_port);
                    
            
                    struct in_addr local_in, remote_in;
                    local_in.s_addr = ntohl(local_ip);
                    remote_in.s_addr = ntohl(remote_ip);
                    
                    std::string local_ip_str = inet_ntoa(local_in);
                    std::string remote_ip_str = inet_ntoa(remote_in);
                    
                  
                    std::string process_name = "unknown";
                    uint64_t inode = std::stoull(inode_str);
                    
                    
                    DIR* proc_dir = opendir("/proc");
                    if (proc_dir) {
                        struct dirent* entry;
                        while ((entry = readdir(proc_dir)) != nullptr) {
                            
                            if (!isdigit(entry->d_name[0])) {
                                continue;
                            }
                            
                            int pid = std::stoi(entry->d_name);
                            std::string fd_dir_path = "/proc/" + std::to_string(pid) + "/fd";
                            DIR* fd_dir = opendir(fd_dir_path.c_str());
                            
                            if (fd_dir) {
                                struct dirent* fd_entry;
                                while ((fd_entry = readdir(fd_dir)) != nullptr) {
                                    std::string fd_path = fd_dir_path + "/" + fd_entry->d_name;
                                    char link_path[PATH_MAX];
                                    ssize_t len = readlink(fd_path.c_str(), link_path, sizeof(link_path) - 1);
                                    
                                    if (len != -1) {
                                        link_path[len] = '\0';
                                        std::string socket_link(link_path);
                                        
                                        
                                        if (socket_link.find("socket:[" + inode_str + "]") != std::string::npos) {
                                            process_name = getExecutablePath(pid);
                                            break;
                                        }
                                    }
                                }
                                closedir(fd_dir);
                            }
                            
                            if (process_name != "unknown") {
                                break;
                            }
                        }
                        closedir(proc_dir);
                    }
               
                    auto key = std::make_tuple(local_ip_str, remote_ip_str, local_port, remote_port);
                    new_connections[key] = process_name;
                }
                
               
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    connections_ = std::move(new_connections);
                }
                
            } catch (const std::exception& e) {
                Logger::get()->error("Error refreshing process connections: {}", e.what());
            }
            
            
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }


}