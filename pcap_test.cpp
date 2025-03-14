#include <iostream>
#include <pcap.h>
#include <string>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int count = 0;
    std::cout << "Packet #" << ++count << " received, length: " << pkthdr->len << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    
    // Find all available devices
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }
    
    // Print available devices
    std::cout << "Available devices:" << std::endl;
    pcap_if_t *d;
    int i = 0;
    for(d = devices; d; d = d->next) {
        std::cout << i++ << ": " << d->name;
        if (d->description)
            std::cout << " (" << d->description << ")";
        std::cout << std::endl;
    }
    
    if (!devices) {
        std::cerr << "No devices available" << std::endl;
        return 1;
    }
    
    // Ask user which device to use
    std::cout << "Enter device number to use: ";
    int dev_num;
    std::cin >> dev_num;
    
    // Find the selected device
    d = devices;
    for(i = 0; i < dev_num && d; i++) {
        d = d->next;
    }
    
    if (!d) {
        std::cerr << "Invalid device number" << std::endl;
        pcap_freealldevs(devices);
        return 1;
    }
    
    std::string device_name = d->name;
    
    // Open the device
    std::cout << "Opening device: " << device_name << std::endl;
    pcap_t *handle = pcap_open_live(device_name.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    // Done with the device list
    pcap_freealldevs(devices);
    
    if (handle == nullptr) {
        std::cerr << "Failed to open device: " << errbuf << std::endl;
        return 1;
    }
    
    // Print datalink type
    int linktype = pcap_datalink(handle);
    std::cout << "Device link type: " << linktype;
    switch(linktype) {
        case DLT_EN10MB:
            std::cout << " (Ethernet)";
            break;
        case DLT_IEEE802_11:
            std::cout << " (Wireless)";
            break;
        case DLT_NULL:
            std::cout << " (Loopback)";
            break;
        case DLT_LINUX_SLL:
            std::cout << " (Linux cooked)";
            break;
        default:
            std::cout << " (Other)";
    }
    std::cout << std::endl;
    
    // Set a simple filter to only capture IP packets
    struct bpf_program fp;
    char filter_exp[] = "ip";
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Failed to compile filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Failed to set filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }
    
    std::cout << "Starting packet capture (press Ctrl+C to stop)..." << std::endl;
    
    // Start packet capture loop
    pcap_loop(handle, 0, packet_handler, nullptr);
    
    pcap_close(handle);
    return 0;
}