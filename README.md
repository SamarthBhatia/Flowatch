# Flowatch

A robust, intelligent network firewall for Linux systems with application behavior analysis, geographical filtering, and traffic monitoring capabilities.

## 🚀 Features
- ✅ **Application-Aware Filtering**: Detect and control network traffic by application  
- ✅ **Behavior Analysis**: Learn normal application behavior patterns and detect anomalies  
- ✅ **GeoIP Filtering**: Block connections to/from specific countries  
- ✅ **Traffic Monitoring**: Visualize and analyze your network traffic  
- ✅ **Comprehensive Rule System**: Create detailed rules based on multiple parameters  
- ✅ **Command Line Interface**: Simple, powerful CLI for control and configuration  
- ✅ **Complete Dialog Tree System**: Hierarchical network conversation representation  
- ✅ **Advanced Dialog Diffing**: Similarity analysis with 11+ feature types  
- ✅ **Multi-Level Minimization**: 3-stage delta debugging (connections → messages → fields)

---

## 🛠️ Requirements
- **CMake** 3.15+
- **libpcap-dev**
- **libspdlog-dev**
- **libssl-dev**
- **nlohmann-json-dev**

---

## 🛠️ Installation
### 🔹 From Source
```bash
# Install dependencies
sudo apt install build-essential cmake libpcap-dev libspdlog-dev libssl-dev nlohmann-json3-dev

# Clone repository
git clone https://github.com/SamarthBhatia/Flowatch.git
cd Flowatch

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)

# Install
sudo make install

# Or instead of manually making a build directory,
./build.sh
```

---

### ⚙️ Configuration

Before starting the flowatch, **initialize the configuration file** by running:

```bash
cd flowatch (if not in root directory)
chmod +x generate_json.sh
./generate_json.sh
```

This script will creeate a **default** `config.json` inside: 
```bash
flowatch/config/firewall/config.json
```

You can modify `config.json` as needed:

```json
{
    "default_policy": "allow",
    "rules_file": "config/firewall/rules.json",
    "log_level": "info",
    "behavior_profiles": "config/firewall/behavior_profiles.json",
    "behavior_learning_period": 60,
    "enable_behavior_monitoring": true,
    "enable_geoip_filtering": true,
    "prompt_for_unknown_connections": true,
    "blocked_count": 0,
    "interface": "en0"
}
```

## 🚀 Usage

### Basic Commands

```bash
# Start the firewall (requires root privileges)
sudo firewall start

# Add a rule to allow an application
add-rule firefox allow * 0

# Block a specific IP address for all applications
add-rule * block 192.168.1.100 0

# Block connections to a specific country
block-country CN

# List all current rules
list-rules

# Check firewall status
status
```

### Dialog Testing Commands

```bash
# Build your system
./build.sh

# Basic integration test
./test_integration.sh

# Advanced dialog testing suite
chmod +x dialog_testing_suite.sh
./dialog_testing_suite.sh

# Algorithm validation (precision testing)
chmod +x algorithm_validation_tests.sh
./algorithm_validation_tests.sh

# Real-world concepts demonstration
chmod +x dialog_concept_demo.sh
./dialog_concept_demo.sh

# Interactive exploration
./dialog_concept_demo.sh --interactive
```
### 📌 Interactive Mode

When running `firewall start`, the program enters interactive mode with a command prompt where you can enter commands directly:

```
firewall> add-rule chrome allow google.com 443
firewall> list-rules
firewall> status
firewall> exit
```

### 📜 Rule Syntax

Rule Format: `<application> <action> <address> <port>`

- `application`: Application name or path, use "*" for all applications
- `action`: Either "allow" or "block"
- `address`: IP address, domain name, or "*" for all addresses
- `port`: Port number, or 0 for all ports

## ⚙️ How It Works

Flowatch uses `libpcap` to monitor network traffic and identifies processes making connections using the `/proc` filesystem. It builds behavior profiles for applications by learning their normal connection patterns and can alert or block abnormal behavior.

The GeoIP functionality allows filtering traffic by country of origin, and the rule system provides flexible control over which applications can access the network.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [libpcap](https://www.tcpdump.org/)
- [spdlog](https://github.com/gabime/spdlog)
- [nlohmann/json](https://github.com/nlohmann/json)
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geoip2/geolite2/) for GeoIP database support

This project builds upon techniques introduced in:

> **Network Dialog Minimization and Network Dialog Diffing:  
> Two Novel Primitives for Network Security Applications**  
> M. Zubair Rafique, Juan Caballero, Christophe Huygens & Wouter Joosen  
> IMDEA Software Institute Technical Report TR-IMDEA-SW-2014-001, March 2014  
> [https://software.imdea.org/~juanca/papers/TR-IMDEA-SW-2014-001.pdf](https://software.imdea.org/~juanca/papers/TR-IMDEA-SW-2014-001.pdf)
