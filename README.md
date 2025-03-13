# Firewall

A robust, intelligent network firewall for Linux systems with application behavior analysis, geographical filtering, and traffic monitoring capabilities.

## Features

- **Application-Aware Filtering**: Detect and control network traffic by application
- **Behavior Analysis**: Learn normal application behavior patterns and detect anomalies
- **GeoIP Filtering**: Block connections to/from specific countries
- **Traffic Monitoring**: Visualize and analyze your network traffic
- **Comprehensive Rule System**: Create detailed rules based on multiple parameters
- **Command Line Interface**: Simple, powerful CLI for control and configuration

## Requirements

- CMake 3.15+
- libpcap-dev
- libspdlog-dev
- libssl-dev
- nlohmann-json-dev

## Installation

### From Source

```bash
# Install dependencies
sudo apt install build-essential cmake libpcap-dev libspdlog-dev libssl-dev nlohmann-json3-dev

# Clone repository
git clone https://github.com/yourusername/firewall.git
cd firewall

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)

# Install
sudo make install
```

### Configuration

The firewall uses a JSON configuration file located at `~/.config/firewall/config.json`. A default configuration is installed during setup, but you can modify it to suit your needs:

```json
{
  "default_policy": "allow",
  "rules_file": "~/.config/firewall/rules.json",
  "log_level": "info",
  "behavior_profiles": "~/.config/firewall/behavior_profiles.json",
  "behavior_learning_period": 60,
  "enable_behavior_monitoring": true,
  "enable_geoip_filtering": true
}
```

## Usage

### Basic Commands

```bash
# Start the firewall (requires root privileges)
sudo firewall start

# Add a rule to allow an application
sudo firewall add-rule firefox allow * 0

# Block a specific IP address for all applications
sudo firewall add-rule * block 192.168.1.100 0

# Block connections to a specific country
sudo firewall block-country CN

# List all current rules
sudo firewall list-rules

# Check firewall status
sudo firewall status
```

### Interactive Mode

When running `firewall start`, the program enters interactive mode with a command prompt where you can enter commands directly:

```
firewall> add-rule chrome allow google.com 443
firewall> list-rules
firewall> status
firewall> exit
```

### Rule Syntax

Rule Format: `<application> <action> <address> <port>`

- **application**: Application name or path, use "*" for all applications
- **action**: Either "allow" or "block"
- **address**: IP address, domain name, or "*" for all addresses
- **port**: Port number, or 0 for all ports

## How It Works

Firewall uses `libpcap` to monitor network traffic and identifies processes making connections using the `/proc` filesystem. It builds behavior profiles for applications by learning their normal connection patterns and can alert or block abnormal behavior.

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
