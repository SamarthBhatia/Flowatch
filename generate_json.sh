 #!/bin/bash

# Get the absolute path of the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Traverse up to find the 'flowatch' directory
PROJECT_DIR="$SCRIPT_DIR"
while [[ "$PROJECT_DIR" != "/" && "$(basename "$PROJECT_DIR")" != "flowatch" ]]; do
    PROJECT_DIR="$(dirname "$PROJECT_DIR")"
done

# Ensure we found 'flowatch' and not reached the root
if [[ "$(basename "$PROJECT_DIR")" != "flowatch" ]]; then
    echo "Error: Could not detect 'flowatch' project directory. Ensure the script is inside the project."
    exit 1
fi

# Define config directory and file path
CONFIG_DIR="$PROJECT_DIR/config/firewall"
CONFIG_FILE="$CONFIG_DIR/config.json"

# Create config directory if not exists
mkdir -p "$CONFIG_DIR"

# Only create if it doesn't exist or is empty
if [ ! -s "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" << EOF
{
    "default_policy": "allow",
    "rules_file": "$CONFIG_DIR/rules.json",
    "log_level": "info",
    "behavior_profiles": "$CONFIG_DIR/behavior_profiles.json",
    "behavior_learning_period": 60,
    "enable_behavior_monitoring": true,
    "enable_geoip_filtering": true,
    "prompt_for_unknown_connections": true,
    "blocked_count": 0,
    "interface": "en0"
}
EOF
    echo "Created default config file at $CONFIG_FILE"
else
    echo "Config file already exists at $CONFIG_FILE"
    
    # Check if interface is set, if not add it
    if ! grep -q "\"interface\"" "$CONFIG_FILE"; then
        # Use temporary file for sed on macOS
        sed -i.bak 's/}$/,\n    "interface": "en0"\n}/' "$CONFIG_FILE"
        rm -f "$CONFIG_FILE.bak"
        echo "Added interface setting to existing config"
    fi
fi

echo "Config initialization complete!"

