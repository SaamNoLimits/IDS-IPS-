#!/bin/bash

# 🛡️ IDS Dashboard Launcher
# Launches the Streamlit dashboard for IDS management

echo "🛡️ Advanced IDS Management Dashboard"
echo "===================================="

# Check if streamlit is installed
if ! command -v streamlit &> /dev/null; then
    echo "📦 Installing required packages..."
    pip3 install -r dashboard_requirements.txt
fi

# Create necessary directories and files
echo "📁 Setting up environment..."
mkdir -p logs
touch ips_rules.json
touch ids_config.json

# Initialize empty config if not exists
if [ ! -s ids_config.json ]; then
    echo '{"detection_threshold": 0.4, "packet_buffer_size": 100, "analysis_window": 3, "log_level": "INFO"}' > ids_config.json
fi

# Initialize empty IPS rules if not exists
if [ ! -s ips_rules.json ]; then
    echo '[]' > ips_rules.json
fi

echo "🚀 Starting IDS Dashboard..."
echo "📱 Dashboard will open in your browser at: http://localhost:8501"
echo "🔧 Use the dashboard to manage your IDS, create IPS rules, and view blockchain-secured logs"
echo ""

# Launch Streamlit dashboard
streamlit run ids_dashboard.py --server.port 8501 --server.address 0.0.0.0
