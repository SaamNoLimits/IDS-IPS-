#!/bin/bash

# Real-Time IDS Pipeline Setup Script
# This script sets up the environment for the IDS pipeline

echo "🛡️  Setting up Real-Time IDS Pipeline"
echo "======================================"

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo "⚠️  Running as root. This is required for network capture."
    else
        echo "❌ This script needs to be run as root for network capture capabilities."
        echo "Please run: sudo $0"
        exit 1
    fi
}

# Install system dependencies
install_system_deps() {
    echo "📦 Installing system dependencies..."
    
    # Update package list
    apt-get update
    
    # Install required packages
    apt-get install -y \
        python3 \
        python3-pip \
        python3-dev \
        libpcap-dev \
        tcpdump \
        iptables \
        ufw \
        net-tools \
        build-essential \
        libffi-dev \
        libssl-dev
    
    echo "✅ System dependencies installed"
}

# Install Python packages
install_python_deps() {
    echo "🐍 Installing Python dependencies..."
    
    # Upgrade pip
    python3 -m pip install --upgrade pip
    
    # Install required packages
    pip3 install \
        tensorflow \
        scapy \
        pandas \
        numpy \
        scikit-learn \
        psutil \
        logging \
        pathlib
    
    echo "✅ Python dependencies installed"
}

# Setup network capture permissions
setup_permissions() {
    echo "🔐 Setting up network capture permissions..."
    
    # Allow Python to capture packets without root
    which python3 | head -1 | xargs -I {} setcap cap_net_raw+ep {}
    
    # Create ids user group
    groupadd -f ids
    
    echo "✅ Permissions configured"
}

# Create directory structure
create_directories() {
    echo "📁 Creating directory structure..."
    
    mkdir -p /opt/ids-pipeline
    mkdir -p /opt/ids-pipeline/logs
    mkdir -p /opt/ids-pipeline/rules
    mkdir -p /opt/ids-pipeline/models
    mkdir -p /var/log/ids
    
    # Set permissions
    chown -R $SUDO_USER:ids /opt/ids-pipeline
    chmod -R 755 /opt/ids-pipeline
    
    echo "✅ Directory structure created"
}

# Create systemd service
create_service() {
    echo "⚙️  Creating systemd service..."
    
    cat > /etc/systemd/system/ids-pipeline.service << EOF
[Unit]
Description=Real-Time IDS Pipeline
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ids-pipeline
ExecStart=/usr/bin/python3 /opt/ids-pipeline/realtime_ids_pipeline.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo "✅ Systemd service created"
}

# Create configuration file
create_config() {
    echo "⚙️  Creating configuration file..."
    
    cat > /opt/ids-pipeline/config.json << EOF
{
    "model_path": "/opt/ids-pipeline/models/enhanced_ids_model_99percent.h5",
    "scaler_path": "/opt/ids-pipeline/models/feature_scaler.pkl",
    "interface": "auto",
    "detection_window": 5,
    "confidence_threshold": 0.8,
    "auto_block": false,
    "log_level": "INFO",
    "rate_limit": {
        "max_connections_per_minute": 100,
        "block_duration": 3600
    },
    "alerts": {
        "email_enabled": false,
        "email_recipient": "admin@example.com",
        "webhook_url": ""
    }
}
EOF

    chown $SUDO_USER:ids /opt/ids-pipeline/config.json
    echo "✅ Configuration file created"
}

# Create helper scripts
create_helper_scripts() {
    echo "🔧 Creating helper scripts..."
    
    # Start script
    cat > /opt/ids-pipeline/start_ids.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting IDS Pipeline..."
cd /opt/ids-pipeline
sudo systemctl start ids-pipeline
sudo systemctl status ids-pipeline
EOF

    # Stop script
    cat > /opt/ids-pipeline/stop_ids.sh << 'EOF'
#!/bin/bash
echo "🛑 Stopping IDS Pipeline..."
sudo systemctl stop ids-pipeline
echo "✅ IDS Pipeline stopped"
EOF

    # Status script
    cat > /opt/ids-pipeline/status_ids.sh << 'EOF'
#!/bin/bash
echo "📊 IDS Pipeline Status:"
sudo systemctl status ids-pipeline
echo ""
echo "📈 Recent detections:"
tail -n 10 /opt/ids-pipeline/logs/ids_pipeline.log
EOF

    # View logs script
    cat > /opt/ids-pipeline/view_logs.sh << 'EOF'
#!/bin/bash
echo "📋 IDS Pipeline Logs:"
echo "Press Ctrl+C to exit"
sudo journalctl -f -u ids-pipeline
EOF

    # Unblock IP script
    cat > /opt/ids-pipeline/unblock_ip.sh << 'EOF'
#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

IP=$1
echo "🔓 Unblocking IP: $IP"

# Remove from iptables
iptables -D INPUT -s $IP -j DROP 2>/dev/null
iptables -D INPUT -s $IP -m limit --limit 10/min -j ACCEPT 2>/dev/null

# Remove from UFW
ufw delete deny from $IP 2>/dev/null

echo "✅ IP $IP unblocked"
EOF

    # Make scripts executable
    chmod +x /opt/ids-pipeline/*.sh
    chown $SUDO_USER:ids /opt/ids-pipeline/*.sh
    
    echo "✅ Helper scripts created"
}

# Create test script for Kali attacks
create_test_script() {
    echo "🧪 Creating test script..."
    
    cat > /opt/ids-pipeline/test_detection.py << 'EOF'
#!/usr/bin/env python3
"""
Test script to verify IDS detection capabilities
"""

import subprocess
import time
import json
import os

def test_port_scan():
    """Simulate port scan detection test"""
    print("🔍 Testing port scan detection...")
    print("Run this from your Kali VM:")
    print("nmap -sS -O target_ip")
    print("or")
    print("nmap -sT -p 1-1000 target_ip")

def test_brute_force():
    """Simulate brute force detection test"""
    print("🔓 Testing brute force detection...")
    print("Run this from your Kali VM:")
    print("hydra -l admin -P /usr/share/wordlists/rockyou.txt target_ip ssh")
    print("or")
    print("medusa -h target_ip -u admin -P /usr/share/wordlists/rockyou.txt -M ssh")

def test_ddos():
    """Simulate DDoS detection test"""
    print("💥 Testing DDoS detection...")
    print("Run this from your Kali VM:")
    print("hping3 -c 10000 -d 120 -S -w 64 -p 80 --flood --rand-source target_ip")
    print("or")
    print("for i in {1..1000}; do curl target_ip & done")

def monitor_detections():
    """Monitor for detections"""
    print("👀 Monitoring for detections...")
    print("Watching attack_detections.json for new alerts...")
    
    detection_file = "attack_detections.json"
    if not os.path.exists(detection_file):
        print(f"Creating {detection_file}...")
        open(detection_file, 'a').close()
    
    print("Press Ctrl+C to stop monitoring")
    
    try:
        # Follow the file like 'tail -f'
        with open(detection_file, 'r') as f:
            # Go to end of file
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                if line:
                    try:
                        detection = json.loads(line.strip())
                        print_detection(detection)
                    except json.JSONDecodeError:
                        pass
                else:
                    time.sleep(1)
    except KeyboardInterrupt:
        print("\n✅ Monitoring stopped")

def print_detection(detection):
    """Print formatted detection"""
    det = detection['detection']
    resp = detection['response']
    
    print(f"\n🚨 ATTACK DETECTED at {detection['timestamp']}")
    print(f"   Type: {det['attack_type']}")
    print(f"   Source: {det['src_ip']}:{det['src_port']}")
    print(f"   Target: {det['dst_ip']}:{det['dst_port']}")
    print(f"   Confidence: {det['confidence']:.2%}")
    print(f"   Action: {resp['action']} ({resp['severity']})")
    
    if resp['rules']:
        print("   Blocking Rules:")
        for rule in resp['rules']:
            print(f"     {rule['rule']}")
    print("-" * 60)

def main():
    print("🧪 IDS Detection Test Suite")
    print("=" * 40)
    print("1. Port Scan Test")
    print("2. Brute Force Test") 
    print("3. DDoS Test")
    print("4. Monitor Detections")
    print("5. Exit")
    
    while True:
        choice = input("\nSelect test (1-5): ").strip()
        
        if choice == '1':
            test_port_scan()
        elif choice == '2':
            test_brute_force()
        elif choice == '3':
            test_ddos()
        elif choice == '4':
            monitor_detections()
        elif choice == '5':
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
EOF

    chmod +x /opt/ids-pipeline/test_detection.py
    chown $SUDO_USER:ids /opt/ids-pipeline/test_detection.py
    
    echo "✅ Test script created"
}

# Create web dashboard (optional)
create_dashboard() {
    echo "🌐 Creating web dashboard..."
    
    cat > /opt/ids-pipeline/dashboard.py << 'EOF'
#!/usr/bin/env python3
"""
Simple web dashboard for IDS monitoring
"""

from flask import Flask, render_template, jsonify
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)

@app.route('/')
def dashboard():
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>IDS Dashboard</title>
    <meta http-equiv="refresh" content="10">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .alert { background: #ffebee; border: 1px solid #f44336; padding: 10px; margin: 10px 0; }
        .stats { background: #e8f5e8; border: 1px solid #4caf50; padding: 10px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>🛡️ Real-Time IDS Dashboard</h1>
    
    <div class="stats">
        <h3>📊 Statistics</h3>
        <div id="stats">Loading...</div>
    </div>
    
    <div class="alert">
        <h3>🚨 Recent Attacks</h3>
        <div id="attacks">Loading...</div>
    </div>
    
    <script>
        function loadData() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('stats').innerHTML = 
                        `Total Attacks: ${data.total_attacks}<br>
                         Attacks Today: ${data.attacks_today}<br>
                         Most Common Attack: ${data.most_common}<br>
                         Last Updated: ${new Date()}`;
                });
            
            fetch('/api/recent_attacks')
                .then(response => response.json())
                .then(data => {
                    let html = '<table><tr><th>Time</th><th>Type</th><th>Source IP</th><th>Action</th></tr>';
                    data.forEach(attack => {
                        html += `<tr>
                            <td>${attack.timestamp}</td>
                            <td>${attack.type}</td>
                            <td>${attack.source_ip}</td>
                            <td>${attack.action}</td>
                        </tr>`;
                    });
                    html += '</table>';
                    document.getElementById('attacks').innerHTML = html;
                });
        }
        
        loadData();
        setInterval(loadData, 10000); // Refresh every 10 seconds
    </script>
</body>
</html>
    '''

@app.route('/api/stats')
def get_stats():
    try:
        with open('attack_detections.json', 'r') as f:
            lines = f.readlines()
        
        total_attacks = len(lines)
        attacks_today = 0
        attack_types = {}
        
        today = datetime.now().date()
        
        for line in lines:
            try:
                detection = json.loads(line.strip())
                timestamp = datetime.strptime(detection['timestamp'], '%Y%m%d_%H%M%S')
                
                if timestamp.date() == today:
                    attacks_today += 1
                
                attack_type = detection['detection']['attack_type']
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            except:
                continue
        
        most_common = max(attack_types, key=attack_types.get) if attack_types else "None"
        
        return jsonify({
            'total_attacks': total_attacks,
            'attacks_today': attacks_today,
            'most_common': most_common
        })
    except:
        return jsonify({
            'total_attacks': 0,
            'attacks_today': 0,
            'most_common': 'None'
        })

@app.route('/api/recent_attacks')
def get_recent_attacks():
    try:
        with open('attack_detections.json', 'r') as f:
            lines = f.readlines()
        
        recent_attacks = []
        for line in lines[-10:]:  # Last 10 attacks
            try:
                detection = json.loads(line.strip())
                recent_attacks.append({
                    'timestamp': detection['timestamp'],
                    'type': detection['detection']['attack_type'],
                    'source_ip': detection['detection']['src_ip'],
                    'action': detection['response']['action']
                })
            except:
                continue
        
        return jsonify(recent_attacks[::-1])  # Reverse to show newest first
    except:
        return jsonify([])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
EOF

    chmod +x /opt/ids-pipeline/dashboard.py
    chown $SUDO_USER:ids /opt/ids-pipeline/dashboard.py
    
    # Install Flask
    pip3 install flask
    
    echo "✅ Web dashboard created (access at http://localhost:8080)"
}

# Main installation function
main() {
    echo "Starting IDS Pipeline installation..."
    
    check_root
    install_system_deps
    install_python_deps
    setup_permissions
    create_directories
    create_service
    create_config
    create_helper_scripts
    create_test_script
    create_dashboard
    
    echo ""
    echo "🎉 IDS Pipeline installation completed!"
    echo ""
    echo "📋 Next steps:"
    echo "1. Copy your model files to /opt/ids-pipeline/models/"
    echo "   - enhanced_ids_model_99percent.h5"
    echo "   - feature_scaler.pkl"
    echo ""
    echo "2. Edit configuration: /opt/ids-pipeline/config.json"
    echo ""
    echo "3. Start the service:"
    echo "   cd /opt/ids-pipeline && ./start_ids.sh"
    echo ""
    echo "4. Test detection:"
    echo "   python3 /opt/ids-pipeline/test_detection.py"
    echo ""
    echo "5. View dashboard:"
    echo "   python3 /opt/ids-pipeline/dashboard.py"
    echo "   Then open http://localhost:8080"
    echo ""
    echo "📁 Important files:"
    echo "   - Service control: /opt/ids-pipeline/{start,stop,status}_ids.sh"
    echo "   - Logs: /opt/ids-pipeline/logs/"
    echo "   - Detections: /opt/ids-pipeline/attack_detections.json"
    echo "   - Block rules: /opt/ids-pipeline/block_rules_*.sh"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "   - Check logs: ./view_logs.sh"
    echo "   - Check status: ./status_ids.sh"
    echo "   - Unblock IP: ./unblock_ip.sh <IP_ADDRESS>"
}

# Run main function
main
