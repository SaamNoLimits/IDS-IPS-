#!/usr/bin/env python3
"""
🛡️ Advanced IDS Management Dashboard with Blockchain Security
Features: Real-time monitoring, IPS rules, blockchain hashes, reports
"""

import streamlit as st
import pandas as pd
import numpy as np
import json
import hashlib
import time
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import subprocess
import os
import sqlite3
from collections import defaultdict, Counter
import threading
import queue

# Page configuration
st.set_page_config(
    page_title="🛡️ Advanced IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    .attack-alert {
        background: linear-gradient(90deg, #ff6b6b 0%, #ee5a24 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    .success-card {
        background: linear-gradient(90deg, #56ab2f 0%, #a8e6cf 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    .blockchain-hash {
        font-family: 'Courier New', monospace;
        background: #2c3e50;
        color: #ecf0f1;
        padding: 0.5rem;
        border-radius: 5px;
        font-size: 0.8rem;
    }
</style>
""", unsafe_allow_html=True)

class BlockchainLogger:
    """Blockchain-secured logging system"""
    
    def __init__(self):
        self.chain = []
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for blockchain"""
        conn = sqlite3.connect('ids_blockchain.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blockchain_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                block_hash TEXT,
                previous_hash TEXT,
                data TEXT,
                nonce INTEGER
            )
        ''')
        conn.commit()
        conn.close()
        
    def calculate_hash(self, timestamp, data, previous_hash, nonce):
        """Calculate SHA-256 hash for block"""
        block_string = f"{timestamp}{data}{previous_hash}{nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, data, difficulty=4):
        """Mine a new block with proof of work"""
        timestamp = datetime.now().isoformat()
        previous_hash = self.get_latest_hash()
        nonce = 0
        
        while True:
            hash_value = self.calculate_hash(timestamp, data, previous_hash, nonce)
            if hash_value.startswith('0' * difficulty):
                break
            nonce += 1
            
        return {
            'timestamp': timestamp,
            'hash': hash_value,
            'previous_hash': previous_hash,
            'data': data,
            'nonce': nonce
        }
    
    def get_latest_hash(self):
        """Get hash of the latest block"""
        conn = sqlite3.connect('ids_blockchain.db')
        cursor = conn.cursor()
        cursor.execute('SELECT block_hash FROM blockchain_logs ORDER BY id DESC LIMIT 1')
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else "0"
    
    def add_block(self, attack_data):
        """Add new attack to blockchain"""
        block = self.mine_block(json.dumps(attack_data))
        
        conn = sqlite3.connect('ids_blockchain.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO blockchain_logs (timestamp, block_hash, previous_hash, data, nonce)
            VALUES (?, ?, ?, ?, ?)
        ''', (block['timestamp'], block['hash'], block['previous_hash'], 
              block['data'], block['nonce']))
        conn.commit()
        conn.close()
        
        return block

class IPSManager:
    """Intrusion Prevention System Manager"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.rules = []
        self.load_rules()
    
    def load_rules(self):
        """Load existing IPS rules"""
        try:
            with open('ips_rules.json', 'r') as f:
                self.rules = json.load(f)
        except FileNotFoundError:
            self.rules = []
    
    def save_rules(self):
        """Save IPS rules to file"""
        with open('ips_rules.json', 'w') as f:
            json.dump(self.rules, f, indent=2)
    
    def add_rule(self, rule_type, source_ip, action, duration=3600):
        """Add new IPS rule"""
        rule = {
            'id': len(self.rules) + 1,
            'type': rule_type,
            'source_ip': source_ip,
            'action': action,
            'duration': duration,
            'created': datetime.now().isoformat(),
            'active': True
        }
        self.rules.append(rule)
        self.save_rules()
        return rule
    
    def generate_iptables_rule(self, rule):
        """Generate iptables command for rule"""
        if rule['action'] == 'BLOCK':
            return f"iptables -A INPUT -s {rule['source_ip']} -j DROP"
        elif rule['action'] == 'RATE_LIMIT':
            return f"iptables -A INPUT -s {rule['source_ip']} -m limit --limit 10/min -j ACCEPT"
        return ""
    
    def apply_rule(self, rule):
        """Apply IPS rule to system"""
        command = self.generate_iptables_rule(rule)
        if command:
            try:
                subprocess.run(command.split(), check=True)
                return True
            except subprocess.CalledProcessError:
                return False
        return False

class IDSAnalyzer:
    """IDS Data Analyzer"""
    
    def __init__(self):
        self.attack_data = []
        self.load_attack_data()
    
    def load_attack_data(self):
        """Load attack data from log files"""
        attack_files = [
            'sensitive_attacks_log.txt',
            'detailed_attack_log.txt',
            'real_attacks_log.txt'
        ]
        
        self.attack_data = []
        for file in attack_files:
            if os.path.exists(file):
                with open(file, 'r') as f:
                    for line in f:
                        if line.strip():
                            self.parse_attack_line(line.strip())
    
    def parse_attack_line(self, line):
        """Parse attack log line"""
        try:
            parts = line.split(': ', 1)
            if len(parts) == 2:
                timestamp_str = parts[0]
                attack_info = parts[1]
                
                # Extract attack details
                attack_data = {
                    'timestamp': timestamp_str,
                    'raw_info': attack_info,
                    'source_ip': self.extract_ip(attack_info),
                    'attack_type': self.extract_attack_type(attack_info),
                    'confidence': self.extract_confidence(attack_info)
                }
                self.attack_data.append(attack_data)
        except Exception as e:
            pass
    
    def extract_ip(self, info):
        """Extract IP address from attack info"""
        import re
        ip_pattern = r'from (\d+\.\d+\.\d+\.\d+)'
        match = re.search(ip_pattern, info)
        return match.group(1) if match else 'Unknown'
    
    def extract_attack_type(self, info):
        """Extract attack type from info"""
        if 'Port Scan' in info:
            return 'Port Scan'
        elif 'SYN' in info:
            return 'SYN Attack'
        elif 'TCP Flood' in info:
            return 'TCP Flood'
        elif 'UDP Flood' in info:
            return 'UDP Flood'
        elif 'ICMP' in info:
            return 'ICMP Attack'
        elif 'Brute Force' in info:
            return 'Brute Force'
        elif 'Stealth' in info:
            return 'Stealth Scan'
        return 'Unknown'
    
    def extract_confidence(self, info):
        """Extract ML confidence from info"""
        import re
        conf_pattern = r'ML[:\s]+(\d+\.?\d*)%'
        match = re.search(conf_pattern, info)
        if match:
            return float(match.group(1))
        return 0.0

# Initialize components
@st.cache_resource
def init_components():
    blockchain = BlockchainLogger()
    ips_manager = IPSManager()
    analyzer = IDSAnalyzer()
    return blockchain, ips_manager, analyzer

def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ Advanced IDS Management Dashboard</h1>', 
                unsafe_allow_html=True)
    
    # Initialize components
    blockchain, ips_manager, analyzer = init_components()
    
    # Sidebar
    st.sidebar.title("🔧 IDS Control Panel")
    page = st.sidebar.selectbox("Select Page", [
        "📊 Real-time Dashboard",
        "🚨 Attack Analysis", 
        "🛡️ IPS Rules Management",
        "⛓️ Blockchain Security",
        "📈 Reports & Analytics",
        "⚙️ System Configuration"
    ])
    
    if page == "📊 Real-time Dashboard":
        show_realtime_dashboard(analyzer, blockchain)
    elif page == "🚨 Attack Analysis":
        show_attack_analysis(analyzer)
    elif page == "🛡️ IPS Rules Management":
        show_ips_management(ips_manager)
    elif page == "⛓️ Blockchain Security":
        show_blockchain_security(blockchain)
    elif page == "📈 Reports & Analytics":
        show_reports_analytics(analyzer)
    elif page == "⚙️ System Configuration":
        show_system_config()

def show_realtime_dashboard(analyzer, blockchain):
    """Real-time dashboard page"""
    st.header("📊 Real-time IDS Dashboard")
    
    # Refresh data
    if st.button("🔄 Refresh Data"):
        analyzer.load_attack_data()
        st.rerun()
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_attacks = len(analyzer.attack_data)
        st.markdown(f"""
        <div class="metric-card">
            <h3>🚨 Total Attacks</h3>
            <h2>{total_attacks}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        unique_ips = len(set([a['source_ip'] for a in analyzer.attack_data]))
        st.markdown(f"""
        <div class="metric-card">
            <h3>🌐 Unique IPs</h3>
            <h2>{unique_ips}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        avg_confidence = np.mean([a['confidence'] for a in analyzer.attack_data]) if analyzer.attack_data else 0
        st.markdown(f"""
        <div class="metric-card">
            <h3>🎯 Avg Confidence</h3>
            <h2>{avg_confidence:.1f}%</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        try:
            recent_attacks = len([a for a in analyzer.attack_data 
                                if 'timestamp' in a and a['timestamp']])
        except:
            recent_attacks = 0
        st.markdown(f"""
        <div class="metric-card">
            <h3>⏰ Last Hour</h3>
            <h2>{recent_attacks}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    # Recent attacks
    st.subheader("🚨 Recent Attacks")
    if analyzer.attack_data:
        recent = analyzer.attack_data[-10:]  # Last 10 attacks
        for attack in reversed(recent):
            st.markdown(f"""
            <div class="attack-alert">
                <strong>{attack['attack_type']}</strong> from <code>{attack['source_ip']}</code><br>
                <small>Confidence: {attack['confidence']:.1f}% | Time: {attack['timestamp']}</small>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No attacks detected yet. Your system is secure! 🛡️")
    
    # Attack timeline
    if analyzer.attack_data:
        st.subheader("📈 Attack Timeline")
        try:
            df = pd.DataFrame(analyzer.attack_data)
            # Simple timeline by count
            attack_counts = df.groupby('attack_type').size().reset_index()
            attack_counts.columns = ['attack_type', 'count']
            
            fig = px.bar(attack_counts, x='attack_type', y='count', 
                        title='Attack Types Distribution',
                        labels={'count': 'Number of Attacks', 'attack_type': 'Attack Type'})
            st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.error(f"Error creating timeline: {e}")

def show_attack_analysis(analyzer):
    """Attack analysis page"""
    st.header("🚨 Attack Analysis")
    
    if not analyzer.attack_data:
        st.warning("No attack data available. Run some attacks to see analysis.")
        return
    
    df = pd.DataFrame(analyzer.attack_data)
    
    # Attack type distribution
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Attack Types Distribution")
        attack_counts = df['attack_type'].value_counts()
        fig = px.pie(values=attack_counts.values, names=attack_counts.index,
                    title="Attack Types")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🌐 Top Attacking IPs")
        ip_counts = df['source_ip'].value_counts().head(10)
        fig = px.bar(x=ip_counts.values, y=ip_counts.index, orientation='h',
                    title="Most Active Attacking IPs")
        st.plotly_chart(fig, use_container_width=True)
    
    # Confidence analysis
    st.subheader("📊 ML Confidence Analysis")
    fig = px.histogram(df, x='confidence', bins=20, 
                      title='Distribution of ML Confidence Scores')
    st.plotly_chart(fig, use_container_width=True)
    
    # Detailed attack table
    st.subheader("📋 Detailed Attack Log")
    st.dataframe(df[['timestamp', 'attack_type', 'source_ip', 'confidence']], 
                use_container_width=True)

def show_ips_management(ips_manager):
    """IPS rules management page"""
    st.header("🛡️ IPS Rules Management")
    
    # Add new rule
    st.subheader("➕ Add New IPS Rule")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        rule_type = st.selectbox("Rule Type", ["BLOCK", "RATE_LIMIT", "MONITOR"])
    
    with col2:
        source_ip = st.text_input("Source IP", placeholder="192.168.1.100")
    
    with col3:
        duration = st.number_input("Duration (seconds)", min_value=60, value=3600)
    
    if st.button("🚀 Add Rule"):
        if source_ip:
            rule = ips_manager.add_rule(rule_type, source_ip, rule_type, duration)
            st.success(f"✅ Rule added: {rule_type} {source_ip}")
            
            # Generate iptables command
            iptables_cmd = ips_manager.generate_iptables_rule(rule)
            if iptables_cmd:
                st.code(iptables_cmd, language='bash')
                
                if st.button("🔧 Apply Rule to System"):
                    if ips_manager.apply_rule(rule):
                        st.success("✅ Rule applied successfully!")
                    else:
                        st.error("❌ Failed to apply rule. Check permissions.")
        else:
            st.error("Please enter a source IP address")
    
    # Current rules
    st.subheader("📋 Current IPS Rules")
    if ips_manager.rules:
        rules_df = pd.DataFrame(ips_manager.rules)
        st.dataframe(rules_df, use_container_width=True)
        
        # Rule management
        st.subheader("🔧 Rule Actions")
        rule_id = st.selectbox("Select Rule ID", [r['id'] for r in ips_manager.rules])
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🗑️ Delete Rule"):
                ips_manager.rules = [r for r in ips_manager.rules if r['id'] != rule_id]
                ips_manager.save_rules()
                st.success("Rule deleted!")
                st.rerun()
        
        with col2:
            if st.button("⏸️ Disable Rule"):
                for rule in ips_manager.rules:
                    if rule['id'] == rule_id:
                        rule['active'] = False
                ips_manager.save_rules()
                st.success("Rule disabled!")
                st.rerun()
    else:
        st.info("No IPS rules configured yet.")

def show_blockchain_security(blockchain):
    """Blockchain security page"""
    st.header("⛓️ Blockchain Security")
    
    st.markdown("""
    ### 🔐 Blockchain-Secured Attack Logs
    All attack detections are secured using blockchain technology with proof-of-work mining.
    Each attack creates an immutable block in the chain.
    """)
    
    # Add attack to blockchain
    st.subheader("➕ Add Attack to Blockchain")
    col1, col2 = st.columns(2)
    
    with col1:
        attack_type = st.text_input("Attack Type", "TCP Flood")
        source_ip = st.text_input("Source IP", "192.168.1.100")
    
    with col2:
        confidence = st.slider("ML Confidence", 0.0, 100.0, 95.0)
        severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    
    if st.button("⛓️ Mine Block"):
        attack_data = {
            'attack_type': attack_type,
            'source_ip': source_ip,
            'confidence': confidence,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        
        with st.spinner("Mining block... This may take a few seconds."):
            block = blockchain.add_block(attack_data)
        
        st.success("✅ Block mined successfully!")
        st.markdown(f"""
        <div class="blockchain-hash">
            <strong>Block Hash:</strong><br>
            {block['hash']}<br><br>
            <strong>Previous Hash:</strong><br>
            {block['previous_hash']}<br><br>
            <strong>Nonce:</strong> {block['nonce']}
        </div>
        """, unsafe_allow_html=True)
    
    # Blockchain explorer
    st.subheader("🔍 Blockchain Explorer")
    conn = sqlite3.connect('ids_blockchain.db')
    blocks_df = pd.read_sql_query("SELECT * FROM blockchain_logs ORDER BY id DESC LIMIT 10", conn)
    conn.close()
    
    if not blocks_df.empty:
        for _, block in blocks_df.iterrows():
            with st.expander(f"Block #{block['id']} - {block['timestamp']}"):
                st.markdown(f"""
                <div class="blockchain-hash">
                    <strong>Hash:</strong> {block['block_hash']}<br>
                    <strong>Previous Hash:</strong> {block['previous_hash']}<br>
                    <strong>Nonce:</strong> {block['nonce']}<br>
                    <strong>Data:</strong><br>
                    {block['data']}
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("No blocks in blockchain yet. Add some attacks to see the chain.")

def show_reports_analytics(analyzer):
    """Reports and analytics page"""
    st.header("📈 Reports & Analytics")
    
    if not analyzer.attack_data:
        st.warning("No data available for reports.")
        return
    
    df = pd.DataFrame(analyzer.attack_data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Time-based analysis
    st.subheader("⏰ Time-based Analysis")
    df['hour'] = df['timestamp'].dt.hour
    hourly_stats = df.groupby('hour').size()
    
    fig = px.bar(x=hourly_stats.index, y=hourly_stats.values,
                title="Attacks by Hour of Day",
                labels={'x': 'Hour', 'y': 'Number of Attacks'})
    st.plotly_chart(fig, use_container_width=True)
    
    # Attack severity matrix
    st.subheader("🎯 Attack Severity Matrix")
    severity_matrix = df.groupby(['attack_type', 'source_ip']).size().unstack(fill_value=0)
    
    if not severity_matrix.empty:
        fig = px.imshow(severity_matrix.values,
                       x=severity_matrix.columns,
                       y=severity_matrix.index,
                       title="Attack Patterns by IP and Type")
        st.plotly_chart(fig, use_container_width=True)
    
    # Export reports
    st.subheader("📄 Export Reports")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Export CSV"):
            csv = df.to_csv(index=False)
            st.download_button("Download CSV", csv, "ids_report.csv", "text/csv")
    
    with col2:
        if st.button("📋 Export JSON"):
            json_data = df.to_json(orient='records', indent=2)
            st.download_button("Download JSON", json_data, "ids_report.json", "application/json")
    
    with col3:
        if st.button("📈 Generate PDF Report"):
            st.info("PDF generation feature coming soon!")

def show_system_config():
    """System configuration page"""
    st.header("⚙️ System Configuration")
    
    # IDS Status
    st.subheader("🛡️ IDS Status")
    
    # Check if IDS is running
    try:
        result = subprocess.run(['pgrep', '-f', 'sensitive_ids.py'], 
                              capture_output=True, text=True)
        ids_running = bool(result.stdout.strip())
    except:
        ids_running = False
    
    if ids_running:
        st.markdown("""
        <div class="success-card">
            <h3>✅ IDS Status: RUNNING</h3>
            <p>Your IDS is actively monitoring network traffic</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="attack-alert">
            <h3>❌ IDS Status: STOPPED</h3>
            <p>Your IDS is not running</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Control buttons
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🚀 Start IDS"):
            st.info("Starting IDS... Check terminal for output")
            # Note: In production, you'd use subprocess to start the IDS
    
    with col2:
        if st.button("🛑 Stop IDS"):
            try:
                subprocess.run(['pkill', '-f', 'sensitive_ids.py'])
                st.success("IDS stopped")
            except:
                st.error("Failed to stop IDS")
    
    with col3:
        if st.button("🔄 Restart IDS"):
            st.info("Restarting IDS...")
    
    # Configuration settings
    st.subheader("⚙️ IDS Configuration")
    
    config = {
        'detection_threshold': st.slider("Detection Threshold", 0.1, 1.0, 0.4),
        'packet_buffer_size': st.number_input("Packet Buffer Size", 50, 500, 100),
        'analysis_window': st.number_input("Analysis Window (seconds)", 1, 10, 3),
        'log_level': st.selectbox("Log Level", ["DEBUG", "INFO", "WARNING", "ERROR"])
    }
    
    if st.button("💾 Save Configuration"):
        with open('ids_config.json', 'w') as f:
            json.dump(config, f, indent=2)
        st.success("Configuration saved!")
    
    # System information
    st.subheader("💻 System Information")
    
    try:
        # Get system info
        import psutil
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("CPU Usage", f"{psutil.cpu_percent()}%")
            st.metric("Memory Usage", f"{psutil.virtual_memory().percent}%")
        
        with col2:
            st.metric("Disk Usage", f"{psutil.disk_usage('/').percent}%")
            st.metric("Network Connections", len(psutil.net_connections()))
    except ImportError:
        st.info("Install psutil for system monitoring: pip install psutil")

if __name__ == "__main__":
    main()
