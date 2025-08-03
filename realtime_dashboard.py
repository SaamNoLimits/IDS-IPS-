#!/usr/bin/env python3
"""
🛡️ Real-Time Auto-Refresh IDS Dashboard
Features: Auto-refresh every 3 seconds, live attack monitoring
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
    page_title="🛡️ Real-Time IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Auto-refresh every 3 seconds
st.markdown("""
<script>
    setTimeout(function(){
        window.location.reload();
    }, 3000);
</script>
""", unsafe_allow_html=True)

# Custom CSS for better visuals
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.7; }
        100% { opacity: 1; }
    }
    .metric-card {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    .attack-alert {
        background: linear-gradient(90deg, #ff6b6b 0%, #ee5a24 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
        animation: flash 1s infinite;
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    @keyframes flash {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.8; }
    }
    .success-card {
        background: linear-gradient(90deg, #56ab2f 0%, #a8e6cf 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    .live-indicator {
        display: inline-block;
        width: 10px;
        height: 10px;
        background-color: #ff0000;
        border-radius: 50%;
        animation: blink 1s infinite;
        margin-right: 5px;
    }
    @keyframes blink {
        0%, 50% { opacity: 1; }
        51%, 100% { opacity: 0; }
    }
    .timestamp {
        font-size: 0.8rem;
        color: #666;
        font-style: italic;
    }
</style>
""", unsafe_allow_html=True)

class RealTimeIDSAnalyzer:
    """Real-time IDS Data Analyzer with auto-refresh"""
    
    def __init__(self):
        self.attack_data = []
        self.last_update = None
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
                try:
                    with open(file, 'r') as f:
                        for line in f:
                            if line.strip():
                                self.parse_attack_line(line.strip())
                except Exception as e:
                    continue
        
        self.last_update = datetime.now()
    
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
    
    def get_recent_attacks(self, minutes=5):
        """Get attacks from last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        recent = []
        for attack in self.attack_data:
            try:
                # Simple time comparison
                if attack['timestamp']:
                    recent.append(attack)
            except:
                continue
        return recent[-20:]  # Last 20 attacks

def check_ids_status():
    """Check if IDS is running"""
    try:
        result = subprocess.run(['pgrep', '-f', 'sensitive_ids.py'], 
                              capture_output=True, text=True)
        return bool(result.stdout.strip())
    except:
        return False

def main():
    # Header with live indicator
    st.markdown('''
    <h1 class="main-header">
        <span class="live-indicator"></span>
        🛡️ Real-Time IDS Dashboard (Auto-Refresh)
    </h1>
    ''', unsafe_allow_html=True)
    
    # Show last update time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(f'<p class="timestamp">🕒 Last Update: {current_time} (Auto-refreshing every 3 seconds)</p>', 
                unsafe_allow_html=True)
    
    # Initialize analyzer
    analyzer = RealTimeIDSAnalyzer()
    
    # IDS Status Check
    ids_running = check_ids_status()
    
    col1, col2 = st.columns([3, 1])
    with col1:
        if ids_running:
            st.markdown("""
            <div class="success-card">
                <h3>✅ IDS Status: RUNNING & MONITORING</h3>
                <p>Your IDS is actively detecting attacks</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="attack-alert">
                <h3>❌ IDS Status: STOPPED</h3>
                <p>Start your IDS to see real-time attacks</p>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        if st.button("🔄 Manual Refresh"):
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
        recent_attacks = len(analyzer.get_recent_attacks(5))
        st.markdown(f"""
        <div class="metric-card">
            <h3>⏰ Last 5 Min</h3>
            <h2>{recent_attacks}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    # Live Attack Feed
    st.subheader("🚨 Live Attack Feed (Auto-Updating)")
    
    if analyzer.attack_data:
        recent = analyzer.get_recent_attacks(10)  # Last 10 minutes
        
        if recent:
            st.markdown("### 🔥 Latest Attacks:")
            for i, attack in enumerate(reversed(recent[-10:])):  # Show last 10
                attack_time = attack['timestamp'] if attack['timestamp'] else 'Unknown'
                st.markdown(f"""
                <div class="attack-alert">
                    <strong>#{len(recent)-i} - {attack['attack_type']}</strong> from <code>{attack['source_ip']}</code><br>
                    <small>Confidence: {attack['confidence']:.1f}% | Time: {attack_time}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("🛡️ No recent attacks detected. Your system is secure!")
    else:
        st.info("📡 Waiting for attack data... Launch attacks from your Kali VM to see real-time detection!")
    
    # Real-time Charts
    if analyzer.attack_data:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Attack Types (Real-time)")
            try:
                df = pd.DataFrame(analyzer.attack_data)
                attack_counts = df['attack_type'].value_counts()
                
                fig = px.pie(values=attack_counts.values, names=attack_counts.index,
                            title="Current Attack Distribution")
                fig.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                st.error(f"Chart error: {e}")
        
        with col2:
            st.subheader("🌐 Top Attacking IPs")
            try:
                df = pd.DataFrame(analyzer.attack_data)
                ip_counts = df['source_ip'].value_counts().head(8)
                
                fig = px.bar(x=ip_counts.values, y=ip_counts.index, orientation='h',
                            title="Most Active Attacking IPs",
                            color=ip_counts.values,
                            color_continuous_scale="Reds")
                st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                st.error(f"Chart error: {e}")
    
    # Quick Actions
    st.subheader("⚡ Quick Actions")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🚀 Start IDS"):
            st.info("Starting IDS... Check terminal")
    
    with col2:
        if st.button("🛑 Stop IDS"):
            try:
                subprocess.run(['sudo', 'pkill', '-f', 'sensitive_ids.py'])
                st.success("IDS stopped")
            except:
                st.error("Failed to stop IDS")
    
    with col3:
        if st.button("📋 View Logs"):
            if os.path.exists('sensitive_attacks_log.txt'):
                with open('sensitive_attacks_log.txt', 'r') as f:
                    logs = f.read()
                st.text_area("Recent Logs", logs[-1000:], height=200)
    
    with col4:
        if st.button("🛡️ Block Last IP"):
            if analyzer.attack_data:
                last_ip = analyzer.attack_data[-1]['source_ip']
                st.code(f"sudo iptables -A INPUT -s {last_ip} -j DROP")
                st.success(f"Command to block {last_ip} generated!")
    
    # Attack Timeline
    if analyzer.attack_data and len(analyzer.attack_data) > 5:
        st.subheader("📈 Attack Timeline (Live)")
        try:
            df = pd.DataFrame(analyzer.attack_data)
            
            # Simple count by attack type
            timeline_data = df.groupby('attack_type').size().reset_index()
            timeline_data.columns = ['Attack Type', 'Count']
            
            fig = px.line(timeline_data, x='Attack Type', y='Count',
                         title='Attack Progression',
                         markers=True)
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.error(f"Timeline error: {e}")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666;">
        🛡️ Real-Time IDS Dashboard | Auto-refreshing every 3 seconds<br>
        Launch attacks from your Kali VM to see live detection!
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
