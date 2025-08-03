#!/usr/bin/env python3
"""
🛡️ Professional IDS Dashboard - Dark Theme with Advanced Analytics
Styled like professional security monitoring dashboards
"""

import streamlit as st
import pandas as pd
import numpy as np
import json
import time
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import subprocess
import os
from collections import defaultdict, Counter
import random

# Page configuration
st.set_page_config(
    page_title="🛡️ Professional IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Auto-refresh every 5 seconds
st.markdown("""
<script>
    setTimeout(function(){
        window.location.reload();
    }, 5000);
</script>
""", unsafe_allow_html=True)

# Professional Dark Theme CSS
st.markdown("""
<style>
    /* Dark theme styling */
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
    }
    
    .main-header {
        font-size: 2.5rem;
        color: #00ff41;
        text-align: center;
        margin-bottom: 1rem;
        font-weight: bold;
        text-shadow: 0 0 10px #00ff41;
    }
    
    .metric-container {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
        padding: 1.5rem;
        border-radius: 15px;
        margin: 0.5rem;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        border: 1px solid rgba(255,255,255,0.1);
    }
    
    .alert-container {
        background: linear-gradient(135deg, #dc2626 0%, #ef4444 100%);
        padding: 1rem;
        border-radius: 10px;
        margin: 0.3rem 0;
        box-shadow: 0 4px 16px rgba(220,38,38,0.3);
        animation: pulse 2s infinite;
    }
    
    .success-container {
        background: linear-gradient(135deg, #059669 0%, #10b981 100%);
        padding: 1rem;
        border-radius: 10px;
        margin: 0.3rem 0;
        box-shadow: 0 4px 16px rgba(5,150,105,0.3);
    }
    
    .chart-container {
        background: rgba(30, 41, 59, 0.8);
        padding: 1rem;
        border-radius: 15px;
        margin: 0.5rem 0;
        border: 1px solid rgba(255,255,255,0.1);
        backdrop-filter: blur(10px);
    }
    
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
        margin: 1rem 0;
    }
    
    .live-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        background-color: #00ff41;
        border-radius: 50%;
        animation: blink 1s infinite;
        margin-right: 8px;
        box-shadow: 0 0 10px #00ff41;
    }
    
    @keyframes blink {
        0%, 50% { opacity: 1; }
        51%, 100% { opacity: 0.3; }
    }
    
    @keyframes pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.02); }
    }
    
    .sidebar .sidebar-content {
        background-color: #1e293b;
    }
    
    .timestamp {
        color: #64748b;
        font-size: 0.9rem;
        text-align: center;
        margin-bottom: 1rem;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #1e293b;
    }
    ::-webkit-scrollbar-thumb {
        background: #3b82f6;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)

class ProfessionalIDSAnalyzer:
    """Professional IDS Data Analyzer"""
    
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
                try:
                    with open(file, 'r') as f:
                        for line in f:
                            if line.strip():
                                self.parse_attack_line(line.strip())
                except Exception:
                    continue
    
    def parse_attack_line(self, line):
        """Parse attack log line"""
        try:
            parts = line.split(': ', 1)
            if len(parts) == 2:
                timestamp_str = parts[0]
                attack_info = parts[1]
                
                attack_data = {
                    'timestamp': timestamp_str,
                    'raw_info': attack_info,
                    'source_ip': self.extract_ip(attack_info),
                    'attack_type': self.extract_attack_type(attack_info),
                    'confidence': self.extract_confidence(attack_info),
                    'severity': self.calculate_severity(attack_info)
                }
                self.attack_data.append(attack_data)
        except Exception:
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
        return float(match.group(1)) if match else 0.0
    
    def calculate_severity(self, info):
        """Calculate attack severity"""
        if 'Flood' in info or 'packets/sec' in info:
            return 'CRITICAL'
        elif 'Port Scan' in info:
            return 'HIGH'
        elif 'Brute Force' in info:
            return 'HIGH'
        elif 'Stealth' in info:
            return 'MEDIUM'
        return 'LOW'

def create_timeline_chart(analyzer):
    """Create events over time chart"""
    if not analyzer.attack_data:
        return go.Figure()
    
    # Simulate timeline data
    times = []
    counts = []
    
    # Group attacks by time intervals
    time_groups = defaultdict(int)
    for attack in analyzer.attack_data[-50:]:  # Last 50 attacks
        try:
            # Simple grouping by minute
            time_groups[len(times)] += 1
            times.append(f"{17}:{30 + len(times) % 10}")
            counts.append(time_groups[len(times)-1])
        except:
            continue
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=times[-20:] if len(times) > 20 else times,
        y=counts[-20:] if len(counts) > 20 else counts,
        mode='lines+markers',
        fill='tonexty',
        line=dict(color='#00ff41', width=2),
        marker=dict(color='#00ff41', size=6),
        name='Attack Events'
    ))
    
    fig.update_layout(
        title="EVENTS OVER TIME",
        title_font=dict(color='white', size=14),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white'),
        xaxis=dict(
            gridcolor='rgba(255,255,255,0.1)',
            showgrid=True,
            zeroline=False
        ),
        yaxis=dict(
            gridcolor='rgba(255,255,255,0.1)',
            showgrid=True,
            zeroline=False
        ),
        height=300,
        margin=dict(l=40, r=40, t=40, b=40)
    )
    
    return fig

def create_attack_types_chart(analyzer):
    """Create attack types pie chart"""
    if not analyzer.attack_data:
        return go.Figure()
    
    attack_counts = Counter([a['attack_type'] for a in analyzer.attack_data])
    
    fig = go.Figure(data=[go.Pie(
        labels=list(attack_counts.keys()),
        values=list(attack_counts.values()),
        hole=0.6,
        marker=dict(
            colors=['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6'],
            line=dict(color='#000000', width=2)
        )
    )])
    
    fig.update_layout(
        title="EVENT TYPES",
        title_font=dict(color='white', size=14),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white'),
        height=300,
        margin=dict(l=40, r=40, t=40, b=40),
        showlegend=True,
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=1.05
        )
    )
    
    return fig

def create_severity_chart(analyzer):
    """Create severity distribution chart"""
    if not analyzer.attack_data:
        return go.Figure()
    
    severity_counts = Counter([a['severity'] for a in analyzer.attack_data])
    
    colors = {
        'CRITICAL': '#dc2626',
        'HIGH': '#ea580c', 
        'MEDIUM': '#ca8a04',
        'LOW': '#16a34a'
    }
    
    fig = go.Figure(data=[go.Bar(
        x=list(severity_counts.keys()),
        y=list(severity_counts.values()),
        marker_color=[colors.get(k, '#3b82f6') for k in severity_counts.keys()]
    )])
    
    fig.update_layout(
        title="THREAT LEVELS",
        title_font=dict(color='white', size=14),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white'),
        xaxis=dict(gridcolor='rgba(255,255,255,0.1)'),
        yaxis=dict(gridcolor='rgba(255,255,255,0.1)'),
        height=300,
        margin=dict(l=40, r=40, t=40, b=40)
    )
    
    return fig

def create_confidence_chart(analyzer):
    """Create ML confidence distribution"""
    if not analyzer.attack_data:
        return go.Figure()
    
    confidences = [a['confidence'] for a in analyzer.attack_data if a['confidence'] > 0]
    
    fig = go.Figure(data=[go.Histogram(
        x=confidences,
        nbinsx=10,
        marker_color='#3b82f6',
        opacity=0.8
    )])
    
    fig.update_layout(
        title="ML CONFIDENCE",
        title_font=dict(color='white', size=14),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white'),
        xaxis=dict(
            title="Confidence %",
            gridcolor='rgba(255,255,255,0.1)'
        ),
        yaxis=dict(
            title="Count",
            gridcolor='rgba(255,255,255,0.1)'
        ),
        height=300,
        margin=dict(l=40, r=40, t=40, b=40)
    )
    
    return fig

def create_ip_analysis_chart(analyzer):
    """Create top IPs chart"""
    if not analyzer.attack_data:
        return go.Figure()
    
    ip_counts = Counter([a['source_ip'] for a in analyzer.attack_data])
    top_ips = dict(ip_counts.most_common(8))
    
    fig = go.Figure(data=[go.Bar(
        y=list(top_ips.keys()),
        x=list(top_ips.values()),
        orientation='h',
        marker_color='#ef4444'
    )])
    
    fig.update_layout(
        title="TOP ATTACKING IPs",
        title_font=dict(color='white', size=14),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white'),
        xaxis=dict(gridcolor='rgba(255,255,255,0.1)'),
        yaxis=dict(gridcolor='rgba(255,255,255,0.1)'),
        height=300,
        margin=dict(l=40, r=40, t=40, b=40)
    )
    
    return fig

def main():
    # Header
    st.markdown('''
    <div class="main-header">
        <span class="live-indicator"></span>
        🛡️ PROFESSIONAL IDS SECURITY DASHBOARD
    </div>
    ''', unsafe_allow_html=True)
    
    # Timestamp
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    st.markdown(f'<div class="timestamp">Last Updated: {current_time} | Auto-refresh: 5s</div>', 
                unsafe_allow_html=True)
    
    # Initialize analyzer
    analyzer = ProfessionalIDSAnalyzer()
    
    # Top metrics row
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        total_attacks = len(analyzer.attack_data)
        st.markdown(f'''
        <div class="metric-container">
            <h3 style="margin:0; color:#00ff41;">TOTAL EVENTS</h3>
            <h1 style="margin:0; font-size:2.5rem;">{total_attacks}</h1>
        </div>
        ''', unsafe_allow_html=True)
    
    with col2:
        critical_attacks = len([a for a in analyzer.attack_data if a.get('severity') == 'CRITICAL'])
        st.markdown(f'''
        <div class="metric-container">
            <h3 style="margin:0; color:#ef4444;">CRITICAL</h3>
            <h1 style="margin:0; font-size:2.5rem;">{critical_attacks}</h1>
        </div>
        ''', unsafe_allow_html=True)
    
    with col3:
        unique_ips = len(set([a['source_ip'] for a in analyzer.attack_data]))
        st.markdown(f'''
        <div class="metric-container">
            <h3 style="margin:0; color:#f97316;">UNIQUE IPs</h3>
            <h1 style="margin:0; font-size:2.5rem;">{unique_ips}</h1>
        </div>
        ''', unsafe_allow_html=True)
    
    with col4:
        avg_confidence = np.mean([a['confidence'] for a in analyzer.attack_data]) if analyzer.attack_data else 0
        st.markdown(f'''
        <div class="metric-container">
            <h3 style="margin:0; color:#22c55e;">AVG CONFIDENCE</h3>
            <h1 style="margin:0; font-size:2.5rem;">{avg_confidence:.0f}%</h1>
        </div>
        ''', unsafe_allow_html=True)
    
    with col5:
        # Check IDS status
        try:
            result = subprocess.run(['pgrep', '-f', 'sensitive_ids.py'], 
                                  capture_output=True, text=True)
            ids_status = "ONLINE" if result.stdout.strip() else "OFFLINE"
            status_color = "#22c55e" if ids_status == "ONLINE" else "#ef4444"
        except:
            ids_status = "UNKNOWN"
            status_color = "#f97316"
        
        st.markdown(f'''
        <div class="metric-container">
            <h3 style="margin:0; color:{status_color};">IDS STATUS</h3>
            <h1 style="margin:0; font-size:1.8rem;">{ids_status}</h1>
        </div>
        ''', unsafe_allow_html=True)
    
    # Main charts grid
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        timeline_fig = create_timeline_chart(analyzer)
        st.plotly_chart(timeline_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        attack_types_fig = create_attack_types_chart(analyzer)
        st.plotly_chart(attack_types_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        severity_fig = create_severity_chart(analyzer)
        st.plotly_chart(severity_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Second row of charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        confidence_fig = create_confidence_chart(analyzer)
        st.plotly_chart(confidence_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        ip_fig = create_ip_analysis_chart(analyzer)
        st.plotly_chart(ip_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Alerts section
    st.markdown("### 🚨 LIVE ALERTS")
    
    if analyzer.attack_data:
        recent_attacks = analyzer.attack_data[-5:]  # Last 5 attacks
        for attack in reversed(recent_attacks):
            severity_color = {
                'CRITICAL': '#dc2626',
                'HIGH': '#ea580c',
                'MEDIUM': '#ca8a04', 
                'LOW': '#16a34a'
            }.get(attack.get('severity', 'LOW'), '#3b82f6')
            
            st.markdown(f'''
            <div class="alert-container" style="background: linear-gradient(135deg, {severity_color}aa 0%, {severity_color} 100%);">
                <strong>{attack['attack_type']}</strong> | 
                <code>{attack['source_ip']}</code> | 
                Confidence: {attack['confidence']:.1f}% | 
                Severity: {attack.get('severity', 'UNKNOWN')} |
                <small>{attack['timestamp']}</small>
            </div>
            ''', unsafe_allow_html=True)
    else:
        st.markdown('''
        <div class="success-container">
            <strong>🛡️ NO ACTIVE THREATS</strong><br>
            Your system is secure. Launch attacks from Kali VM to test detection.
        </div>
        ''', unsafe_allow_html=True)

if __name__ == "__main__":
    main()
