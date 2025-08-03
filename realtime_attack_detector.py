#!/usr/bin/env python3
"""
Enhanced Real-Time IDS with Attack Type Classification
Detects and classifies: Port Scans, DoS, DDoS, Brute Force, and more
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
import pickle
import tensorflow as tf
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import psutil
import socket
from pathlib import Path

# Expected features from your trained model
EXPECTED_FEATURES = [
    "Avg Packet Size", "Packet Length Mean", "Bwd Packet Length Std",
    "Packet Length Variance", "Bwd Packet Length Max", "Packet Length Max",
    "Packet Length Std", "Fwd Packet Length Mean", "Avg Fwd Segment Size",
    "Flow Bytes/s", "Avg Bwd Segment Size", "Bwd Packet Length Mean",
    "Fwd Packets/s", "Flow Packets/s", "Init Fwd Win Bytes",
    "Subflow Fwd Bytes", "Fwd Packets Length Total", "Fwd Act Data Packets",
    "Total Fwd Packets", "Subflow Fwd Packets"
]

class AttackTypeClassifier:
    """Classifies different types of network attacks"""
    
    def __init__(self):
        self.connection_tracker = defaultdict(lambda: {
            'ports': set(), 'packets': 0, 'bytes': 0, 'start_time': time.time(),
            'tcp_flags': [], 'protocols': set(), 'last_seen': time.time()
        })
        self.recent_packets = deque(maxlen=1000)
        
    def analyze_attack_pattern(self, packets, src_ip):
        """Analyze packets to determine attack type"""
        if not packets:
            return "Unknown Attack"
            
        # Update connection tracker
        conn_info = self.connection_tracker[src_ip]
        conn_info['last_seen'] = time.time()
        
        tcp_packets = []
        udp_packets = []
        icmp_packets = []
        unique_ports = set()
        tcp_flags = []
        
        for pkt in packets:
            if IP in pkt:
                # Track protocols
                if TCP in pkt:
                    tcp_packets.append(pkt)
                    unique_ports.add(pkt[TCP].dport)
                    # Extract TCP flags
                    flags = pkt[TCP].flags
                    tcp_flags.append(flags)
                    conn_info['tcp_flags'].append(flags)
                    
                elif UDP in pkt:
                    udp_packets.append(pkt)
                    unique_ports.add(pkt[UDP].dport)
                    
                elif ICMP in pkt:
                    icmp_packets.append(pkt)
        
        conn_info['ports'].update(unique_ports)
        conn_info['packets'] += len(packets)
        conn_info['bytes'] += sum(len(pkt) for pkt in packets)
        
        # Calculate rates
        time_window = time.time() - conn_info['start_time']
        packet_rate = conn_info['packets'] / max(time_window, 1)
        
        # Attack type classification
        attack_type = self.classify_attack_type(
            tcp_packets, udp_packets, icmp_packets, 
            unique_ports, tcp_flags, packet_rate, conn_info
        )
        
        return attack_type
    
    def classify_attack_type(self, tcp_pkts, udp_pkts, icmp_pkts, ports, tcp_flags, rate, conn_info):
        """Classify the specific attack type"""
        
        # Port Scan Detection
        if len(ports) > 10:  # Scanning multiple ports
            if len(tcp_pkts) > len(udp_pkts):
                return f"🔍 TCP Port Scan ({len(ports)} ports)"
            else:
                return f"🔍 UDP Port Scan ({len(ports)} ports)"
        
        # SYN Flood Detection
        syn_count = sum(1 for flag in tcp_flags if flag & 0x02)  # SYN flag
        if syn_count > 20 and rate > 50:
            return f"💥 SYN Flood Attack ({syn_count} SYN packets, {rate:.1f} pps)"
        
        # DoS Detection based on packet rate
        if rate > 100:
            if len(tcp_pkts) > 0:
                return f"💥 TCP DoS Attack ({rate:.1f} packets/sec)"
            elif len(udp_pkts) > 0:
                return f"💥 UDP DoS Attack ({rate:.1f} packets/sec)"
            else:
                return f"💥 DoS Attack ({rate:.1f} packets/sec)"
        
        # ICMP Flood
        if len(icmp_pkts) > 20 and rate > 30:
            return f"🧊 ICMP Flood Attack ({len(icmp_pkts)} ICMP packets)"
        
        # Brute Force Detection (many connections to same port)
        if len(conn_info['tcp_flags']) > 50:
            common_ports = Counter()
            # This is simplified - in real scenario you'd track destination ports
            if 22 in ports or 21 in ports or 23 in ports:
                return f"🔐 Brute Force Attack (SSH/FTP/Telnet)"
        
        # Stealth Scan Detection
        fin_count = sum(1 for flag in tcp_flags if flag & 0x01)  # FIN flag
        rst_count = sum(1 for flag in tcp_flags if flag & 0x04)  # RST flag
        if fin_count > 10 or rst_count > 10:
            return f"👤 Stealth Scan (FIN/RST packets)"
        
        # Generic suspicious activity
        if rate > 20:
            return f"⚠️ Suspicious Activity ({rate:.1f} packets/sec)"
        
        return "🚨 Network Attack Detected"

class EnhancedIDSMonitor:
    def __init__(self, model_path, scaler_path):
        print("🔧 Loading Enhanced IDS with Attack Classification...")
        self.model = tf.keras.models.load_model(model_path)
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
            
        self.interface = self.get_default_interface()
        self.packet_buffer = deque(maxlen=200)
        self.running = False
        self.attack_classifier = AttackTypeClassifier()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        print(f"✅ Enhanced IDS loaded successfully")
        print(f"🌐 Monitoring interface: {self.interface}")
        
    def get_default_interface(self):
        """Get default network interface"""
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.split()[4]
            return 'eth0'
        except:
            return 'eth0'
    
    def extract_enhanced_features(self, packets):
        """Extract features with enhanced analysis"""
        if not packets:
            return None
            
        # Basic packet statistics
        packet_lengths = [len(pkt) for pkt in packets]
        fwd_packets = []
        bwd_packets = []
        total_bytes = sum(packet_lengths)
        
        # Enhanced packet analysis
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        udp_packets = [pkt for pkt in packets if UDP in pkt]
        
        # Separate forward and backward packets (enhanced logic)
        src_ips = {}
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                if src_ip not in src_ips:
                    src_ips[src_ip] = 0
                src_ips[src_ip] += 1
        
        # Determine primary source (attacker)
        if src_ips:
            primary_src = max(src_ips, key=src_ips.get)
            for pkt in packets:
                if IP in pkt:
                    if pkt[IP].src == primary_src:
                        fwd_packets.append(len(pkt))
                    else:
                        bwd_packets.append(len(pkt))
        
        if not packet_lengths:
            return None
            
        # Calculate enhanced features
        features = {}
        
        # Packet size statistics
        features["Avg Packet Size"] = np.mean(packet_lengths)
        features["Packet Length Mean"] = np.mean(packet_lengths)
        features["Packet Length Max"] = np.max(packet_lengths)
        features["Packet Length Std"] = np.std(packet_lengths) if len(packet_lengths) > 1 else 0
        features["Packet Length Variance"] = np.var(packet_lengths) if len(packet_lengths) > 1 else 0
        
        # Forward packet statistics
        if fwd_packets:
            features["Fwd Packet Length Mean"] = np.mean(fwd_packets)
            features["Avg Fwd Segment Size"] = np.mean(fwd_packets)
            features["Fwd Packets Length Total"] = sum(fwd_packets)
            features["Total Fwd Packets"] = len(fwd_packets)
            features["Fwd Act Data Packets"] = len([p for p in fwd_packets if p > 60])
            features["Subflow Fwd Packets"] = len(fwd_packets)
            features["Subflow Fwd Bytes"] = sum(fwd_packets)
        else:
            features["Fwd Packet Length Mean"] = 0
            features["Avg Fwd Segment Size"] = 0
            features["Fwd Packets Length Total"] = 0
            features["Total Fwd Packets"] = 0
            features["Fwd Act Data Packets"] = 0
            features["Subflow Fwd Packets"] = 0
            features["Subflow Fwd Bytes"] = 0
        
        # Backward packet statistics
        if bwd_packets:
            features["Bwd Packet Length Mean"] = np.mean(bwd_packets)
            features["Bwd Packet Length Max"] = np.max(bwd_packets)
            features["Bwd Packet Length Std"] = np.std(bwd_packets) if len(bwd_packets) > 1 else 0
            features["Avg Bwd Segment Size"] = np.mean(bwd_packets)
        else:
            features["Bwd Packet Length Mean"] = 0
            features["Bwd Packet Length Max"] = 0
            features["Bwd Packet Length Std"] = 0
            features["Avg Bwd Segment Size"] = 0
        
        # Enhanced flow statistics
        duration = 3.0  # 3 second window for faster detection
        features["Flow Bytes/s"] = total_bytes / duration
        features["Flow Packets/s"] = len(packets) / duration
        features["Fwd Packets/s"] = len(fwd_packets) / duration
        
        # TCP Window size (enhanced)
        if tcp_packets:
            features["Init Fwd Win Bytes"] = tcp_packets[0][TCP].window if tcp_packets else 8192
        else:
            features["Init Fwd Win Bytes"] = 8192
        
        return features
    
    def packet_handler(self, packet):
        """Handle captured packets with enhanced analysis"""
        self.packet_buffer.append(packet)
        
        # Add to classifier's recent packets
        self.attack_classifier.recent_packets.append(packet)
    
    def predict_attack(self, features_dict):
        """Make prediction using the trained model"""
        try:
            # Create feature vector in correct order
            feature_vector = []
            for feature_name in EXPECTED_FEATURES:
                feature_vector.append(features_dict.get(feature_name, 0))
            
            # Convert to DataFrame for scaler
            feature_df = pd.DataFrame([feature_vector], columns=EXPECTED_FEATURES)
            
            # Scale features
            scaled_features = self.scaler.transform(feature_df)
            
            # Make prediction
            prediction = self.model.predict(scaled_features, verbose=0)
            confidence = float(prediction[0][0])
            
            return confidence
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return 0.0
    
    def detection_loop(self):
        """Enhanced detection loop with attack classification"""
        print("🔍 Starting enhanced attack detection and classification...")
        
        while self.running:
            try:
                if len(self.packet_buffer) >= 15:  # Analyze with more packets for better classification
                    # Get recent packets
                    recent_packets = list(self.packet_buffer)
                    
                    # Extract features
                    features = self.extract_enhanced_features(recent_packets)
                    
                    if features:
                        # Make prediction
                        confidence = self.predict_attack(features)
                        
                        # Check if attack detected (lowered threshold for more sensitivity)
                        if confidence > 0.3:
                            # Get source IP
                            src_ip = "Unknown"
                            if recent_packets and IP in recent_packets[-1]:
                                src_ip = recent_packets[-1][IP].src
                            
                            # Classify attack type
                            attack_type = self.attack_classifier.analyze_attack_pattern(recent_packets, src_ip)
                            
                            # Enhanced attack display
                            print("=" * 80)
                            print(f"🚨 ATTACK DETECTED FROM KALI VM!")
                            print(f"   Attack Type: {attack_type}")
                            print(f"   Source IP: {src_ip}")
                            print(f"   ML Confidence: {confidence:.2%}")
                            print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                            print(f"   Packets Analyzed: {len(recent_packets)}")
                            
                            # Additional attack details
                            tcp_count = len([p for p in recent_packets if TCP in p])
                            udp_count = len([p for p in recent_packets if UDP in p])
                            icmp_count = len([p for p in recent_packets if ICMP in p])
                            
                            print(f"   Protocol Distribution:")
                            if tcp_count > 0:
                                print(f"     - TCP: {tcp_count} packets")
                            if udp_count > 0:
                                print(f"     - UDP: {udp_count} packets")
                            if icmp_count > 0:
                                print(f"     - ICMP: {icmp_count} packets")
                            
                            print("=" * 80)
                            
                            # Log to file with enhanced details
                            with open('detailed_attack_log.txt', 'a') as f:
                                f.write(f"{datetime.now()}: {attack_type} from {src_ip} "
                                       f"(ML confidence: {confidence:.2%}, "
                                       f"TCP:{tcp_count}, UDP:{udp_count}, ICMP:{icmp_count})\n")
                    
                    # Clear buffer more frequently for real-time detection
                    self.packet_buffer.clear()
                
                time.sleep(1)  # Check every second for faster response
                
            except Exception as e:
                self.logger.error(f"Detection loop error: {e}")
                time.sleep(1)
    
    def start_monitoring(self):
        """Start the enhanced IDS monitoring"""
        print("🚀 Starting Enhanced IDS with Attack Type Classification...")
        self.running = True
        
        # Start detection loop in separate thread
        detection_thread = threading.Thread(target=self.detection_loop)
        detection_thread.daemon = True
        detection_thread.start()
        
        # Start packet capture
        print(f"📡 Starting packet capture on {self.interface}...")
        print("🎯 Ready to detect and classify attacks from your Kali VM!")
        print("   - Port Scans (TCP/UDP)")
        print("   - DoS/DDoS Attacks")
        print("   - SYN Flood Attacks")
        print("   - ICMP Floods")
        print("   - Brute Force Attempts")
        print("   - Stealth Scans")
        print()
        
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n🛑 Stopping Enhanced IDS...")
            self.running = False
        except Exception as e:
            print(f"❌ Capture error: {e}")
            print("💡 Try running with sudo or check interface name")

def main():
    print("=" * 80)
    print("🛡️  ENHANCED IDS - REAL-TIME ATTACK DETECTION & CLASSIFICATION")
    print("🎯 Detects: Port Scans | DoS | DDoS | Brute Force | Stealth Scans")
    print("=" * 80)
    
    # Configuration
    MODEL_PATH = "enhanced_ids_model_99percent.h5"
    SCALER_PATH = "feature_scaler.pkl"
    
    # Check files exist
    if not os.path.exists(MODEL_PATH):
        print(f"❌ Model not found: {MODEL_PATH}")
        return
        
    if not os.path.exists(SCALER_PATH):
        print(f"❌ Scaler not found: {SCALER_PATH}")
        return
    
    try:
        # Create and start enhanced IDS
        ids = EnhancedIDSMonitor(MODEL_PATH, SCALER_PATH)
        
        print("✅ Enhanced IDS initialized successfully")
        print("🔍 Ready to detect and classify attacks from your Kali VM...")
        print("💡 Press Ctrl+C to stop")
        print()
        
        ids.start_monitoring()
        
    except KeyboardInterrupt:
        print("\n✅ Enhanced IDS stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
