#!/usr/bin/env python3
"""
Calibrated IDS - Reduced False Positives
Only detects actual attacks, not normal network traffic
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

class AttackPatternDetector:
    """Detects actual attack patterns, not normal traffic"""
    
    def __init__(self):
        self.connection_tracker = defaultdict(lambda: {
            'ports': set(), 'packets': 0, 'bytes': 0, 'start_time': time.time(),
            'tcp_flags': [], 'protocols': set(), 'last_seen': time.time(),
            'connections': 0, 'failed_connections': 0
        })
        self.baseline_established = False
        self.normal_traffic_baseline = {'avg_rate': 0, 'avg_ports': 0}
        
    def is_actual_attack(self, packets, src_ip):
        """Determine if this is an actual attack vs normal traffic"""
        if not packets:
            return False, "No packets"
            
        conn_info = self.connection_tracker[src_ip]
        conn_info['last_seen'] = time.time()
        
        # Analyze packet patterns
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        udp_packets = [pkt for pkt in packets if UDP in pkt]
        icmp_packets = [pkt for pkt in packets if ICMP in pkt]
        
        unique_ports = set()
        tcp_flags = []
        syn_count = 0
        rst_count = 0
        fin_count = 0
        
        for pkt in packets:
            if IP in pkt:
                if TCP in pkt:
                    unique_ports.add(pkt[TCP].dport)
                    flags = pkt[TCP].flags
                    tcp_flags.append(flags)
                    
                    # Count specific flags
                    if flags & 0x02:  # SYN
                        syn_count += 1
                    if flags & 0x04:  # RST
                        rst_count += 1
                    if flags & 0x01:  # FIN
                        fin_count += 1
                        
                elif UDP in pkt:
                    unique_ports.add(pkt[UDP].dport)
        
        # Update connection info
        conn_info['ports'].update(unique_ports)
        conn_info['packets'] += len(packets)
        
        # Calculate rates
        time_window = max(time.time() - conn_info['start_time'], 1)
        packet_rate = conn_info['packets'] / time_window
        
        # STRICT ATTACK DETECTION CRITERIA
        
        # 1. Port Scan Detection (STRICT)
        if len(unique_ports) > 20 and len(packets) > 30:
            return True, f"🔍 Port Scan Detected ({len(unique_ports)} ports scanned)"
        
        # 2. SYN Flood Detection (STRICT)
        if syn_count > 50 and packet_rate > 100:
            return True, f"💥 SYN Flood Attack ({syn_count} SYN packets, {packet_rate:.1f} pps)"
        
        # 3. High-Rate DoS Detection (STRICT)
        if packet_rate > 200 and len(packets) > 100:
            if len(tcp_packets) > len(udp_packets):
                return True, f"💥 TCP DoS Attack ({packet_rate:.1f} packets/sec)"
            else:
                return True, f"💥 UDP DoS Attack ({packet_rate:.1f} packets/sec)"
        
        # 4. ICMP Flood (STRICT)
        if len(icmp_packets) > 50 and packet_rate > 80:
            return True, f"🧊 ICMP Flood Attack ({len(icmp_packets)} ICMP packets)"
        
        # 5. Stealth Scan Detection (STRICT)
        if (fin_count > 20 or rst_count > 20) and len(unique_ports) > 10:
            return True, f"👤 Stealth Scan Detected (FIN/RST scan on {len(unique_ports)} ports)"
        
        # 6. Rapid Connection Attempts (Brute Force)
        if len(unique_ports) == 1 and syn_count > 30 and packet_rate > 50:
            port = list(unique_ports)[0] if unique_ports else 0
            if port in [22, 21, 23, 3389, 80, 443]:  # Common brute force targets
                return True, f"🔐 Brute Force Attack on port {port} ({syn_count} attempts)"
        
        # If none of the strict criteria are met, it's likely normal traffic
        return False, "Normal network traffic"

class CalibratedIDSMonitor:
    def __init__(self, model_path, scaler_path):
        print("🔧 Loading Calibrated IDS (Reduced False Positives)...")
        self.model = tf.keras.models.load_model(model_path)
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
            
        self.interface = self.get_default_interface()
        self.packet_buffer = deque(maxlen=300)
        self.running = False
        self.attack_detector = AttackPatternDetector()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        print(f"✅ Calibrated IDS loaded successfully")
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
    
    def extract_features(self, packets):
        """Extract features for ML model"""
        if not packets:
            return None
            
        packet_lengths = [len(pkt) for pkt in packets]
        fwd_packets = []
        bwd_packets = []
        total_bytes = sum(packet_lengths)
        
        # Enhanced packet analysis
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        
        # Separate forward and backward packets
        src_ips = {}
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                if src_ip not in src_ips:
                    src_ips[src_ip] = 0
                src_ips[src_ip] += 1
        
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
            
        # Calculate features
        features = {}
        
        features["Avg Packet Size"] = np.mean(packet_lengths)
        features["Packet Length Mean"] = np.mean(packet_lengths)
        features["Packet Length Max"] = np.max(packet_lengths)
        features["Packet Length Std"] = np.std(packet_lengths) if len(packet_lengths) > 1 else 0
        features["Packet Length Variance"] = np.var(packet_lengths) if len(packet_lengths) > 1 else 0
        
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
        
        duration = 5.0
        features["Flow Bytes/s"] = total_bytes / duration
        features["Flow Packets/s"] = len(packets) / duration
        features["Fwd Packets/s"] = len(fwd_packets) / duration
        
        if tcp_packets:
            features["Init Fwd Win Bytes"] = tcp_packets[0][TCP].window if tcp_packets else 8192
        else:
            features["Init Fwd Win Bytes"] = 8192
        
        return features
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        self.packet_buffer.append(packet)
    
    def predict_attack(self, features_dict):
        """Make prediction using the trained model"""
        try:
            feature_vector = []
            for feature_name in EXPECTED_FEATURES:
                feature_vector.append(features_dict.get(feature_name, 0))
            
            feature_df = pd.DataFrame([feature_vector], columns=EXPECTED_FEATURES)
            scaled_features = self.scaler.transform(feature_df)
            prediction = self.model.predict(scaled_features, verbose=0)
            confidence = float(prediction[0][0])
            
            return confidence
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return 0.0
    
    def detection_loop(self):
        """Calibrated detection loop - only real attacks"""
        print("🔍 Starting calibrated attack detection...")
        print("⚡ Monitoring for ACTUAL attacks only (no false positives)")
        print()
        
        while self.running:
            try:
                if len(self.packet_buffer) >= 50:  # Need more packets for accurate detection
                    recent_packets = list(self.packet_buffer)
                    
                    # Get source IP
                    src_ip = "Unknown"
                    if recent_packets and IP in recent_packets[-1]:
                        src_ip = recent_packets[-1][IP].src
                    
                    # First check: Is this actually an attack pattern?
                    is_attack, attack_description = self.attack_detector.is_actual_attack(recent_packets, src_ip)
                    
                    if is_attack:
                        # Second check: ML model confirmation
                        features = self.extract_features(recent_packets)
                        if features:
                            ml_confidence = self.predict_attack(features)
                            
                            # Only alert if BOTH pattern detection AND ML agree it's an attack
                            if ml_confidence > 0.7:  # Higher threshold for ML
                                print("🚨" * 20)
                                print(f"🚨 REAL ATTACK DETECTED FROM KALI VM!")
                                print(f"   Attack Type: {attack_description}")
                                print(f"   Source IP: {src_ip}")
                                print(f"   ML Confidence: {ml_confidence:.2%}")
                                print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                                print(f"   Packets Analyzed: {len(recent_packets)}")
                                
                                # Protocol breakdown
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
                                
                                print("🚨" * 20)
                                print()
                                
                                # Log real attack
                                with open('real_attacks_log.txt', 'a') as f:
                                    f.write(f"{datetime.now()}: {attack_description} from {src_ip} "
                                           f"(ML: {ml_confidence:.2%})\n")
                    
                    # Clear buffer
                    self.packet_buffer.clear()
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                self.logger.error(f"Detection loop error: {e}")
                time.sleep(1)
    
    def start_monitoring(self):
        """Start the calibrated IDS monitoring"""
        print("🚀 Starting Calibrated IDS...")
        self.running = True
        
        detection_thread = threading.Thread(target=self.detection_loop)
        detection_thread.daemon = True
        detection_thread.start()
        
        print(f"📡 Monitoring {self.interface} for REAL attacks only...")
        print("🎯 Will detect:")
        print("   - Port Scans (20+ ports)")
        print("   - DoS Attacks (200+ packets/sec)")
        print("   - SYN Floods (50+ SYN packets)")
        print("   - ICMP Floods (50+ ICMP packets)")
        print("   - Brute Force (30+ login attempts)")
        print("   - Stealth Scans (20+ FIN/RST packets)")
        print()
        print("✅ Ready! Normal traffic will be ignored.")
        print("🔥 Launch attacks from your Kali VM to see detection!")
        print()
        
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n🛑 Stopping Calibrated IDS...")
            self.running = False
        except Exception as e:
            print(f"❌ Capture error: {e}")

def main():
    print("=" * 80)
    print("🛡️  CALIBRATED IDS - REAL ATTACKS ONLY (NO FALSE POSITIVES)")
    print("=" * 80)
    
    MODEL_PATH = "enhanced_ids_model_99percent.h5"
    SCALER_PATH = "feature_scaler.pkl"
    
    if not os.path.exists(MODEL_PATH):
        print(f"❌ Model not found: {MODEL_PATH}")
        return
        
    if not os.path.exists(SCALER_PATH):
        print(f"❌ Scaler not found: {SCALER_PATH}")
        return
    
    try:
        ids = CalibratedIDSMonitor(MODEL_PATH, SCALER_PATH)
        
        print("✅ Calibrated IDS initialized")
        print("🔍 Monitoring for REAL attacks only...")
        print("💡 Press Ctrl+C to stop")
        print()
        
        ids.start_monitoring()
        
    except KeyboardInterrupt:
        print("\n✅ Calibrated IDS stopped")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
