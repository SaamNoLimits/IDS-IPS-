#!/usr/bin/env python3
"""
Fixed IDS Runner with correct feature alignment
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
from collections import defaultdict, deque
import pickle
import tensorflow as tf
from scapy.all import sniff, IP, TCP, UDP, ICMP
import psutil
import socket
from pathlib import Path

# Expected features from your trained model
EXPECTED_FEATURES = [
    "Avg Packet Size",
    "Packet Length Mean", 
    "Bwd Packet Length Std",
    "Packet Length Variance",
    "Bwd Packet Length Max",
    "Packet Length Max",
    "Packet Length Std",
    "Fwd Packet Length Mean",
    "Avg Fwd Segment Size",
    "Flow Bytes/s",
    "Avg Bwd Segment Size", 
    "Bwd Packet Length Mean",
    "Fwd Packets/s",
    "Flow Packets/s",
    "Init Fwd Win Bytes",
    "Subflow Fwd Bytes",
    "Fwd Packets Length Total",
    "Fwd Act Data Packets",
    "Total Fwd Packets",
    "Subflow Fwd Packets"
]

class SimpleIDSMonitor:
    def __init__(self, model_path, scaler_path):
        print("🔧 Loading IDS model and scaler...")
        self.model = tf.keras.models.load_model(model_path)
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
            
        self.interface = self.get_default_interface()
        self.packet_buffer = deque(maxlen=100)
        self.running = False
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        print(f"✅ Model loaded successfully")
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
    
    def extract_simple_features(self, packets):
        """Extract features matching the trained model"""
        if not packets:
            return None
            
        # Basic packet statistics
        packet_lengths = [len(pkt) for pkt in packets]
        fwd_packets = []
        bwd_packets = []
        total_bytes = sum(packet_lengths)
        
        # Separate forward and backward packets (simplified)
        for pkt in packets:
            if IP in pkt:
                if len(fwd_packets) <= len(bwd_packets):
                    fwd_packets.append(len(pkt))
                else:
                    bwd_packets.append(len(pkt))
        
        if not packet_lengths:
            return None
            
        # Calculate features to match expected names
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
            features["Fwd Act Data Packets"] = len([p for p in fwd_packets if p > 60])  # Data packets
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
        
        # Flow statistics (simplified)
        duration = 5.0  # 5 second window
        features["Flow Bytes/s"] = total_bytes / duration
        features["Flow Packets/s"] = len(packets) / duration
        features["Fwd Packets/s"] = len(fwd_packets) / duration
        
        # TCP Window size (simplified)
        features["Init Fwd Win Bytes"] = 8192  # Default TCP window
        
        return features
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        self.packet_buffer.append(packet)
    
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
        """Main detection loop"""
        print("🔍 Starting attack detection loop...")
        
        while self.running:
            try:
                if len(self.packet_buffer) >= 10:  # Analyze when we have enough packets
                    # Get recent packets
                    recent_packets = list(self.packet_buffer)
                    
                    # Extract features
                    features = self.extract_simple_features(recent_packets)
                    
                    if features:
                        # Make prediction
                        confidence = self.predict_attack(features)
                        
                        # Check if attack detected (threshold: 0.5)
                        if confidence > 0.5:
                            src_ip = "Unknown"
                            if recent_packets and IP in recent_packets[-1]:
                                src_ip = recent_packets[-1][IP].src
                            
                            print(f"🚨 ATTACK DETECTED!")
                            print(f"   Source IP: {src_ip}")
                            print(f"   Confidence: {confidence:.2%}")
                            print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                            print(f"   Packets analyzed: {len(recent_packets)}")
                            print("-" * 60)
                            
                            # Log to file
                            with open('attack_log.txt', 'a') as f:
                                f.write(f"{datetime.now()}: Attack from {src_ip} (confidence: {confidence:.2%})\n")
                    
                    # Clear old packets
                    self.packet_buffer.clear()
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                self.logger.error(f"Detection loop error: {e}")
                time.sleep(1)
    
    def start_monitoring(self):
        """Start the IDS monitoring"""
        print("🚀 Starting IDS monitoring...")
        self.running = True
        
        # Start detection loop in separate thread
        detection_thread = threading.Thread(target=self.detection_loop)
        detection_thread.daemon = True
        detection_thread.start()
        
        # Start packet capture
        print(f"📡 Starting packet capture on {self.interface}...")
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n🛑 Stopping IDS...")
            self.running = False
        except Exception as e:
            print(f"❌ Capture error: {e}")
            print("💡 Try running with sudo or check interface name")

def main():
    print("=" * 80)
    print("🛡️  SIMPLIFIED IDS ATTACK DETECTION SYSTEM")
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
        # Create and start IDS
        ids = SimpleIDSMonitor(MODEL_PATH, SCALER_PATH)
        
        print("✅ IDS initialized successfully")
        print("🔍 Monitoring for attacks from your Kali VM...")
        print("💡 Press Ctrl+C to stop")
        print()
        
        ids.start_monitoring()
        
    except KeyboardInterrupt:
        print("\n✅ IDS stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
