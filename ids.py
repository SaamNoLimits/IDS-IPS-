#!/usr/bin/env python3
"""
Real-Time IDS Pipeline with Attack Detection and Response
Monitors network traffic, detects attacks, and provides blocking rules
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

class NetworkTrafficCapture:
    """Captures and processes network traffic in real-time"""
    
    def __init__(self, interface=None):
        self.interface = interface or self.get_default_interface()
        self.packet_buffer = deque(maxlen=1000)
        self.flow_tracker = defaultdict(dict)
        self.capture_active = False
        
    def get_default_interface(self):
        """Get default network interface"""
        try:
            # Get default route interface
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.split()[4]
            return 'eth0'  # fallback
        except:
            return 'eth0'
    
    def extract_flow_features(self, packets):
        """Extract network flow features from packets"""
        if not packets:
            return None
            
        flows = defaultdict(lambda: {
            'packets': [], 'bytes': 0, 'start_time': None, 'end_time': None,
            'src_ip': None, 'dst_ip': None, 'src_port': None, 'dst_port': None,
            'protocol': None, 'fwd_packets': 0, 'bwd_packets': 0,
            'fwd_bytes': 0, 'bwd_bytes': 0, 'packet_lengths': []
        })
        
        for pkt in packets:
            if IP in pkt:
                ip_layer = pkt[IP]
                
                # Create flow key
                if TCP in pkt or UDP in pkt:
                    transport = pkt[TCP] if TCP in pkt else pkt[UDP]
                    flow_key = f"{ip_layer.src}:{transport.sport}-{ip_layer.dst}:{transport.dport}"
                    reverse_key = f"{ip_layer.dst}:{transport.dport}-{ip_layer.src}:{transport.sport}"
                    
                    # Use existing flow or create new
                    if flow_key in flows:
                        current_flow = flows[flow_key]
                    elif reverse_key in flows:
                        current_flow = flows[reverse_key]
                        flow_key = reverse_key
                    else:
                        current_flow = flows[flow_key]
                        current_flow['src_ip'] = ip_layer.src
                        current_flow['dst_ip'] = ip_layer.dst
                        current_flow['src_port'] = transport.sport
                        current_flow['dst_port'] = transport.dport
                        current_flow['protocol'] = 'TCP' if TCP in pkt else 'UDP'
                        current_flow['start_time'] = time.time()
                    
                    # Update flow statistics
                    packet_size = len(pkt)
                    current_flow['packets'].append(pkt)
                    current_flow['bytes'] += packet_size
                    current_flow['packet_lengths'].append(packet_size)
                    current_flow['end_time'] = time.time()
                    
                    # Determine direction
                    if (ip_layer.src == current_flow['src_ip'] and 
                        transport.sport == current_flow['src_port']):
                        current_flow['fwd_packets'] += 1
                        current_flow['fwd_bytes'] += packet_size
                    else:
                        current_flow['bwd_packets'] += 1
                        current_flow['bwd_bytes'] += packet_size
        
        # Convert flows to feature vectors
        feature_vectors = []
        for flow_key, flow_data in flows.items():
            if len(flow_data['packets']) < 2:  # Skip single packet flows
                continue
                
            duration = flow_data['end_time'] - flow_data['start_time']
            duration = max(duration, 0.001)  # Avoid division by zero
            
            packet_lengths = flow_data['packet_lengths']
            total_packets = len(packet_lengths)
            
            features = {
                'Flow Duration': duration * 1000000,  # microseconds
                'Total Fwd Packets': flow_data['fwd_packets'],
                'Total Bwd Packets': flow_data['bwd_packets'],
                'Fwd Packets Length Total': flow_data['fwd_bytes'],
                'Bwd Packets Length Total': flow_data['bwd_bytes'],
                'Flow Bytes/s': flow_data['bytes'] / duration,
                'Flow Packets/s': total_packets / duration,
                'Fwd Packets/s': flow_data['fwd_packets'] / duration,
                'Bwd Packets/s': flow_data['bwd_packets'] / duration,
                'Packet Length Mean': np.mean(packet_lengths) if packet_lengths else 0,
                'Packet Length Std': np.std(packet_lengths) if len(packet_lengths) > 1 else 0,
                'Packet Length Variance': np.var(packet_lengths) if packet_lengths else 0,
                'Packet Length Max': max(packet_lengths) if packet_lengths else 0,
                'Fwd Packet Length Mean': flow_data['fwd_bytes'] / max(flow_data['fwd_packets'], 1),
                'Bwd Packet Length Mean': flow_data['bwd_bytes'] / max(flow_data['bwd_packets'], 1),
                'Fwd Packet Length Max': flow_data['fwd_bytes'] if flow_data['fwd_packets'] > 0 else 0,
                'Bwd Packet Length Max': flow_data['bwd_bytes'] if flow_data['bwd_packets'] > 0 else 0,
                'Fwd Packet Length Std': 0,  # Simplified for real-time
                'Bwd Packet Length Std': 0,  # Simplified for real-time
                'Avg Packet Size': np.mean(packet_lengths) if packet_lengths else 0,
                'Avg Fwd Segment Size': flow_data['fwd_bytes'] / max(flow_data['fwd_packets'], 1),
                'Avg Bwd Segment Size': flow_data['bwd_bytes'] / max(flow_data['bwd_packets'], 1),
                # Add metadata
                'src_ip': flow_data['src_ip'],
                'dst_ip': flow_data['dst_ip'],
                'src_port': flow_data['src_port'],
                'dst_port': flow_data['dst_port'],
                'protocol': flow_data['protocol'],
                'timestamp': flow_data['end_time']
            }
            
            feature_vectors.append(features)
        
        return feature_vectors
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        self.packet_buffer.append(packet)
    
    def start_capture(self):
        """Start packet capture"""
        self.capture_active = True
        print(f"Starting packet capture on interface: {self.interface}")
        try:
            sniff(iface=self.interface, prn=self.packet_handler, 
                  stop_filter=lambda x: not self.capture_active,
                  store=False)
        except Exception as e:
            print(f"Error in packet capture: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False
    
    def get_recent_flows(self, window_seconds=5):
        """Get flows from recent packets"""
        current_time = time.time()
        recent_packets = []
        
        # Get packets from the last window_seconds
        temp_buffer = list(self.packet_buffer)
        for pkt in temp_buffer:
            if hasattr(pkt, 'time') and (current_time - pkt.time) <= window_seconds:
                recent_packets.append(pkt)
        
        return self.extract_flow_features(recent_packets)

class IDSModel:
    """IDS Model wrapper for real-time detection"""
    
    def __init__(self, model_path, scaler_path=None):
        self.model = tf.keras.models.load_model(model_path)
        self.scaler = None
        self.class_names = ['Benign', 'DDoS', 'Bruteforce', 'Botnet']
        self.feature_names = [
            'Flow Duration', 'Total Fwd Packets', 'Total Bwd Packets',
            'Fwd Packets Length Total', 'Bwd Packets Length Total',
            'Flow Bytes/s', 'Flow Packets/s', 'Fwd Packets/s', 'Bwd Packets/s',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'Packet Length Max', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
            'Fwd Packet Length Max', 'Bwd Packet Length Max', 'Fwd Packet Length Std',
            'Bwd Packet Length Std', 'Avg Packet Size', 'Avg Fwd Segment Size',
            'Avg Bwd Segment Size'
        ]
        
        if scaler_path and os.path.exists(scaler_path):
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
    
    def preprocess_features(self, flow_features):
        """Preprocess features for model input"""
        if not flow_features:
            return None
        
        # Convert to DataFrame
        df = pd.DataFrame(flow_features)
        
        # Select only model features
        model_features = []
        for feature in self.feature_names:
            if feature in df.columns:
                model_features.append(feature)
        
        if not model_features:
            return None
        
        X = df[model_features].fillna(0)
        
        # Handle infinite values
        X = X.replace([np.inf, -np.inf], 0)
        
        # Scale if scaler available
        if self.scaler:
            X_scaled = self.scaler.transform(X)
        else:
            # Simple normalization
            X_scaled = (X - X.mean()) / (X.std() + 1e-8)
        
        return X_scaled, df[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'timestamp']]
    
    def predict(self, flow_features):
        """Make predictions on flow features"""
        processed_data = self.preprocess_features(flow_features)
        if processed_data is None:
            return []
        
        X_scaled, metadata = processed_data
        
        # Get predictions
        predictions = self.model.predict(X_scaled, verbose=0)
        predicted_classes = np.argmax(predictions, axis=1)
        confidence_scores = np.max(predictions, axis=1)
        
        # Combine predictions with metadata
        results = []
        for i, (pred_class, confidence) in enumerate(zip(predicted_classes, confidence_scores)):
            if pred_class != 0:  # Not benign
                result = {
                    'src_ip': metadata.iloc[i]['src_ip'],
                    'dst_ip': metadata.iloc[i]['dst_ip'],
                    'src_port': metadata.iloc[i]['src_port'],
                    'dst_port': metadata.iloc[i]['dst_port'],
                    'protocol': metadata.iloc[i]['protocol'],
                    'attack_type': self.class_names[pred_class],
                    'confidence': float(confidence),
                    'timestamp': metadata.iloc[i]['timestamp']
                }
                results.append(result)
        
        return results

class AttackResponseSystem:
    """System for generating and applying response rules"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.attack_history = deque(maxlen=1000)
        self.rate_limits = defaultdict(lambda: deque(maxlen=100))
        
    def analyze_attack(self, detection):
        """Analyze attack and determine response"""
        attack_type = detection['attack_type']
        src_ip = detection['src_ip']
        
        # Add to history
        self.attack_history.append(detection)
        
        # Check for repeated attacks from same IP
        recent_attacks = [d for d in self.attack_history 
                         if d['src_ip'] == src_ip and 
                         time.time() - d['timestamp'] < 300]  # 5 minutes
        
        response = {
            'action': 'ALERT',
            'severity': 'LOW',
            'block_duration': 0,
            'rules': []
        }
        
        if len(recent_attacks) >= 3:
            response['action'] = 'BLOCK'
            response['severity'] = 'HIGH'
            response['block_duration'] = 3600  # 1 hour
        elif attack_type in ['DDoS', 'Bruteforce']:
            response['action'] = 'BLOCK'
            response['severity'] = 'MEDIUM'
            response['block_duration'] = 1800  # 30 minutes
        
        # Generate firewall rules
        response['rules'] = self.generate_firewall_rules(detection, response)
        
        return response
    
    def generate_firewall_rules(self, detection, response):
        """Generate firewall blocking rules"""
        src_ip = detection['src_ip']
        dst_port = detection['dst_port']
        protocol = detection['protocol'].lower()
        
        rules = []
        
        if response['action'] == 'BLOCK':
            # iptables rules
            rules.append({
                'type': 'iptables',
                'rule': f"iptables -A INPUT -s {src_ip} -j DROP",
                'description': f"Block all traffic from {src_ip}"
            })
            
            # UFW rules
            rules.append({
                'type': 'ufw',
                'rule': f"ufw deny from {src_ip}",
                'description': f"UFW block {src_ip}"
            })
            
            # Specific port blocking
            if dst_port:
                rules.append({
                    'type': 'iptables',
                    'rule': f"iptables -A INPUT -s {src_ip} -p {protocol} --dport {dst_port} -j DROP",
                    'description': f"Block {src_ip} from accessing {protocol}/{dst_port}"
                })
        
        # Rate limiting rules
        rules.append({
            'type': 'iptables',
            'rule': f"iptables -A INPUT -s {src_ip} -m limit --limit 10/min -j ACCEPT",
            'description': f"Rate limit {src_ip} to 10 connections per minute"
        })
        
        return rules
    
    def apply_response(self, response, auto_apply=False):
        """Apply response rules"""
        if not auto_apply:
            return
        
        for rule in response['rules']:
            if rule['type'] == 'iptables':
                try:
                    subprocess.run(rule['rule'].split(), check=True)
                    print(f"Applied: {rule['rule']}")
                except subprocess.CalledProcessError as e:
                    print(f"Failed to apply rule: {e}")

class RealTimeIDSPipeline:
    """Main IDS Pipeline coordinator"""
    
    def __init__(self, model_path, scaler_path=None, interface=None):
        self.traffic_capture = NetworkTrafficCapture(interface)
        self.ids_model = IDSModel(model_path, scaler_path)
        self.response_system = AttackResponseSystem()
        self.running = False
        self.detection_thread = None
        self.capture_thread = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ids_pipeline.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def start_detection_loop(self):
        """Main detection loop"""
        print("🚀 Starting Real-Time IDS Detection...")
        self.logger.info("IDS Pipeline started")
        
        while self.running:
            try:
                # Get recent network flows
                flows = self.traffic_capture.get_recent_flows(window_seconds=5)
                
                if flows:
                    # Detect attacks
                    detections = self.ids_model.predict(flows)
                    
                    # Process detections
                    for detection in detections:
                        self.handle_detection(detection)
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                self.logger.error(f"Error in detection loop: {e}")
                time.sleep(5)
    
    def handle_detection(self, detection):
        """Handle a single attack detection"""
        attack_type = detection['attack_type']
        src_ip = detection['src_ip']
        confidence = detection['confidence']
        
        print(f"🚨 ATTACK DETECTED!")
        print(f"   Type: {attack_type}")
        print(f"   Source IP: {src_ip}")
        print(f"   Target: {detection['dst_ip']}:{detection['dst_port']}")
        print(f"   Confidence: {confidence:.2%}")
        print(f"   Time: {datetime.fromtimestamp(detection['timestamp'])}")
        
        # Log detection
        self.logger.warning(f"Attack detected: {attack_type} from {src_ip} (confidence: {confidence:.2%})")
        
        # Generate response
        response = self.response_system.analyze_attack(detection)
        
        print(f"📋 RESPONSE GENERATED:")
        print(f"   Action: {response['action']}")
        print(f"   Severity: {response['severity']}")
        if response['block_duration'] > 0:
            print(f"   Block Duration: {response['block_duration']} seconds")
        
        print(f"🛡️ FIREWALL RULES:")
        for rule in response['rules']:
            print(f"   {rule['type']}: {rule['rule']}")
            print(f"      → {rule['description']}")
        
        # Save detection to file
        self.save_detection(detection, response)
        
        print("-" * 80)
    
    def save_detection(self, detection, response):
        """Save detection and response to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        record = {
            'timestamp': timestamp,
            'detection': detection,
            'response': response
        }
        
        # Save to JSON log
        with open('attack_detections.json', 'a') as f:
            f.write(json.dumps(record) + '\n')
        
        # Save blocking rules to script
        if response['action'] == 'BLOCK':
            script_file = f"block_rules_{timestamp}.sh"
            with open(script_file, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write(f"# Blocking rules for {detection['attack_type']} from {detection['src_ip']}\n")
                f.write(f"# Generated: {datetime.now()}\n\n")
                
                for rule in response['rules']:
                    if rule['type'] in ['iptables', 'ufw']:
                        f.write(f"# {rule['description']}\n")
                        f.write(f"{rule['rule']}\n\n")
            
            os.chmod(script_file, 0o755)
            print(f"💾 Blocking rules saved to: {script_file}")
    
    def start(self):
        """Start the IDS pipeline"""
        self.running = True
        
        # Start packet capture in separate thread
        self.capture_thread = threading.Thread(target=self.traffic_capture.start_capture)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        time.sleep(2)  # Allow capture to start
        
        # Start detection loop
        self.start_detection_loop()
    
    def stop(self):
        """Stop the IDS pipeline"""
        print("🛑 Stopping IDS Pipeline...")
        self.running = False
        self.traffic_capture.stop_capture()
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        self.logger.info("IDS Pipeline stopped")

def main():
    """Main function to run the IDS pipeline"""
    print("=" * 80)
    print("🛡️  REAL-TIME IDS ATTACK DETECTION & RESPONSE PIPELINE")
    print("=" * 80)
    
    # Configuration
    MODEL_PATH = "enhanced_ids_model_99percent.h5"  # Update with your model path
    SCALER_PATH = "feature_scaler.pkl"  # Update with your scaler path
    INTERFACE = None  # Auto-detect or specify (e.g., 'eth0', 'wlan0')
    
    # Check if model exists
    if not os.path.exists(MODEL_PATH):
        print(f"❌ Model not found at: {MODEL_PATH}")
        print("Please update MODEL_PATH with the correct path to your saved model")
        return
    
    try:
        # Create and start pipeline
        pipeline = RealTimeIDSPipeline(MODEL_PATH, SCALER_PATH, INTERFACE)
        
        print("✅ Pipeline initialized successfully")
        print("🔍 Monitoring network traffic for attacks...")
        print("💡 Press Ctrl+C to stop")
        print()
        
        pipeline.start()
        
    except KeyboardInterrupt:
        print("\n🛑 Stopping pipeline...")
        pipeline.stop()
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
