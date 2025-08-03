#!/bin/bash

# 🚀 IDS Attack Tests for Kali VM
# Target: Ubuntu IDS machine at 192.168.74.69
# Copy this script to your Kali VM and run it

TARGET="192.168.74.69"  # Your Ubuntu IDS machine

echo "🛡️  IDS Attack Testing Suite"
echo "============================"
echo "🎯 Target: $TARGET (Ubuntu IDS machine)"
echo "📅 Time: $(date)"
echo ""

# Check connectivity
echo "🔍 Checking connectivity to target..."
if ! ping -c 1 $TARGET >/dev/null 2>&1; then
    echo "❌ Cannot reach $TARGET"
    echo "Make sure your Ubuntu machine is running and accessible"
    exit 1
fi
echo "✅ Target is reachable"
echo ""

# Function to wait between tests
wait_test() {
    echo "⏳ Waiting 8 seconds for IDS to process..."
    sleep 8
    echo ""
}

# Test 1: TCP SYN Flood
echo "🔥 TEST 1: TCP SYN Flood Attack"
echo "Command: hping3 -S -p 80 --flood -c 30 $TARGET"
echo "Expected IDS Detection: SYN Attack or TCP Flood"
timeout 8s sudo hping3 -S -p 80 --flood -c 30 $TARGET 2>/dev/null || echo "SYN flood sent"
echo "✅ SYN Flood test completed"
wait_test

# Test 2: Port Scan
echo "🔍 TEST 2: TCP Port Scan"
echo "Command: nmap -sS -p 1-50 $TARGET"
echo "Expected IDS Detection: Port Scan"
nmap -sS -p 1-50 $TARGET >/dev/null 2>&1
echo "✅ Port scan test completed"
wait_test

# Test 3: UDP Flood
echo "💥 TEST 3: UDP Flood Attack"
echo "Command: hping3 --udp --flood -c 25 $TARGET"
echo "Expected IDS Detection: UDP Flood"
timeout 6s sudo hping3 --udp --flood -c 25 $TARGET 2>/dev/null || echo "UDP flood sent"
echo "✅ UDP Flood test completed"
wait_test

# Test 4: ICMP Flood
echo "🧊 TEST 4: ICMP Flood Attack"
echo "Command: hping3 --icmp --flood -c 20 $TARGET"
echo "Expected IDS Detection: ICMP Attack"
timeout 5s sudo hping3 --icmp --flood -c 20 $TARGET 2>/dev/null || echo "ICMP flood sent"
echo "✅ ICMP Flood test completed"
wait_test

# Test 5: SSH Brute Force Simulation
echo "🔐 TEST 5: SSH Brute Force Simulation"
echo "Command: Multiple rapid connections to port 22"
echo "Expected IDS Detection: Brute Force Attack"
for i in {1..12}; do
    sudo hping3 -S -p 22 -c 1 $TARGET >/dev/null 2>&1
    sleep 0.2
done
echo "✅ SSH Brute force simulation completed"
wait_test

# Test 6: Stealth FIN Scan
echo "👤 TEST 6: Stealth FIN Scan"
echo "Command: nmap -sF -p 1-30 $TARGET"
echo "Expected IDS Detection: Stealth Scan"
nmap -sF -p 1-30 $TARGET >/dev/null 2>&1
echo "✅ FIN scan test completed"
wait_test

# Test 7: High-Rate SYN Attack
echo "⚡ TEST 7: High-Rate SYN Attack"
echo "Command: hping3 -S -p 443 -i u100 -c 50 $TARGET"
echo "Expected IDS Detection: SYN Attack or TCP Flood"
timeout 8s sudo hping3 -S -p 443 -i u100 -c 50 $TARGET 2>/dev/null || echo "High-rate SYN sent"
echo "✅ High-rate SYN attack completed"
wait_test

# Test 8: UDP Port Scan
echo "📡 TEST 8: UDP Port Scan"
echo "Command: nmap -sU -p 53,67,123,161 $TARGET"
echo "Expected IDS Detection: Port Scan"
nmap -sU -p 53,67,123,161 $TARGET >/dev/null 2>&1
echo "✅ UDP port scan completed"
wait_test

# Test 9: Mixed Protocol Attack
echo "🌪️ TEST 9: Mixed Protocol Attack"
echo "Command: Combined TCP/UDP/ICMP attack"
echo "Expected IDS Detection: Multiple attack types"
(
    timeout 4s sudo hping3 -S -p 80 --flood $TARGET 2>/dev/null &
    timeout 4s sudo hping3 --udp -p 53 --flood $TARGET 2>/dev/null &
    timeout 4s sudo hping3 --icmp --flood $TARGET 2>/dev/null &
    wait
) || echo "Mixed attack sent"
echo "✅ Mixed protocol attack completed"
wait_test

# Test 10: Slow Stealth Scan
echo "🐌 TEST 10: Slow Stealth Scan"
echo "Command: nmap -sS -T1 -p 1-20 $TARGET"
echo "Expected IDS Detection: Port Scan (may be delayed)"
nmap -sS -T1 -p 1-20 $TARGET >/dev/null 2>&1
echo "✅ Slow stealth scan completed"

echo ""
echo "🎉 ALL ATTACK TESTS COMPLETED!"
echo "==============================="
echo "📊 Check your Ubuntu IDS terminal for detection results"
echo ""
echo "🚨 Attack types tested:"
echo "  ✓ TCP SYN Flood"
echo "  ✓ TCP Port Scan"
echo "  ✓ UDP Flood"
echo "  ✓ ICMP Flood"
echo "  ✓ SSH Brute Force Simulation"
echo "  ✓ Stealth FIN Scan"
echo "  ✓ High-Rate SYN Attack"
echo "  ✓ UDP Port Scan"
echo "  ✓ Mixed Protocol Attack"
echo "  ✓ Slow Stealth Scan"
echo ""
echo "📋 On your Ubuntu machine, check these log files:"
echo "  - sensitive_attacks_log.txt"
echo "  - detailed_attack_log.txt"
echo ""
echo "⏰ Test completed: $(date)"
echo ""
echo "🔥 Your IDS should have detected most/all of these attacks!"
