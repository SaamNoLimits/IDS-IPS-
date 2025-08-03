#!/bin/bash

# IDS Attack Testing Suite for Kali VM
# Run this script from your Kali VM to test all attack types
# Target: Ubuntu machine running IDS (192.168.74.69)

TARGET_IP="192.168.74.69"  # Ubuntu IDS machine

# Check if we can reach the target
ping -c 1 $TARGET_IP >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Cannot reach target $TARGET_IP"
    echo "Make sure your Ubuntu IDS machine is running and accessible"
    exit 1
fi

echo "🚀 IDS Attack Testing Suite"
echo "=========================="
echo "Target: $TARGET_IP"
echo "Time: $(date)"
echo ""

# Function to wait between tests
wait_between_tests() {
    echo "⏳ Waiting 10 seconds before next test..."
    sleep 10
    echo ""
}

# Test 1: TCP SYN Flood
echo "🔥 TEST 1: TCP SYN Flood Attack"
echo "Command: hping3 -S -p 80 --flood -c 50 $TARGET_IP"
timeout 15s hping3 -S -p 80 --flood -c 50 $TARGET_IP 2>/dev/null
echo "✅ SYN Flood test completed"
wait_between_tests

# Test 2: Port Scan
echo "🔍 TEST 2: TCP Port Scan"
echo "Command: nmap -sS -p 1-100 $TARGET_IP"
nmap -sS -p 1-100 $TARGET_IP >/dev/null 2>&1
echo "✅ Port scan test completed"
wait_between_tests

# Test 3: UDP Flood
echo "💥 TEST 3: UDP Flood Attack"
echo "Command: hping3 --udp --flood -c 30 $TARGET_IP"
timeout 10s hping3 --udp --flood -c 30 $TARGET_IP 2>/dev/null
echo "✅ UDP Flood test completed"
wait_between_tests

# Test 4: ICMP Flood
echo "🧊 TEST 4: ICMP Flood Attack"
echo "Command: hping3 --icmp --flood -c 20 $TARGET_IP"
timeout 8s hping3 --icmp --flood -c 20 $TARGET_IP 2>/dev/null
echo "✅ ICMP Flood test completed"
wait_between_tests

# Test 5: Stealth FIN Scan
echo "👤 TEST 5: Stealth FIN Scan"
echo "Command: nmap -sF -p 1-50 $TARGET_IP"
nmap -sF -p 1-50 $TARGET_IP >/dev/null 2>&1
echo "✅ FIN scan test completed"
wait_between_tests

# Test 6: Stealth NULL Scan
echo "👻 TEST 6: Stealth NULL Scan"
echo "Command: nmap -sN -p 1-50 $TARGET_IP"
nmap -sN -p 1-50 $TARGET_IP >/dev/null 2>&1
echo "✅ NULL scan test completed"
wait_between_tests

# Test 7: Rapid Connection Attempts (Brute Force Simulation)
echo "🔐 TEST 7: Rapid Connection Attempts (SSH Brute Force Sim)"
echo "Command: Multiple rapid connections to port 22"
for i in {1..15}; do
    hping3 -S -p 22 -c 1 $TARGET_IP >/dev/null 2>&1
    sleep 0.1
done
echo "✅ Brute force simulation completed"
wait_between_tests

# Test 8: TCP ACK Scan
echo "🎯 TEST 8: TCP ACK Scan"
echo "Command: nmap -sA -p 1-50 $TARGET_IP"
nmap -sA -p 1-50 $TARGET_IP >/dev/null 2>&1
echo "✅ ACK scan test completed"
wait_between_tests

# Test 9: UDP Port Scan
echo "📡 TEST 9: UDP Port Scan"
echo "Command: nmap -sU -p 53,67,68,69,123,161 $TARGET_IP"
nmap -sU -p 53,67,68,69,123,161 $TARGET_IP >/dev/null 2>&1
echo "✅ UDP port scan completed"
wait_between_tests

# Test 10: Mixed Protocol Attack
echo "🌪️ TEST 10: Mixed Protocol Attack"
echo "Command: Combined TCP/UDP/ICMP attack"
(
    timeout 5s hping3 -S -p 80 --flood $TARGET_IP 2>/dev/null &
    timeout 5s hping3 --udp -p 53 --flood $TARGET_IP 2>/dev/null &
    timeout 5s hping3 --icmp --flood $TARGET_IP 2>/dev/null &
    wait
)
echo "✅ Mixed protocol attack completed"
wait_between_tests

# Test 11: Slow Port Scan
echo "🐌 TEST 11: Slow Port Scan (Stealth)"
echo "Command: nmap -sS -T1 -p 1-30 $TARGET_IP"
nmap -sS -T1 -p 1-30 $TARGET_IP >/dev/null 2>&1
echo "✅ Slow port scan completed"
wait_between_tests

# Test 12: High-Rate SYN Attack
echo "⚡ TEST 12: High-Rate SYN Attack"
echo "Command: hping3 -S -p 443 -i u50 -c 100 $TARGET_IP"
timeout 10s hping3 -S -p 443 -i u50 -c 100 $TARGET_IP 2>/dev/null
echo "✅ High-rate SYN attack completed"

echo ""
echo "🎉 ALL ATTACK TESTS COMPLETED!"
echo "================================"
echo "Check your IDS terminal for detection results."
echo "Attack types tested:"
echo "  ✓ TCP SYN Flood"
echo "  ✓ Port Scans (TCP/UDP)"
echo "  ✓ UDP Flood"
echo "  ✓ ICMP Flood"
echo "  ✓ Stealth Scans (FIN/NULL)"
echo "  ✓ Brute Force Simulation"
echo "  ✓ ACK Scan"
echo "  ✓ Mixed Protocol Attack"
echo "  ✓ Slow Stealth Scan"
echo "  ✓ High-Rate Attacks"
echo ""
echo "📊 Check the following log files on your IDS machine:"
echo "  - sensitive_attacks_log.txt"
echo "  - detailed_attack_log.txt"
echo ""
echo "Time completed: $(date)"
