#!/bin/bash
# Quick test script - run after implementing all fixes

echo "Testing basic connectivity..."
sudo ./create-topo.sh
make clean && make

echo "Starting conntrack..."
sudo ./conntrack -1 veth1 -2 veth2 -l 5 &
CONNTRACK_PID=$!
sleep 3

echo "Testing ping..."
if sudo ip netns exec ns1 ping -c 3 10.0.0.2; then
    echo "✓ Ping works - MAC swapping fix successful!"
else
    echo "✗ Ping failed - check MAC swapping implementation"
fi

echo "Testing TCP connection..."
sudo ip netns exec ns2 nc -l 8080 &
SERVER_PID=$!
sleep 1

if echo "test" | sudo ip netns exec ns1 timeout 5 nc 10.0.0.2 8080; then
    echo "✓ TCP connection works - state machine fixes successful!"
else
    echo "✗ TCP connection failed - check state machine implementation"
fi

echo "Testing UDP flow..."
sudo ip netns exec ns2 nc -u -l 9999 &
UDP_SERVER_PID=$!
sleep 1

if echo "UDP test" | sudo ip netns exec ns1 timeout 5 nc -u 10.0.0.2 9999; then
    echo "✓ UDP flow works - UDP support implemented!"
else
    echo "✗ UDP flow failed - check UDP implementation"
fi

# Cleanup
sudo kill $CONNTRACK_PID $SERVER_PID $UDP_SERVER_PID 2>/dev/null || true
echo "Basic tests completed!"
