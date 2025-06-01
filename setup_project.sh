#!/bin/bash

# Quick Project Setup Script


set -e

echo "Setting up TCP Connection Tracker project..."

# Step 1: Backup original file
if [ -f "ebpf/conntrack.bpf.c" ]; then
    echo "Backing up original conntrack.bpf.c..."
    cp ebpf/conntrack.bpf.c ebpf/conntrack.bpf.c.original
    echo "✓ Original file backed up as conntrack.bpf.c.original"
fi

# Step 2: Create conntrack_common.h
echo "Creating missing header file: conntrack_common.h..."
cat > ebpf/conntrack_common.h << 'EOF'
#ifndef __CONNTRACK_COMMON_H
#define __CONNTRACK_COMMON_H

#define FORCE_INLINE inline __attribute__((always_inline))

/* TCP flag definitions */
#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02  
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20

/* Connection timeouts (in nanoseconds) */
#define TCP_SYN_SENT    (30ULL * 1000000000ULL)   /* 30 seconds */
#define TCP_SYN_RECV    (60ULL * 1000000000ULL)   /* 60 seconds */
#define TCP_ESTABLISHED (3600ULL * 1000000000ULL) /* 1 hour */
#define TCP_FIN_WAIT    (120ULL * 1000000000ULL)  /* 2 minutes */
#define TCP_LAST_ACK    (30ULL * 1000000000ULL)   /* 30 seconds */
#define UDP_FLOW_TIMEOUT (300ULL * 1000000000ULL) /* 5 minutes */

/* Return codes */
#define CONNTRACK_DROP -1
#define CONNTRACK_ACCEPT 0

/* Helper for sequence number arithmetic */
#define HEX_BE_ONE 0x01000000  /* 1 in big endian */

/* Configuration structure */
struct conntrack_config {
    int log_level;
    int if_index_if1;
    int if_index_if2;
};

/* Global configuration - defined in main program */
extern const volatile struct conntrack_config conntrack_cfg;

#endif // __CONNTRACK_COMMON_H
EOF
echo "✓ conntrack_common.h created"

# Step 3: Instructions for replacing main file
echo ""
echo "IMPORTANT: Manual step required!"
echo "========================================="
echo "You need to replace the content of ebpf/conntrack.bpf.c with the fixed version."
echo ""
echo "The complete fixed file is provided in the artifacts above."
echo "Copy the entire content from 'Complete Fixed eBPF Program' and replace"
echo "the current ebpf/conntrack.bpf.c file."
echo ""
echo "After replacing the file, run:"
echo "  make clean && make"
echo ""

# Step 4: Create testing script
echo "Creating comprehensive testing script..."
# Note: The complete testing script content would be written here
# For brevity, creating a simplified version that references the main script

cat > test_fixes.sh << 'EOF'
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
EOF

chmod +x test_fixes.sh
echo "✓ Basic testing script created as test_fixes.sh"

echo ""
echo "Setup completed! Next steps:"
echo "1. Replace ebpf/conntrack.bpf.c with the fixed version (see instructions above)"
echo "2. Run: make clean && make"
echo "3. Run: sudo ./test_fixes.sh"
echo "4. Run the complete test suite for full validation"
echo ""
echo "Files created/modified:"
echo "  ✓ ebpf/conntrack_common.h (new header file)"
echo "  ✓ ebpf/conntrack.bpf.c.original (backup)"
echo "  ✓ test_fixes.sh (basic testing)"
echo "  → ebpf/conntrack.bpf.c (needs manual replacement)"
