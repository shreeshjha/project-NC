#!/bin/bash

echo "Fixing Makefile variable definitions..."

# Check current variable definitions
echo "=== Current variable definitions ==="
grep -n "LIBLOG_OBJ\|HELPERS_OBJ\|LIBARGPARSE_OBJ" Makefile

echo ""
echo "=== Checking if variables are properly defined ==="

# Backup the Makefile
cp Makefile Makefile.backup

# The issue is that LIBLOG_OBJ is referenced but not defined
# Let's add the missing variable definitions

# Find where variables are defined (usually near the top)
echo "Looking for variable definition section..."
grep -n "OUTPUT\|CLANG\|APPS" Makefile | head -5

# Add the missing variable definitions after the APPS line
# First, let's see what HELPERS_OBJ should be
echo ""
echo "Checking for helper files..."
ls -la *helper* 2>/dev/null || echo "No helper files found"

# The line with APPS = should be around line 11-15, let's add our variables after it
APPS_LINE=$(grep -n "^APPS = " Makefile | cut -d: -f1)
echo "APPS defined at line: $APPS_LINE"

if [ -n "$APPS_LINE" ]; then
    # Insert the missing variable definitions after the APPS line
    sed -i "${APPS_LINE}a\\
\\
# Object file definitions\\
HELPERS_OBJ = conntrack_if_helper.o\\
LIBLOG_OBJ = log.o\\
LIBARGPARSE_OBJ = " Makefile
    
    echo "✓ Added missing variable definitions"
else
    echo "Could not find APPS line, adding variables manually..."
    # Add after OUTPUT definition
    OUTPUT_LINE=$(grep -n "^OUTPUT := " Makefile | cut -d: -f1)
    if [ -n "$OUTPUT_LINE" ]; then
        sed -i "${OUTPUT_LINE}a\\
\\
# Object file definitions\\
HELPERS_OBJ = conntrack_if_helper.o\\
LIBLOG_OBJ = log.o\\
LIBARGPARSE_OBJ = " Makefile
        echo "✓ Added variables after OUTPUT definition"
    fi
fi

# Also need to add build rules for these objects
echo ""
echo "Adding build rules for log.o..."

# Add the log.o build rule
cat >> Makefile << 'EOF'

# Build log object
log.o: log.c log.h
	$(call msg,LIBLOG,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

EOF

echo "✓ Added log.o build rule"

# Now try to build
echo ""
echo "Testing build with fixed Makefile..."
make clean
make

if [ $? -eq 0 ]; then
    echo "✓ Build successful with fixed Makefile!"
else
    echo "❌ Build still failing, trying manual approach..."
    
    # Manual build as fallback
    echo "Building manually..."
    gcc -g -Wall -I.output -I./ebpf -I.output/libbpf -c log.c -o log.o
    gcc -g -Wall -I.output -I./ebpf -I.output/libbpf -c conntrack_if_helper.c -o conntrack_if_helper.o
    
    # Link manually
    gcc .output/conntrack.o conntrack_if_helper.o log.o \
        -L.output/libbpf -lbpf -lelf -lz -o conntrack
    
    gcc .output/xdp_loader.o log.o \
        -L.output/libbpf -lbpf -lelf -lz -o xdp_loader
        
    if [ -f "conntrack" ] && [ -f "xdp_loader" ]; then
        chmod +x conntrack xdp_loader
        echo "✓ Manual build successful!"
    fi
fi

echo ""
echo "Final status:"
ls -la conntrack xdp_loader 2>/dev/null || echo "Binaries not found"
