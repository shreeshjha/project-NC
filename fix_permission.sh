#!/bin/bash

echo "Fixing permission issues..."

# Fix ownership of the .output directory and all its contents
sudo chown -R $(whoami):$(whoami) .output/ 2>/dev/null || true
sudo chown -R $(whoami):$(whoami) conntrack 2>/dev/null || true
sudo chown -R $(whoami):$(whoami) xdp_loader 2>/dev/null || true
sudo chown -R $(whoami):$(whoami) liblog.o 2>/dev/null || true

# Remove the .output directory completely to start fresh
echo "Removing .output directory..."
sudo rm -rf .output/

# Also remove any compiled binaries that might have wrong permissions
rm -f conntrack xdp_loader liblog.o

echo "✓ Permissions fixed and build directory cleaned"
echo ""
echo "Now try building again:"
echo "  make"
