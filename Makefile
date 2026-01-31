# ==============================================================================
# Phantom Mesh - Master Makefile
# ==============================================================================
# Build all components to dist/ directory
#
# Usage:
#   make all              - Build all nodes (native)
#   make all-cross        - Build all cross-compilation targets
#   make phantom          - Build Phantom C2
#   make edge             - Build Edge agent (all platforms)
#   make cloud            - Build Cloud/IoT nodes (all platforms)
#   make clean            - Remove dist/ and target/
# ==============================================================================

# Configuration
DIST_DIR       := dist
CARGO          := cargo
ZIG            := zig
STRIP          := strip

# Rust cross-compilation targets
RUST_LINUX_X64   := x86_64-unknown-linux-musl
RUST_LINUX_ARM64 := aarch64-unknown-linux-musl
RUST_WIN_X64     := x86_64-pc-windows-gnu
RUST_WIN_ARM64   := aarch64-pc-windows-gnu
RUST_MACOS_X64   := x86_64-apple-darwin
RUST_MACOS_ARM64 := aarch64-apple-darwin

# Cloud Node (Zig) directories
CLOUD_DIR      := crates/nodes/cloud

# ==============================================================================
# Main Targets
# ==============================================================================

.PHONY: all all-cross phantom edge cloud clean dist-clean help

all: phantom-native edge-native cloud-native
	@echo ""
	@echo "=========================================="
	@echo " BUILD COMPLETE (Native)"
	@echo "=========================================="
	@ls -la $(DIST_DIR)/
	@echo "=========================================="

all-cross: edge-all cloud-all phantom-native
	@echo ""
	@echo "=========================================="
	@echo " CROSS-COMPILATION COMPLETE"
	@echo "=========================================="
	@ls -la $(DIST_DIR)/
	@echo "=========================================="

help:
	@echo "Phantom Mesh Build System"
	@echo ""
	@echo "Main Targets:"
	@echo "  all              Build all components (native)"
	@echo "  all-cross        Build all cross-compilation targets"
	@echo "  clean            Remove all build artifacts"
	@echo ""
	@echo "Component Targets:"
	@echo "  phantom          Build Phantom C2 (native)"
	@echo "  edge-all         Build Edge for all platforms"
	@echo "  cloud-all        Build Cloud/IoT for all platforms"
	@echo ""
	@echo "Edge Targets:"
	@echo "  edge-linux-x64   Edge for Linux x86_64"
	@echo "  edge-linux-arm64 Edge for Linux ARM64"
	@echo "  edge-win-x64     Edge for Windows x86_64"
	@echo "  edge-win-arm64   Edge for Windows ARM64"
	@echo "  edge-macos       Edge for macOS (native)"
	@echo ""
	@echo "Cloud/IoT Targets:"
	@echo "  cloud-linux-x64   Cloud for Linux x86_64"
	@echo "  cloud-linux-arm64 Cloud for Linux ARM64"
	@echo "  cloud-macos       Cloud for macOS (native)"

# ==============================================================================
# Phantom Node (Rust) - C2 Master
# ==============================================================================

phantom: phantom-native

phantom-native:
	@mkdir -p $(DIST_DIR)
	$(CARGO) build -p phantom --release
	cp target/release/phantom $(DIST_DIR)/phantom
	@echo "[Phantom] Built native binary -> $(DIST_DIR)/phantom"

# ==============================================================================
# Edge Node (Rust) - All Platforms
# ==============================================================================

edge: edge-native

edge-all: edge-linux-x64 edge-linux-arm64 edge-win-x64
	@echo "[Edge] All cross-compilation targets complete"

edge-native:
	@mkdir -p $(DIST_DIR)
	$(CARGO) build -p edge --release
	cp target/release/edge $(DIST_DIR)/edge
	@echo "[Edge] Built native binary -> $(DIST_DIR)/edge"

edge-linux-x64:
	@mkdir -p $(DIST_DIR)/edge
	$(CARGO) build -p edge --release --target $(RUST_LINUX_X64)
	cp target/$(RUST_LINUX_X64)/release/edge $(DIST_DIR)/edge/edge.linux.x64
	$(STRIP) $(DIST_DIR)/edge/edge.linux.x64 2>/dev/null || true
	@echo "[Edge] Built Linux x86_64 -> $(DIST_DIR)/edge/edge.linux.x64"

edge-linux-arm64:
	@mkdir -p $(DIST_DIR)/edge
	$(CARGO) build -p edge --release --target $(RUST_LINUX_ARM64)
	cp target/$(RUST_LINUX_ARM64)/release/edge $(DIST_DIR)/edge/edge.linux.arm64
	$(STRIP) $(DIST_DIR)/edge/edge.linux.arm64 2>/dev/null || true
	@echo "[Edge] Built Linux ARM64 -> $(DIST_DIR)/edge/edge.linux.arm64"

edge-win-x64:
	@mkdir -p $(DIST_DIR)
	$(CARGO) build -p edge --release --target $(RUST_WIN_X64)
	cp target/$(RUST_WIN_X64)/release/edge.exe $(DIST_DIR)/edge.exe
	@echo "[Edge] Built Windows x86_64 -> $(DIST_DIR)/edge.exe"

edge-win-arm64:
	@mkdir -p $(DIST_DIR)/edge
	$(CARGO) build -p edge --release --target $(RUST_WIN_ARM64)
	cp target/$(RUST_WIN_ARM64)/release/edge.exe $(DIST_DIR)/edge/edge.win.arm64.exe
	@echo "[Edge] Built Windows ARM64 -> $(DIST_DIR)/edge/edge.win.arm64.exe"

edge-macos:
	@mkdir -p $(DIST_DIR)/edge
	$(CARGO) build -p edge --release
	cp target/release/edge $(DIST_DIR)/edge/edge.macos
	$(STRIP) $(DIST_DIR)/edge/edge.macos 2>/dev/null || true
	@echo "[Edge] Built macOS -> $(DIST_DIR)/edge/edge.macos"

# ==============================================================================
# Cloud/IoT Node (Zig) - All Platforms
# ==============================================================================

cloud: cloud-native

cloud-all: cloud-linux-x64 cloud-linux-arm64
	@echo "[Cloud] All cross-compilation targets complete"

cloud-native:
	@mkdir -p $(DIST_DIR)
	cd $(CLOUD_DIR) && $(ZIG) build -Doptimize=ReleaseFast
	@if [ -f "$(CLOUD_DIR)/zig-out/bin/cloud" ]; then \
		cp $(CLOUD_DIR)/zig-out/bin/cloud $(DIST_DIR)/cloud; \
	else \
		echo "[Cloud] Note: zig-out not found, using direct build"; \
		cd $(CLOUD_DIR) && $(ZIG) build-exe src/main.zig -O ReleaseFast --name cloud && \
		mv cloud ../../../$(DIST_DIR)/cloud 2>/dev/null || true; \
	fi
	@echo "[Cloud] Built native binary -> $(DIST_DIR)/cloud"

cloud-linux-x64:
	@mkdir -p $(DIST_DIR)/cloud
	cd $(CLOUD_DIR) && $(ZIG) build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-gnu
	@if [ -f "$(CLOUD_DIR)/zig-out/bin/cloud" ]; then \
		cp $(CLOUD_DIR)/zig-out/bin/cloud $(DIST_DIR)/cloud/cloud.linux.x64; \
	fi
	@echo "[Cloud] Built Linux x86_64 -> $(DIST_DIR)/cloud/cloud.linux.x64"

cloud-linux-arm64:
	@mkdir -p $(DIST_DIR)/cloud
	cd $(CLOUD_DIR) && $(ZIG) build -Doptimize=ReleaseFast -Dtarget=aarch64-linux-gnu
	@if [ -f "$(CLOUD_DIR)/zig-out/bin/cloud" ]; then \
		cp $(CLOUD_DIR)/zig-out/bin/cloud $(DIST_DIR)/cloud/cloud.linux.arm64; \
	fi
	@echo "[Cloud] Built Linux ARM64 -> $(DIST_DIR)/cloud/cloud.linux.arm64"

cloud-macos:
	@mkdir -p $(DIST_DIR)/cloud
	cd $(CLOUD_DIR) && $(ZIG) build -Doptimize=ReleaseFast
	@if [ -f "$(CLOUD_DIR)/zig-out/bin/cloud" ]; then \
		cp $(CLOUD_DIR)/zig-out/bin/cloud $(DIST_DIR)/cloud/cloud.macos; \
	fi
	@echo "[Cloud] Built macOS -> $(DIST_DIR)/cloud/cloud.macos"

# ==============================================================================
# Plugins (Rust dynamic libraries)
# ==============================================================================

plugins:
	@mkdir -p $(DIST_DIR)/plugins
	$(CARGO) build -p ddos --release 2>/dev/null || true
	$(CARGO) build -p cryptojacking --release 2>/dev/null || true
	$(CARGO) build -p keylogger --release 2>/dev/null || true
	@cp target/release/*.dylib $(DIST_DIR)/plugins/ 2>/dev/null || true
	@cp target/release/*.so $(DIST_DIR)/plugins/ 2>/dev/null || true
	@echo "[Plugins] Build complete -> $(DIST_DIR)/plugins/"

# ==============================================================================
# Utilities
# ==============================================================================

clean:
	rm -rf $(DIST_DIR)
	rm -rf target
	cd $(CLOUD_DIR) && rm -rf zig-out zig-cache 2>/dev/null || true
	@echo "[Clean] All build artifacts removed"

dist-clean:
	rm -rf $(DIST_DIR)
	@echo "[Clean] dist/ removed"

# Install cross-compilation toolchains
install-targets:
	@echo "Installing Rust cross-compilation targets..."
	rustup target add $(RUST_LINUX_X64)
	rustup target add $(RUST_LINUX_ARM64)
	rustup target add $(RUST_WIN_X64)
	rustup target add $(RUST_WIN_ARM64) 2>/dev/null || echo "Note: Windows ARM64 may require additional setup"
	@echo ""
	@echo "For Linux cross-compilation on macOS, you may need:"
	@echo "  brew install filosottile/musl-cross/musl-cross"
	@echo "  brew install mingw-w64"
	@echo ""
	@echo "Targets installed successfully"

# Check dependencies
check-deps:
	@echo "Checking build dependencies..."
	@which $(CARGO) > /dev/null || (echo "ERROR: cargo not found" && exit 1)
	@which $(ZIG) > /dev/null || (echo "ERROR: zig not found" && exit 1)
	@echo "cargo: $(shell cargo --version)"
	@echo "zig:   $(shell zig version)"
	@echo "All dependencies OK"

# Run tests
test:
	$(CARGO) test --workspace
	@echo "[Test] All tests passed"
