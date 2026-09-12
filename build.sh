#!/usr/bin/env bash
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# If local portable Go is installed in .tools/go, use it
if [ -d "$PROJECT_DIR/.tools/go/bin" ]; then
    export PATH="$PROJECT_DIR/.tools/go/bin:$PATH"
fi

if ! command -v go >/dev/null 2>&1; then
    echo "Error: Go compiler not found on PATH."
    exit 1
fi

echo "========================================="
echo "   Running Test Suite                    "
echo "========================================="
go test -v ./...
python3 test_wireguard_link_to_config.py

echo ""
echo "========================================="
echo "   Compiling Standalone Binaries         "
echo "========================================="
mkdir -p dist

echo "-> Building Linux binary (static, zero-dependency)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/wireguard-link-to-config main.go parser.go
chmod +x dist/wireguard-link-to-config

echo "-> Building Windows binary (.exe, native PE)..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/wireguard-link-to-config.exe main.go parser.go

echo ""
echo "[✔] Build completed successfully! Generated binaries:"
ls -lh dist/
