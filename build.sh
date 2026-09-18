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

VERSION="${VERSION:-1.1.0}"
# Clean leading 'v' if present (e.g. v1.0.0 -> 1.0.0)
VERSION="${VERSION#v}"

echo "========================================="
echo "   Running Test Suite (Version: $VERSION) "
echo "========================================="
go test -v ./...
python3 test_wireguard_link_to_config.py

echo ""
echo "========================================="
echo "   Compiling Standalone Binaries         "
echo "========================================="
mkdir -p dist

LDFLAGS="-s -w -X main.Version=${VERSION}"

echo "-> Building Linux binary (static, zero-dependency)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o dist/wireguard-link-to-config main.go parser.go
chmod +x dist/wireguard-link-to-config

echo "-> Building Windows binary (.exe, native PE)..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o dist/wireguard-link-to-config.exe main.go parser.go

echo ""
echo "[✔] Build completed successfully! Generated binaries:"
ls -lh dist/
