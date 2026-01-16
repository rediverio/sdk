#!/bin/bash
# Build script for rediver-sdk

set -e

echo "Building rediver-sdk..."

# Build all packages
go build ./...

# Build CLI
go build -o bin/rediver-agent ./cmd/rediver-agent

echo "Build completed successfully!"
echo "Binary: bin/rediver-agent"
