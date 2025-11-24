#!/bin/bash

# TLSNotary Oracle System - Quick Start Script

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 Starting TLSNotary Oracle System"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PACKAGES_DIR="$SCRIPT_DIR/.."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Please install Node.js 20+"
    exit 1
fi

echo "✓ Node.js version: $(node --version)"

# Setup Notary Service
echo ""
echo "📦 Setting up Notary Service..."
cd "$PACKAGES_DIR/notary-service"

if [ ! -d "node_modules" ]; then
    echo "  Installing dependencies..."
    npm install
fi

if [ ! -f ".env" ]; then
    echo "  Generating keypair..."
    npm run generate-keys
    echo "  ✓ Notary keypair generated"
    echo ""
    echo "  ⚠️  IMPORTANT: Save the public key for contract registration!"
    echo ""
else
    echo "  ✓ .env file exists"
fi

if [ ! -d "dist" ]; then
    echo "  Building..."
    npm run build
fi

echo "  ✓ Notary service ready"

# Setup Oracle Service
echo ""
echo "📦 Setting up Oracle Service..."
cd "$PACKAGES_DIR/oracle-service"

if [ ! -d "node_modules" ]; then
    echo "  Installing dependencies..."
    npm install
fi

if [ ! -f ".env" ]; then
    echo "  Creating .env from example..."
    cp .env.example .env
fi

if [ ! -d "dist" ]; then
    echo "  Building..."
    npm run build
fi

echo "  ✓ Oracle service ready"

# Start services
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔥 Starting Services..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Start notary in background
cd "$PACKAGES_DIR/notary-service"
echo "Starting Notary Service (port 3001)..."
npm start > notary.log 2>&1 &
NOTARY_PID=$!
echo "  PID: $NOTARY_PID"

# Wait for notary to start
echo "  Waiting for notary to be ready..."
for i in {1..10}; do
    if curl -s http://localhost:3001/health > /dev/null 2>&1; then
        echo "  ✓ Notary service is running"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "  ❌ Notary service failed to start"
        kill $NOTARY_PID 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# Start oracle in background
cd "$PACKAGES_DIR/oracle-service"
echo ""
echo "Starting Oracle Service..."
npm start > oracle.log 2>&1 &
ORACLE_PID=$!
echo "  PID: $ORACLE_PID"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ System Running"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Services:"
echo "  Notary:  http://localhost:3001 (PID: $NOTARY_PID)"
echo "  Oracle:  Running (PID: $ORACLE_PID)"
echo ""
echo "Logs:"
echo "  Notary:  tail -f $PACKAGES_DIR/notary-service/notary.log"
echo "  Oracle:  tail -f $PACKAGES_DIR/oracle-service/oracle.log"
echo ""
echo "Commands:"
echo "  Health:  curl http://localhost:3001/health"
echo "  Stats:   curl http://localhost:3001/stats"
echo "  Stop:    kill $NOTARY_PID $ORACLE_PID"
echo ""
echo "Press Ctrl+C to stop all services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Wait for interrupt
trap "echo ''; echo 'Stopping services...'; kill $NOTARY_PID $ORACLE_PID 2>/dev/null; exit 0" INT TERM

# Keep script running
wait
