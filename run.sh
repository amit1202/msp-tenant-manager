#!/bin/bash
set -e

echo "MSP Tenant Manager"
echo "=================="

# Install dependencies if needed
if ! python3 -c "import flask, requests" 2>/dev/null; then
  echo "Installing dependencies..."
  pip3 install -r requirements.txt --break-system-packages -q
fi

echo "Starting on http://localhost:5050"
echo "Press Ctrl+C to stop."
echo ""
python3 app.py
