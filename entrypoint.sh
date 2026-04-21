#!/bin/bash

if [ -d ".venv" ]; then
  PYTHON=".venv/bin/python3"
else
  PYTHON="python3"
fi

TOR_LOG="tor_bootstrap.log"
rm -f "$TOR_LOG"

# Check if port 9050 is already in use
if $PYTHON -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 9050)); s.close()" 2>/dev/null; then
  echo "Tor is already running on port 9050."
else
  echo "Starting Tor..."
  tor > "$TOR_LOG" 2>&1 &
fi

echo "Waiting for Tor to be fully ready (Bootstrapped 100%)..."

# Loop until Bootstrapped 100% is found or timeout (90 seconds)
# We also check the socket as a fallback
timeout 90 bash -c "
until grep -q 'Bootstrapped 100%' '$TOR_LOG' 2>/dev/null || $PYTHON -c \"import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 9050)); s.close()\" 2>/dev/null; do
  echo -n '.'
  sleep 2
done
echo
"

if ! $PYTHON -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 9050)); s.close()" 2>/dev/null; then
  echo "ERROR: Tor failed to start or is not listening on port 9050."
  exit 1
fi

echo "Tor socket is open. Waiting a few seconds for network stabilization..."
sleep 5

echo "Tor is ready."
echo "Starting Dcrawler: AI-Powered Dark Web OSINT Tool..."
exec $PYTHON dcrawler.py "$@"

