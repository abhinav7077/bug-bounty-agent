#!/usr/bin/env bash
# Installs and starts Ollama directly inside WSL2 (self-contained — avoids
# the Windows-host-vs-WSL2-NAT networking issues of running Ollama on Windows
# and reaching it from WSL2). Run manually; needs sudo.

set -euo pipefail

echo "==> zstd (required by the Ollama installer for extraction, not installed by default here)"
sudo apt install -y zstd

echo "==> Installing Ollama"
curl -fsSL https://ollama.com/install.sh | sh

echo "==> Starting Ollama server in the background"
nohup ollama serve > "$HOME/ollama.log" 2>&1 &
sleep 3

echo "==> Pulling model (this is a large download, ~18GB for 30B — may take a while)"
ollama pull qwen3-coder:30b

echo "==> Verifying"
curl -s http://localhost:11434/api/tags | jq .

echo ""
echo "Ollama is running on http://localhost:11434 inside WSL2."
echo "Leave this terminal's 'ollama serve' running, or set it up as a systemd service:"
echo "  sudo systemctl enable --now ollama   # if the installer registered a systemd unit"
