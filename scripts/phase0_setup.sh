#!/usr/bin/env bash
# Phase 0 environment setup — run this yourself in your WSL terminal.
# Claude cannot run sudo here (no TTY for a password prompt), so this is
# meant to be pasted/run manually, section by section if you want to watch
# each step. Safe to re-run — every step is idempotent.
#
# Deviation from docs/DEVELOPMENT_PLAN.md: the plan calls for python3.11, but
# this box is Ubuntu 26.04 (Resolute), which ships python3.14 by default and
# has no python3.11 package. We use python3.14 throughout instead — nothing
# in this project needs 3.11 specifically.

set -euo pipefail

echo "==> [1/7] apt update/upgrade + base packages"
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget build-essential python3-venv python3-pip \
  nmap sqlmap nikto masscan dnsutils jq docker.io ruby-full
# chromium-browser: on this Ubuntu release it's a transitional package that
# triggers a snap install. Needed specifically for gowitness (tools/recon.py's
# run_gowitness) — verified live 2026-07-18 that gowitness itself installs and
# runs fine via `go install`, but errors at runtime with "failed to initialize
# chrome context: exec: 'google-chrome': executable file not found in $PATH"
# with no browser present. Nothing else in this project needs it.
sudo apt install -y chromium-browser

echo "    seclists: not an apt package on this Ubuntu release, only a snap — installing separately"
if command -v snap &>/dev/null; then
  sudo snap install seclists || echo "    !! seclists snap install failed (continuing) — get it manually later: https://github.com/danielmiessler/SecLists"
else
  echo "    !! snap not available — skipping seclists, get it manually later: https://github.com/danielmiessler/SecLists"
fi

echo "==> [2/7] docker group"
sudo usermod -aG docker "$USER"
echo "    (you must close and reopen your terminal, or run 'newgrp docker', for this to take effect)"

echo "==> [3/7] Go 1.22"
if ! command -v go &>/dev/null; then
  GO_TARBALL=go1.22.10.linux-amd64.tar.gz
  curl -LO "https://go.dev/dl/${GO_TARBALL}"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "${GO_TARBALL}"
  rm -f "${GO_TARBALL}"
  grep -q '/usr/local/go/bin' ~/.bashrc || echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
else
  echo "    go already installed: $(go version)"
fi

echo "==> [4/7] ProjectDiscovery + Go-based tools"
GOTOOLS=(
  # amass was missing from this list entirely until 2026-07-18 — not a failed
  # install, just never added (it's OWASP Amass, a separate project from the
  # ProjectDiscovery tools below, easy to overlook). Needed for
  # tools/recon.py's planned run_amass wrapper, still unbuilt as of this fix.
  github.com/owasp-amass/amass/v4/cmd/amass@latest
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  github.com/projectdiscovery/httpx/cmd/httpx@latest
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  github.com/projectdiscovery/katana/cmd/katana@latest
  github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  github.com/projectdiscovery/notify/cmd/notify@latest
  github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  github.com/projectdiscovery/tlsx/cmd/tlsx@latest
  github.com/ffuf/ffuf/v2@latest
  github.com/lc/gau/v2/cmd/gau@latest
  github.com/tomnomnom/waybackurls@latest
  github.com/tomnomnom/gf@latest
  github.com/tomnomnom/qsreplace@latest
  github.com/tomnomnom/anew@latest
  github.com/tomnomnom/assetfinder@latest
  github.com/hahwul/dalfox/v2@latest
  github.com/d3mondev/puredns/v2@latest
  github.com/haccer/subjack@latest
  github.com/assetnote/kiterunner@latest
  github.com/tomnomnom/hacks/kxss@latest
  github.com/sensepost/gowitness@latest
  github.com/hakluke/hakrawler@latest
)
for pkg in "${GOTOOLS[@]}"; do
  echo "    go install $pkg"
  go install "$pkg" || echo "    !! FAILED: $pkg (continuing)"
done

# gf's own binary does nothing useful without pattern files in ~/.gf/ — confirmed live
# 2026-07-19 (session 4): `gf xss` on a fresh install returns "no such pattern" for every
# pattern name, `gf -list` is empty. The GOTOOLS entry above only installs the binary. No
# sudo needed, just a git clone — added here rather than left as a separate manual step.
echo "==> [4b/7] gf patterns (binary alone is non-functional without these)"
mkdir -p "$HOME/.gf"
if [ -z "$(ls -A "$HOME/.gf" 2>/dev/null)" ]; then
  tmp_gf_patterns="$(mktemp -d)"
  git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git "$tmp_gf_patterns" \
    && cp "$tmp_gf_patterns"/*.json "$HOME/.gf/" \
    || echo "    !! FAILED: gf patterns clone (continuing)"
  rm -rf "$tmp_gf_patterns"
else
  echo "    ~/.gf already has patterns, skipping"
fi

echo "==> [5/7] trufflehog + gitleaks (install scripts, not go install)"
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$HOME/go/bin"
curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh -s -- -b "$HOME/go/bin" 2>/dev/null \
  || echo "    gitleaks installer script not found — install manually from https://github.com/gitleaks/gitleaks/releases"

echo "==> [6/7] nuclei templates"
"$HOME/go/bin/nuclei" -update-templates || echo "    run manually once nuclei is on PATH: nuclei -update-templates"

echo "==> [7/7] pip-installed recon tools + uv (system-wide pipx-style, no venv needed for these CLI tools)"
sudo apt install -y pipx
pipx ensurepath
# arjun/wapiti3/theHarvester/ghauri/s3scanner/shodan are real PyPI packages.
# paramspider/corsy/cloud_enum are NOT on PyPI (GitHub-only tools) — they're
# cloned below instead of pipx-installed, so don't add them back to this list.
for pkg in arjun wapiti3 theHarvester ghauri s3scanner shodan; do
  pipx install "$pkg" || echo "    !! FAILED: $pkg (continuing)"
done
pipx install uv || true

echo "==> Clone no-package tools into ~/tools/"
mkdir -p "$HOME/tools"
cd "$HOME/tools"
for repo in \
  m4ll0k/SecretFinder \
  GerbenJavado/LinkFinder \
  defparam/smuggler \
  rezasp/joomscan \
  s0md3v/XSStrike \
  devanshbatham/ParamSpider \
  s0md3v/Corsy \
  initstring/cloud_enum
do
  name=$(basename "$repo")
  if [ -d "$name" ]; then
    echo "    $name already cloned, pulling latest"
    (cd "$name" && git pull --ff-only) || true
  else
    git clone "https://github.com/${repo}.git"
  fi
done

echo "==> Installing Python deps for cloned script-based tools into a shared venv"
# Ubuntu 26.04 blocks plain `pip install` outside a venv (PEP 668,
# "externally-managed-environment") — these three tools are run as scripts
# (python3 paramspider.py, etc.), not installed as packages, so a single
# shared venv for all of them is simpler than one venv each.
TOOLS_VENV="$HOME/tools/.venv-scripts"
python3 -m venv "$TOOLS_VENV"
for name in ParamSpider Corsy cloud_enum; do
  req="$HOME/tools/$name/requirements.txt"
  if [ -f "$req" ]; then
    "$TOOLS_VENV/bin/pip" install -q -r "$req" \
      || echo "    !! pip install -r $req failed (continuing)"
  fi
done
echo "    Run these tools with: $TOOLS_VENV/bin/python3 ~/tools/<Tool>/<script>.py"

echo ""
echo "==> Verifying critical tools on PATH:"
which subfinder httpx nuclei ffuf nmap sqlmap dalfox go 2>&1 || true

echo ""
echo "Done. Open a new terminal (or 'source ~/.bashrc && newgrp docker') so PATH and docker group changes take effect."
