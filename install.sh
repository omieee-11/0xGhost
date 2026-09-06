#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-example.com}"
REPO_DIR="$HOME/0xGhost"
REPO_URL="https://github.com/omieee-11/0xGhost.git"

# Ensure repository exists and is up to date
if [ -d "$REPO_DIR/.git" ]; then
  git -C "$REPO_DIR" pull --ff-only
else
  rm -rf "$REPO_DIR"
  git clone "$REPO_URL" "$REPO_DIR"
fi

# Install required system packages only if missing
MISSING_PKGS=()
for pkg in python3-venv python3-pip nmap ffuf golang git jq; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    MISSING_PKGS+=("$pkg")
  fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
  sudo apt update
  sudo apt install -y "${MISSING_PKGS[@]}"
fi

cd "$REPO_DIR"

# Create venv if missing
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

# Install required Python dependencies only if missing
MISSING_PY_PKGS=()
for pkg in requests beautifulsoup4 urllib3 python-nmap tqdm flask flask-cors; do
  if ! python3 -m pip show "$pkg" >/dev/null 2>&1; then
    MISSING_PY_PKGS+=("$pkg")
  fi
done

if [ ${#MISSING_PY_PKGS[@]} -gt 0 ]; then
  python3 -m pip install --upgrade pip
  python3 -m pip install "${MISSING_PY_PKGS[@]}"
fi

# Create global wrapper command
sudo tee /usr/local/bin/0xghost >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-example.com}"
cd "$HOME/0xGhost"
# shellcheck disable=SC1091
source .venv/bin/activate
python3 main.py "$TARGET"
EOF

sudo chmod +x /usr/local/bin/0xghost

# Run immediately for current execution
python3 main.py "$TARGET"
