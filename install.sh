#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-example.com}"

if [ ! -f "main.py" ]; then
  if [ -d "$HOME/0xGhost" ]; then
    cd "$HOME/0xGhost"
  else
    git clone https://github.com/omieee-11/0xGhost.git "$HOME/0xGhost"
    cd "$HOME/0xGhost"
  fi
fi

sudo apt update && sudo apt install -y \
  python3-venv \
  python3-pip \
  nmap \
  ffuf \
  golang \
  git \
  jq

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install \
  requests \
  beautifulsoup4 \
  urllib3 \
  python-nmap \
  tqdm \
  flask \
  flask-cors

python3 main.py "$TARGET"
