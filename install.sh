#!/usr/bin/env bash
# wpf installer — installs the `wpf` CLI globally on Kali / Debian / Ubuntu / Arch / Fedora.
#
# Default install method: pipx (isolated venv, console script linked into ~/.local/bin).
# After install, `wpf` is on your PATH from any shell. No activation needed.
#
# Usage:
#   ./install.sh                 # install wpf only (no security tools)
#   ./install.sh --with-tools    # install wpf + run `wpf install all`
#   ./install.sh --dev           # editable install (changes to ./wpf/ take effect immediately)
#   ./install.sh --uninstall     # remove wpf and its data/config
#
# Idempotent — safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
WITH_TOOLS=0
DEV=0
UNINSTALL=0

for arg in "$@"; do
  case "$arg" in
    --with-tools) WITH_TOOLS=1 ;;
    --dev)        DEV=1 ;;
    --uninstall)  UNINSTALL=1 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown arg: $arg"; exit 2 ;;
  esac
done

# ── colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then BOLD=$'\e[1m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; DIM=$'\e[2m'; RESET=$'\e[0m';
else BOLD=""; GREEN=""; YELLOW=""; RED=""; DIM=""; RESET=""; fi

say()  { printf "%s▶%s %s\n"  "$BOLD"   "$RESET" "$*"; }
ok()   { printf "%s✓%s %s\n"  "$GREEN"  "$RESET" "$*"; }
warn() { printf "%s!%s %s\n"  "$YELLOW" "$RESET" "$*" >&2; }
err()  { printf "%s✗%s %s\n"  "$RED"    "$RESET" "$*" >&2; }

# ── detect package manager ──────────────────────────────────────────────────
detect_pm() {
  if   command -v apt        >/dev/null 2>&1; then echo apt
  elif command -v dnf        >/dev/null 2>&1; then echo dnf
  elif command -v pacman     >/dev/null 2>&1; then echo pacman
  elif command -v brew       >/dev/null 2>&1; then echo brew
  else echo unknown; fi
}
PM="$(detect_pm)"

# ── uninstall path ──────────────────────────────────────────────────────────
if [[ $UNINSTALL -eq 1 ]]; then
  say "uninstalling wpf"
  if command -v pipx >/dev/null && pipx list 2>/dev/null | grep -q '^   package wpf '; then
    pipx uninstall wpf || true
  fi
  rm -f "$HOME/.local/bin/wpf"
  read -rp "Delete data dir ~/.local/share/wpf (engagements + audit log)? [y/N] " r
  [[ "$r" =~ ^[Yy]$ ]] && rm -rf "$HOME/.local/share/wpf" "$HOME/.cache/wpf"
  read -rp "Delete config dir ~/.config/wpf? [y/N] " r
  [[ "$r" =~ ^[Yy]$ ]] && rm -rf "$HOME/.config/wpf"
  ok "wpf uninstalled"
  exit 0
fi

# ── precondition: python ≥ 3.10 ─────────────────────────────────────────────
say "checking Python ≥ 3.10"
if ! command -v python3 >/dev/null 2>&1; then
  err "python3 not found"
  case "$PM" in
    apt)    echo "→ sudo apt -y install python3 python3-venv python3-pip" ;;
    dnf)    echo "→ sudo dnf -y install python3 python3-pip" ;;
    pacman) echo "→ sudo pacman -S --noconfirm python python-pip" ;;
    brew)   echo "→ brew install python" ;;
  esac
  exit 1
fi
PYVER="$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')"
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
  err "Python $PYVER is too old — need 3.10+"
  exit 1
fi
ok "python $PYVER"

# ── system deps for weasyprint (PDF) ────────────────────────────────────────
say "installing system deps (Pango/Cairo for PDF, libpcap for naabu, pipx, git)"

# Determine if we can use sudo non-interactively. -n returns immediately if a password
# would be required. If not, fall back to "no privilege escalation" and let the user
# install the system bits themselves — we keep going so pipx still works at user level.
SUDO=""
if [[ $EUID -eq 0 ]]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  SUDO="sudo"
else
  warn "no passwordless sudo — skipping system package step. If PDF rendering fails, run:"
  case "$PM" in
    apt)    echo "    sudo apt-get -y install python3-venv pipx libpango-1.0-0 libpangoft2-1.0-0 libpcap-dev golang-go pandoc" ;;
    dnf)    echo "    sudo dnf -y install python3-pip pipx pango libpcap-devel golang pandoc" ;;
    pacman) echo "    sudo pacman -S --noconfirm python-pipx pango libpcap go pandoc" ;;
    brew)   echo "    brew install pipx pango libpcap go pandoc" ;;
  esac
  SUDO="SKIP"
fi

if [[ "$SUDO" != "SKIP" ]]; then
  case "$PM" in
    apt)
      $SUDO apt-get update -qq || warn "apt update failed — continuing"
      $SUDO env DEBIAN_FRONTEND=noninteractive apt-get -y install \
        python3-venv python3-pip pipx git curl wget \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
        libpcap-dev golang-go pandoc >/dev/null 2>&1 \
        || warn "some apt packages failed — continuing"
      ;;
    dnf)
      $SUDO dnf -y install python3-pip pipx git curl wget pango harfbuzz \
        libpcap-devel golang pandoc >/dev/null 2>&1 || warn "dnf install partial"
      ;;
    pacman)
      $SUDO pacman -S --noconfirm python-pipx git curl wget pango harfbuzz \
        libpcap go pandoc >/dev/null 2>&1 || warn "pacman install partial"
      ;;
    brew)
      brew install pipx git pango libpcap go pandoc >/dev/null 2>&1 || warn "brew install partial"
      ;;
    *)
      warn "unknown package manager — install pipx + pango + libpcap manually"
      ;;
  esac
fi

# ── pipx in PATH ────────────────────────────────────────────────────────────
if ! command -v pipx >/dev/null 2>&1; then
  err "pipx still missing after install attempt"
  echo "→ python3 -m pip install --user pipx && python3 -m pipx ensurepath"
  exit 1
fi
pipx ensurepath >/dev/null 2>&1 || true
export PATH="$HOME/.local/bin:$PATH"
ok "pipx OK"

# ── install wpf ─────────────────────────────────────────────────────────────
say "installing wpf from $SCRIPT_DIR"
INSTALL_ARGS=()
if [[ $DEV -eq 1 ]]; then
  INSTALL_ARGS+=(--editable)
fi
if pipx list 2>/dev/null | grep -q '^   package wpf '; then
  warn "wpf already installed via pipx — reinstalling"
  pipx uninstall wpf >/dev/null
fi
pipx install "${INSTALL_ARGS[@]}" "$SCRIPT_DIR"

# ── verify ──────────────────────────────────────────────────────────────────
if ! command -v wpf >/dev/null 2>&1; then
  err "wpf still not on PATH after pipx install"
  echo "Add this to your ~/.zshrc or ~/.bashrc:"
  echo '   export PATH="$HOME/.local/bin:$PATH"'
  echo "Then open a new shell."
  exit 1
fi
WPF_VER="$(wpf version 2>/dev/null || echo unknown)"
ok "$WPF_VER — installed at $(command -v wpf)"

# ── optional: install all security tools ────────────────────────────────────
if [[ $WITH_TOOLS -eq 1 ]]; then
  say "running 'wpf install all' (apt / go / pipx / git / docker)"
  wpf install all || warn "some tools failed to install — re-run 'wpf install <name>' individually"
fi

# ── tail ────────────────────────────────────────────────────────────────────
cat <<'EOF'

╔══════════════════════════════════════════════════════════════════════════╗
║ wpf installed — open a new shell and run:                                ║
║                                                                          ║
║   wpf doctor                       # inventory installed tools           ║
║   wpf engagement --name "demo" --type lab --authorized-by self           ║
║   wpf scope add '*.example.com'                                          ║
║   wpf recon example.com --mode passive                                   ║
║   wpf scan-wstg --list                                                   ║
║   wpf hunt --chapter ch06_xss <url>                                      ║
║   wpf report --format md,pdf,docx --theme corporate                      ║
║                                                                          ║
║ Tip: ./install.sh --with-tools also runs `wpf install all`.              ║
║      ./install.sh --dev for editable mode.                               ║
║      ./install.sh --uninstall to remove.                                 ║
╚══════════════════════════════════════════════════════════════════════════╝
EOF
