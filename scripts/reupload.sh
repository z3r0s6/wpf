#!/usr/bin/env bash
# wpf — nuke the GitHub repo, wipe local git history, re-upload as a single
# clean commit. Run from the wpf/ directory.
#
# Usage:
#   bash scripts/reupload.sh
#
# What it does:
#   1. Confirms you really want to wipe.
#   2. `gh repo delete z3r0s6/wpf --yes`        (deletes on GitHub)
#   3. `rm -rf .git`                            (drops all 8+ commits locally)
#   4. `git init -b main` + single commit       (no co-author trailers anywhere)
#   5. `gh repo create wpf --public --push`     (re-uploads as a brand-new repo)
#
# Requirements: gh CLI, logged in (`gh auth status`).

set -euo pipefail

USER="z3r0s6"
REPO="wpf"
REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"

if [[ -t 1 ]]; then
  BOLD=$'\e[1m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; RESET=$'\e[0m'
else
  BOLD=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi
say()  { printf "%s▶%s %s\n" "$BOLD"   "$RESET" "$*"; }
ok()   { printf "%s✓%s %s\n" "$GREEN"  "$RESET" "$*"; }
warn() { printf "%s!%s %s\n" "$YELLOW" "$RESET" "$*" >&2; }
err()  { printf "%s✗%s %s\n" "$RED"    "$RESET" "$*" >&2; exit 1; }

cd "$REPO_DIR"
[[ -f pyproject.toml && -d wpf ]] || err "this doesn't look like the wpf repo — aborting"

# ── 0. prerequisites ────────────────────────────────────────────────────────
command -v gh  >/dev/null 2>&1 || err "gh CLI not installed"
command -v git >/dev/null 2>&1 || err "git not installed"
gh auth status >/dev/null 2>&1 || err "gh not logged in — run: gh auth login"

# ── 1. confirm ──────────────────────────────────────────────────────────────
cat <<EOF

This will:
  • DELETE  https://github.com/${USER}/${REPO}
  • WIPE    ${REPO_DIR}/.git   (all local commit history)
  • CREATE  https://github.com/${USER}/${REPO}  with one clean commit

Files in ${REPO_DIR} are NOT touched. Only git history.

EOF
read -rp "Type 'yes' to proceed: " ans
[[ "$ans" == "yes" ]] || err "aborted"

# ── 2. make sure gh has delete_repo scope ───────────────────────────────────
say "ensuring gh has delete_repo permission"
gh auth refresh -h github.com -s delete_repo

# ── 3. delete the remote repo (idempotent — ignore 'not found') ────────────
say "deleting https://github.com/${USER}/${REPO}"
gh repo delete "${USER}/${REPO}" --yes 2>/dev/null && ok "remote repo deleted" \
  || warn "remote repo did not exist (that's fine)"

# ── 4. wipe local git history ──────────────────────────────────────────────
say "wiping local .git"
rm -rf .git
ok "local history cleared"

# ── 5. fresh init + single commit (no co-author trailers) ──────────────────
say "creating fresh git history"
git init -q -b main

git config user.name  "${USER}"
git config user.email "${USER}@users.noreply.github.com"

git add -A
git commit -q -m "wpf 0.1.0 — initial commit"
ok "single clean commit created (no co-author trailers)"

# ── 6. re-create on GitHub and push ────────────────────────────────────────
say "creating github.com/${USER}/${REPO} and pushing"
gh repo create "${REPO}" --public --source=. --remote=origin --push

echo
ok "done — https://github.com/${USER}/${REPO}"
ok "verify with:  gh repo view ${USER}/${REPO} --web"
