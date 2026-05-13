#!/usr/bin/env bash
# wpf self-test — end-to-end smoke test against a bundled vulnerable mock target.
#
# What it does:
#   1. Starts scripts/mock_target.py on 127.0.0.1:8765 (intentionally weak HTTP server).
#   2. Scaffolds a "wpf-self-test" engagement and authorizes 127.0.0.1 in scope.
#   3. Runs every implemented WSTG runner + every implemented BBB workflow against it.
#   4. Renders Markdown / PDF / DOCX reports.
#   5. Asserts the artefacts exist, the PDF is valid, ≥10 findings were recorded.
#   6. Kills the mock target.
#
# Usage:
#   bash scripts/self_test.sh                 # run everything, keep reports
#   bash scripts/self_test.sh --cleanup       # also remove the engagement DB row after
#
# Exits 0 on success, non-zero with a clear message on failure.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ENGAGEMENT="wpf-self-test"
TARGET_BASE="http://127.0.0.1:8765"
CLEANUP=0

for arg in "$@"; do
  case "$arg" in
    --cleanup) CLEANUP=1 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $arg"; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then BOLD=$'\e[1m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; RESET=$'\e[0m';
else BOLD=""; GREEN=""; YELLOW=""; RED=""; RESET=""; fi
say()  { printf "%s▶%s %s\n"  "$BOLD"   "$RESET" "$*"; }
ok()   { printf "%s✓%s %s\n"  "$GREEN"  "$RESET" "$*"; }
warn() { printf "%s!%s %s\n"  "$YELLOW" "$RESET" "$*" >&2; }
fail() { printf "%s✗%s %s\n"  "$RED"    "$RESET" "$*" >&2; exit 1; }

# ── precondition: wpf installed ─────────────────────────────────────────────
if ! command -v wpf >/dev/null 2>&1; then
  fail "wpf not on PATH. Run ./install.sh first (and open a new shell)."
fi
say "wpf version: $(wpf version)"

# ── start the mock target ──────────────────────────────────────────────────
say "starting mock target (vulnnginx demo) on 127.0.0.1:8765"
MOCK_LOG="$(mktemp -t wpf-mock.XXXXXX.log)"
python3 "$SCRIPT_DIR/mock_target.py" >"$MOCK_LOG" 2>&1 &
MOCK_PID=$!
cleanup() {
  if kill -0 "$MOCK_PID" 2>/dev/null; then
    kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
  fi
  rm -f "$MOCK_LOG"
}
trap cleanup EXIT INT TERM

# wait up to 5s for the port to open
for _ in $(seq 1 10); do
  if curl -fsS --max-time 1 "$TARGET_BASE/" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
if ! curl -fsS --max-time 2 "$TARGET_BASE/" >/dev/null 2>&1; then
  cat "$MOCK_LOG"
  fail "mock target failed to start"
fi
ok "mock target up at $TARGET_BASE"

# ── scaffold engagement + scope ─────────────────────────────────────────────
say "scaffolding engagement '$ENGAGEMENT'"
wpf engagement --name "$ENGAGEMENT" --type lab --authorized-by self >/dev/null
wpf scope add 127.0.0.1 >/dev/null
wpf scope check 127.0.0.1 >/dev/null || fail "scope check failed for 127.0.0.1"
wpf scope check evil.example >/dev/null 2>&1 && fail "scope guard accepted out-of-scope host" || true
ok "scope guard refusing out-of-scope hosts (expected)"

# ── run the WSTG suite (only the automated ones — manual stubs add noise) ──
say "running WSTG automated tests"
WSTG_TESTS=(
  WSTG-INFO-02 WSTG-INFO-03 WSTG-INFO-05 WSTG-INFO-08
  WSTG-CONF-02 WSTG-CONF-07 WSTG-CONF-08 WSTG-CONF-09
  WSTG-ATHN-01 WSTG-SESS-02 WSTG-SESS-05
  WSTG-CLNT-07 WSTG-CLNT-09
  WSTG-ERRH-01 WSTG-INPV-01 WSTG-INPV-18
)
URL="$TARGET_BASE/?q=hi&user=1"
for tid in "${WSTG_TESTS[@]}"; do
  wpf scan-wstg --id "$tid" "$URL" 2>&1 | tail -2 | sed 's/^/    /'
done

# SQLi probe wants its own URL with an `id=` query param
wpf scan-wstg --id WSTG-INPV-05 "$TARGET_BASE/api/users/1?id=1" 2>&1 | tail -2 | sed 's/^/    /'

# ── run the BBB workflows (the automated ones) ──────────────────────────────
say "running Bug Bounty Bootcamp chapter workflows"
BBB_CHAPTERS=(
  ch06_xss ch07_open_redirect ch08_clickjacking ch09_csrf
  ch10_idor ch11_sqli ch13_ssrf ch21_info_disclosure ch24_api
)
for ch in "${BBB_CHAPTERS[@]}"; do
  wpf hunt --chapter "$ch" "$URL" 2>&1 | tail -2 | sed 's/^/    /'
done

# ── render report ──────────────────────────────────────────────────────────
say "rendering report.md / .pdf / .docx (corporate theme)"
wpf report --format md,pdf,docx --theme corporate 2>&1 | tail -8 | sed 's/^/    /'

REPORT_DIR="$REPO_ROOT/reports/$ENGAGEMENT"
[[ -f "$REPORT_DIR/report.md"   ]] || fail "report.md missing"
[[ -f "$REPORT_DIR/report.pdf"  ]] || fail "report.pdf missing"
[[ -f "$REPORT_DIR/report.docx" ]] || fail "report.docx missing"
ok "report.md   $(stat -c%s "$REPORT_DIR/report.md")   bytes"
ok "report.pdf  $(stat -c%s "$REPORT_DIR/report.pdf")  bytes"
ok "report.docx $(stat -c%s "$REPORT_DIR/report.docx") bytes"

# PDF must be a valid PDF
file "$REPORT_DIR/report.pdf" | grep -q "PDF document" || fail "report.pdf is not a valid PDF"

# At least 10 findings recorded (the mock is intentionally noisy)
FCOUNT=$(grep -oE "^#### [0-9]+\." "$REPORT_DIR/report.md" | wc -l | tr -d ' ')
if [[ "$FCOUNT" -lt 10 ]]; then
  fail "expected ≥10 findings, got $FCOUNT — check the report manually"
fi
ok "$FCOUNT findings recorded"

# ── optional cleanup ───────────────────────────────────────────────────────
if [[ $CLEANUP -eq 1 ]]; then
  say "removing engagement row from the store"
  python3 - <<PY
import sqlite3, os
from pathlib import Path
db = Path(os.path.expanduser("~/.local/share/wpf/wpf.db"))
if db.exists():
    c = sqlite3.connect(str(db))
    c.execute("DELETE FROM engagements WHERE name=?", ("$ENGAGEMENT",))
    c.commit(); c.close()
    print("    deleted '$ENGAGEMENT' rows")
PY
  rm -rf "$REPORT_DIR"
  rm -f "$REPO_ROOT/scope/scope.yml"
  ok "cleanup complete"
fi

printf "\n%s✓ self-test passed%s — open %s/report.pdf\n" "$GREEN" "$RESET" "$REPORT_DIR"
