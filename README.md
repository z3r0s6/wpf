# wpf - Web Pentest Framework

> WSTG v4.2 (97 tests) + Bug Bounty Bootcamp (25 chapters) + ars0n-style recon - one CLI, one report.

`wpf` turns the **OWASP Web Security Testing Guide v4.2** checklist, Vickie Li's **Bug Bounty Bootcamp** workflows, and the 3-round recon pipeline shape of [R-s0n/ars0n-framework-v2](https://github.com/R-s0n/ars0n-framework-v2) into one operator-friendly CLI. It wraps best-of-breed Kali tools, gates everything behind an explicit scope file, and produces high-quality **Markdown / PDF / DOCX** reports with logo + theming.

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![Tools: 91](https://img.shields.io/badge/tools-91-green)](wpf/data/install_matrix.json)
[![WSTG: 97/97](https://img.shields.io/badge/WSTG_v4.2-97%2F97-orange)](wpf/data/wstg_checklist.json)
[![BBB: 25/25](https://img.shields.io/badge/Bug_Bounty_Bootcamp-25%2F25-orange)](wpf/data/bbbootcamp_workflows.json)

---

## Table of contents

1. [Why this exists](#why-this-exists)
2. [Install](#install)
3. [5-minute walkthrough](#5-minute-walkthrough)
4. [Operating modes - OSINT vs passive vs active vs aggressive](#operating-modes)
5. [Command reference](#command-reference)
   - [doctor / install / install bundles](#doctor--install)
   - [engagement / scope](#engagement--scope)
   - [recon](#recon)
   - [scan-wstg](#scan-wstg)
   - [hunt](#hunt-bbb-workflows)
   - [report](#report)
   - [tui / version](#tui--version)
6. [Scope file grammar](#scope-file)
7. [Self-test (bash script)](#self-test)
8. [Tesla bug-bounty OSINT demo](#tesla-bug-bounty-osint-demo)
9. [Project layout](#project-layout)
10. [Authorization & ethics](#authorization--ethics)
11. [Caveats](#caveats)

---

## Why this exists

The standard pentest workflow is: read the WSTG PDF, read the bug-bounty book, install 30 tools, glue them together with shell scripts and `anew | tee`, copy-paste findings into a Word template. `wpf` collapses that into a single CLI with a real data model, an auditable scope guard, and a polished report - without requiring any paid API key.

## Highlights

- **97 WSTG v4.2 runners** (`wpf scan-wstg`) - 18 fully automated, the rest manual-checklist stubs carrying the PDF's *How to Test* steps and tool list verbatim.
- **25 Bug Bounty Bootcamp workflows** (`wpf hunt`) - 14 active runners (XSS, open redirect, clickjacking, CSRF, IDOR, SQLi, SSRF, XXE, SSTI, takeover, info disclosure, API hacking, recon pipeline), 11 chapter-stub workflows with the methodology baked in.
- **ars0n-style recon pipeline** - OSINT → passive → DNS-brute → JS-discovery, with consolidation + httpx between rounds and the **ROI scoring** heuristics ported verbatim from `ROIReport.js → calculateROIScore()`. Auto-pauses when the surface exceeds the configured ceiling (default 2 500 subdomains / 500 live hosts).
- **91 tools** auto-installable from one place. Curated install **bundles** (`passive`, `recon`, `xss`, `sqli`, …) so you don't have to memorize names.
- **Reports** in Markdown / PDF / DOCX with 4 themes (`corporate`, `dark`, `light`, `minimal`), logo, severity grouping, WSTG/CWE/OWASP references, audit trail.
- **Authorization-first** - every active probe is gated by `scope/scope.yml`. Out-of-scope hosts are hard-refused before any subprocess starts. There is no override flag.
- **No API keys required.** Shodan/Censys/SecurityTrails/GitHub PAT/WPScan token are read from env vars; absent ⇒ stage silently skipped.

---

## Install

### One-liner on Kali / Debian / Ubuntu / Arch / Fedora / macOS

```bash
git clone https://github.com/z3r0s6/wpf.git
cd wpf
./install.sh                  # installs wpf into a pipx-managed venv, links into ~/.local/bin
```

After that, `wpf` is available from **any shell** - no venv activation, no `pip install` dance.

### Installer flags

| Flag | What it does |
|------|--------------|
| *(none)* | Install wpf only |
| `--with-tools` | Install wpf **and** run `wpf install all` (apt / go / pipx / git / docker - large, ~30 min) |
| `--dev` | Editable install - edits to `./wpf/` take effect immediately |
| `--uninstall` | Remove wpf and its data after confirmation |

### Alternative - manual pipx

```bash
python3 -m pip install --user pipx && pipx ensurepath
pipx install .                                  # from the repo root
```

### Alternative - manual venv

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

> If `wpf: command not found` after install: run `pipx ensurepath` and **open a new shell**. pipx links into `~/.local/bin`, which needs to be on PATH.

### System dependencies (handled by `install.sh`)

- Python ≥ 3.10
- libpango / libcairo (PDF rendering)
- libpcap-dev (naabu)
- Go ≥ 1.22 (most ProjectDiscovery tools)
- pandoc (optional - better DOCX tables)
- pipx, git, curl

---

## One command to do everything: `wpf full`

If you just want results without thinking about which sub-command to run:

```bash
wpf full
```

Interactive prompts ask for the engagement name, in/out scope, target, mode,
and output folder, then it:

1. Creates `scope/<name>.yml` and marks it active.
2. Runs `wpf recon TARGET --mode <mode>`.
3. Runs every implemented WSTG test (97 runners).
4. Runs every implemented Bug Bounty Bootcamp chapter workflow (24, minus the
   recon chapter which already ran).
5. Renders `report.md` / `report.pdf` / `report.docx` and dumps
   `findings.json` + `findings_summary.txt`.

Everything lands in **`reports/<name>/`**. Non-interactive form for scripting:

```bash
wpf full --name acme-2026 --type bug_bounty --authorized-by security@acme.example \
         --in '*.acme.example,acme.example' \
         --target https://acme.example \
         --mode passive \
         --theme corporate \
         -o ./reports/acme-2026/ \
         -y
```

Skip individual phases with `--skip-recon`, `--skip-wstg`, `--skip-hunt`.

---

## 5-minute walkthrough (manual flow)

```bash
# 1. Inventory what's already installed on your box
wpf doctor

# 2. Install everything you'll need with one bundle
wpf install recon                     # subfinder, amass, assetfinder, httpx, dnsx, ...
# or pick by phase
wpf install passive probe crawl       # multiple bundles
wpf install sqlmap dalfox nuclei      # specific tools
wpf install all                       # the full 91-tool catalog (~30 min)

# 3. Scaffold an engagement + scope file
wpf engagement --name "ACME-2026" --type bug_bounty --authorized-by security@acme.example
wpf scope add '*.acme.example'
wpf scope add 'api.acme.example'
wpf scope show

# 4. Recon (start OSINT-only - zero requests to the target)
wpf recon acme.example --mode osint

# 5. Step up to passive (subfinder ... + httpx probe + crawl + ROI scoring)
wpf recon acme.example --mode passive

# 6. Run a single WSTG test, a whole category, or all 97
wpf scan-wstg --id WSTG-INPV-05 https://api.acme.example/users?id=1
wpf scan-wstg --category SESS   https://acme.example
wpf scan-wstg                   https://acme.example       # full battery

# 7. Run a Bug Bounty Bootcamp chapter workflow
wpf hunt --chapter ch06_xss   'https://acme.example/?q=foo'
wpf hunt --chapter ch24_api   https://api.acme.example
wpf hunt --list                                             # all 25 chapters

# 8. Render the report
wpf report --format md,pdf,docx --theme corporate
ls reports/ACME-2026/                                       # report.md / .pdf / .docx
```

---

## Operating modes

`wpf` distinguishes four progressively-noisier behaviours. Pick the lowest one that meets your authorization.

| Mode         | Where it lives                | What it does                                                           | Sends traffic to target? |
|--------------|-------------------------------|-------------------------------------------------------------------------|--------------------------|
| **OSINT**    | `wpf recon --mode osint`     | subfinder · amass-passive · crt.sh · assetfinder · gau · waybackurls    | **No** (third parties only) |
| **passive**  | `wpf recon --mode passive`   | OSINT + httpx probe + light crawl + screenshots + takeover check        | Yes - read-only          |
| **active**   | `wpf recon --mode active`    | passive + DNS brute force (shuffledns + cewl wordlist)                  | Yes - DNS only           |
| **all**      | `wpf recon --mode all`       | active + every enrichment stage                                         | Yes                       |
| **aggressive** | `flags.aggressive: true` in `scope.yml` | Unlocks exploit primitives (sqlmap actively exploits SQLi, dalfox confirmation, …) | Yes - interactive |

OSINT mode is safe for any bug-bounty program that allows reconnaissance, including ones whose rules forbid "scanning". Passive mode actively probes the target. `--aggressive` is a separate flag inside `scope.yml`; CLI commands cannot opt into it for you.

---

## Command reference

```
wpf doctor
wpf install [TOOL|BUNDLE...|all] [--methods apt,go,pipx,git,docker] [--list-bundles]
wpf scope {init,add,remove,clear,show,check,edit} [args]
wpf engagement --name X --type Y [--authorized-by W]
wpf recon TARGET [--mode osint|passive|active|all]
                 [--max-subdomains N] [--max-live N]
                 [--no-screenshots] [--no-takeover]
wpf scan-wstg [TARGET] [--id WSTG-XXX-NN] [--category INFO|CONF|...|APIT] [--list]
wpf hunt      [TARGET] [--chapter ch06_xss] [--list]
wpf report [-e ENGAGEMENT] [--format md,pdf,docx] [-t THEME] [-l LOGO] [-o DIR] [--list]
wpf full   [--name N] [--in HOSTS] [--target URL] [--mode M] [-o DIR] [-y]
wpf tui
wpf version
```

### doctor / install

```bash
wpf doctor                                   # color table, 91 tools, missing-tool install hints

wpf install --list-bundles                   # see all bundles
wpf install passive                          # passive recon bundle
wpf install recon probe crawl                # chain bundles
wpf install subfinder httpx nuclei           # specific tools
wpf install all                              # everything (long - ~30 min)
wpf install nuclei --methods go              # restrict to a single method
wpf install all --methods apt                # only what's available via apt
```

**Bundles available**

| Bundle | Contents |
|--------|----------|
| `passive` | subfinder, assetfinder, amass, gau, waybackurls, anew, unfurl, qsreplace |
| `recon` | subfinder, amass, assetfinder, findomain, gau, waybackurls, dnsx, httpx, anew, unfurl |
| `probe` | httpx, dnsx, naabu, nmap, whatweb, webanalyze, gowitness |
| `crawl` | katana, gospider, hakrawler, linkfinder, getJS, gau, waybackurls |
| `fuzz` | ffuf, feroxbuster, dirsearch, gobuster, seclists |
| `xss` | dalfox, kxss, Gxss, qsreplace, xsstrike |
| `sqli` | sqlmap, ghauri |
| `ssrf` | interactsh-client, ssrfmap |
| `ssti` | sstimap |
| `cors` | corsy, corscanner |
| `jwt` | jwt_tool |
| `cms` | wpscan, joomscan, droopescan, nikto |
| `takeover` | subzy, subjack |
| `params` | arjun, x8, paramspider |
| `vuln` | nuclei, nuclei-templates |
| `smuggle` | smuggler, http2smugl, h2csmuggler |
| `cloud` | cloud_enum, s3scanner, gcpbucketbrute |
| `mobile` | apktool, jadx, mobsf |
| `proxy` | mitmproxy, zaproxy, proxify |

### engagement / scope

Each engagement gets its own scope file at `scope/<name>.yml`. The currently
active engagement is exposed as a symlink `scope/scope.yml → scope/<name>.yml`,
so every other subcommand "just works" against the active one. Switch with
`wpf scope use NAME`.

```bash
wpf engagement --name "ACME-2026" --type bug_bounty --authorized-by "security@acme.example"
# → writes scope/ACME-2026.yml AND makes it the active engagement

wpf scope list                               # every engagement, marks the active one
wpf scope show                               # print the active engagement's scope
wpf scope show tesla-bb                      # print a specific engagement's scope
wpf scope use tesla-bb                       # switch active engagement
wpf scope add 'example.com'                  # add to active engagement's in-scope
wpf scope add '*.example.com'                # wildcard
wpf scope add '10.0.0.0/24'                  # CIDR
wpf scope add --out 'status.example.com'     # add to out-of-scope
wpf scope add --engagement tesla-bb '*.tesla.com'  # target a specific engagement
wpf scope edit                               # open active engagement in nano
wpf scope edit tesla-bb                      # open a specific one in nano (or $EDITOR)
wpf scope check evil.example                 # exit 0 if in scope, non-zero otherwise

wpf scope remove tesla-bb                    # delete an engagement (interactive confirm)
wpf scope remove tesla-bb -y                 # skip the confirmation
wpf scope remove tesla-bb -y --purge-db      # also wipe its findings / runs from the DB
```

| Subcommand | Effect |
|------------|--------|
| `init --name X --type T` | Create `scope/X.yml`, make it active. (`engagement` does the same + DB row.) |
| `list` | Table of every engagement file, marks the active one. |
| `use NAME` | Re-point `scope/scope.yml` at `scope/NAME.yml`. |
| `show [NAME]` | Show the scope file; defaults to the active engagement. |
| `add ENTRY [--out] [--engagement X]` | Append to the in-scope (or out-of-scope) list of the active or named engagement. |
| `check HOST [--engagement X]` | Exit code reflects whether HOST is allowed. |
| `edit [NAME]` | Open in `$EDITOR`, falling back to **nano**, then `vi`. |
| `remove NAME [-y] [--purge-db]` | Delete `scope/NAME.yml`. With `--purge-db`, also remove the engagement's rows from `~/.local/share/wpf/wpf.db`. |

### recon

```bash
# OSINT only - zero packets to the target
wpf recon tesla.com --mode osint

# Passive - OSINT + httpx + crawl + screenshots + takeover check
wpf recon acme.example --mode passive

# Active - passive + DNS brute force (needs shuffledns + massdns)
wpf recon acme.example --mode active

# All enrichments
wpf recon acme.example --mode all --max-subdomains 5000 --max-live 1000

# Trim noise
wpf recon acme.example --no-screenshots --no-takeover
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--mode` | `passive` | `osint` / `passive` / `active` / `all` |
| `--max-subdomains` | `2500` | pause if the consolidated subdomain set is larger (ars0n safety net) |
| `--max-live` | `500` | pause if httpx finds more live web hosts than this |
| `--no-screenshots` | off | skip gowitness pass |
| `--no-takeover` | off | skip subzy/subjack subdomain-takeover check |

### scan-wstg

```bash
wpf scan-wstg --list                         # show all 97 runners
wpf scan-wstg --id WSTG-INPV-05 'https://api.acme.example/users?id=1'
wpf scan-wstg --category CLNT https://acme.example
wpf scan-wstg https://acme.example           # entire 97-test battery
```

Implemented runners (the rest are manual-checklist stubs):

INFO-02 *Fingerprint Web Server* · INFO-03 *Metafiles* · INFO-05 *Webpage content leakage* · INFO-08 *Framework fingerprint* · CONF-02 *Security headers* · CONF-07 *HSTS* · CONF-08 *RIA policies* · CONF-09 *Exposed file permissions* · ATHN-01 *Cleartext credentials* · SESS-02 *Cookie attributes* · SESS-05 *CSRF* · CLNT-07 *CORS* · CLNT-09 *Clickjacking* · ERRH-01 *Verbose error handling* · CRYP-01 *Weak TLS* · INPV-01 *Reflected XSS canary* · INPV-05 *SQL injection (sqlmap on `--aggressive`)* · INPV-18 *SSTI canary*

### hunt (BBB workflows)

```bash
wpf hunt --list                              # all 25 chapters
wpf hunt --chapter ch06_xss 'https://acme.example/search?q=hi'
wpf hunt --chapter ch24_api https://api.acme.example
wpf hunt https://acme.example                # all chapters
```

Implemented chapter runners:

`ch05_recon` (delegates to the recon pipeline) · `ch06_xss` · `ch07_open_redirect` · `ch08_clickjacking` · `ch09_csrf` · `ch10_idor` · `ch11_sqli` · `ch13_ssrf` · `ch15_xxe` (with `xml_endpoints=[...]`) · `ch16_ssti` · `ch20_subdomain_takeover` · `ch21_info_disclosure` · `ch24_api`

The other 12 chapters are runnable as **manual checklists** - they emit a Finding stub carrying the chapter's methodology + payloads + bypass techniques from the BBB JSON.

### report

```bash
wpf report --format md,pdf,docx --theme corporate
wpf report --format pdf --theme dark --logo logos/acme.png
wpf report --format md --out /tmp/quick-md/
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--format` | `md,pdf,docx` | comma-list of `md` / `pdf` / `docx` |
| `--theme` | `corporate` | `corporate` / `dark` / `light` / `minimal` |
| `--logo` | shipped SVG | PNG or SVG, embedded on cover |
| `--out` | `reports/<engagement>/` | output directory |

### tui / version

```bash
wpf tui                                      # Textual launcher (copy generated commands)
wpf version                                  # print version
```

---

## Scope file

`scope/scope.yml` - required for every active subcommand. Edit it directly or use `wpf scope ...`.

```yaml
engagement:
  name: "ACME bug-bounty 2026"
  type: bug_bounty            # bug_bounty | pentest | lab
  authorized_by: "security@acme.example"
  start: 2026-05-01
  end:   2026-08-01
scope:
  in:
    - "*.acme.example"        # wildcard - matches every subdomain (not the apex)
    - "acme.example"          # bare domain - matches apex AND every subdomain
    - "api.acme.example"      # explicit host
    - "203.0.113.0/24"        # CIDR range
    - "198.51.100.42"         # IP literal
  out:
    - "status.acme.example"   # vendor-hosted, out of scope
    - "*.dev.acme.example"
flags:
  rate_limit_rps: 10
  aggressive: false           # MUST be true to run sqlmap / exploit primitives
  user_agent: "wpf/0.1 (bug-bounty; authorized)"
```

Out-of-scope **wins** over in-scope (the rule order is: out-of-scope first, then in-scope). Every authorization decision and every tool launch is appended to `~/.local/share/wpf/audit.log.jsonl`.

---

## Self-test

A bundled bash script that proves the whole pipeline works end-to-end against a local mock target.

```bash
bash scripts/self_test.sh
```

What it does:

1. Starts `scripts/mock_target.py` on `127.0.0.1:8765` - a small HTTP server intentionally vulnerable to ~12 checks (missing headers, cookie flags, reflected XSS, exposed `.env`, debug page, CORS reflection, …).
2. Creates a `wpf-self-test` lab engagement and authorizes `127.0.0.1`.
3. Runs every implemented WSTG runner and every implemented BBB workflow.
4. Renders Markdown / PDF / DOCX with the corporate theme.
5. Asserts ≥10 findings recorded and the PDF is valid.
6. Kills the mock target.

Pass criteria - recent run:

```
✓ wpf version: 0.1.0
✓ mock target up at http://127.0.0.1:8765
✓ scope guard refusing out-of-scope hosts (expected)
✓ report.md   17 446 bytes
✓ report.pdf  126 586 bytes  (PDF document, version 1.7)
✓ report.docx 42 315 bytes
✓ 24 findings recorded
✓ self-test passed
```

Add `--cleanup` to also delete the engagement after.

---

## Tesla bug-bounty OSINT demo

Tesla operates a public Bugcrowd program covering `tesla.com` + subdomains. The demo below uses **OSINT mode**, which queries third-party data sources (CT logs via crt.sh, passive DNS via amass) and sends **zero packets to Tesla's servers**.

```bash
wpf engagement --name "tesla-bb" --type bug_bounty --authorized-by "Bugcrowd-Tesla-Public-Program"
wpf scope add 'tesla.com'
wpf scope add '*.tesla.com'
wpf recon tesla.com --mode osint
```

Output (truncated):

```
▶ recon: passive subdomain enumeration
  → amass tesla.com
  → crtsh tesla.com
  ← crtsh: 503 subdomains
  consolidated: 501 unique subdomains
✓ OSINT-only mode: 501 subdomains persisted, no probing performed
{ 'target': 'tesla.com', 'subdomains': 501, 'live': 0, ... }
```

Audit log (proves nothing was sent to Tesla):

```
event=scope.allowed host=tesla.com action=recon.passive.subdomains engagement=tesla-bb
event=run.start tool=amass cmd="amass enum -d tesla.com -nocolor -passive"
event=scope.allowed host=tesla.com action=crtsh.query engagement=tesla-bb
```

Sample of discovered subdomains (first 15, alphabetized):

```
acme-sentry-4.eng.use1.vn.cloud.tesla.com
acme-sentry-4a.eng.use1.vn.cloud.tesla.com
acs2-poc.voice.tesla.com
ai-api.tesla.com
ai-api-stg.tesla.com
ai-api-uat.tesla.com
akamai-apigateway-einvoicing-stg.tesla.com
akamai-apigateway-vehicleextinfogw-prdsvc-st.tesla.com
ams13-gpgw1.tesla.com
apac-cppm.tesla.com
apac.logs.tesla.com
apacvpn.tesla.com
apacvpn1.tesla.com
apacvpn2.tesla.com
…
```

> **Important** Move to `--mode passive` only after reading the [Tesla program rules](https://bugcrowd.com/tesla) - passive mode sends HTTP probes to discovered hosts. Aggressive scanning of Tesla properties is **not** authorized by the public program.

---

## Project layout

```
wpf/                              124 files, ~5 000 LOC Python
├── install.sh                    bootstrap installer (apt/dnf/pacman/brew aware)
├── pyproject.toml                console_script: wpf = wpf.__main__:app
├── MANIFEST.in                   ships data/, payloads/, templates/, themes/
├── LICENSE                       GPL-3.0-or-later
├── .gitignore                    excludes .venv, reports/, scope.yml, audit logs
├── README.md                     this file
├── scope/
│   └── example.scope.yml         template scope (the real scope.yml is gitignored)
├── scripts/
│   ├── self_test.sh              one-command end-to-end smoke test
│   └── mock_target.py            local "vulnnginx" demo target used by self_test
└── wpf/                          the package
    ├── __main__.py               Typer CLI
    ├── core/                     scope guard, runner, store, finding, ROI, logging
    ├── install/                  doctor + installer (bundles + apt/go/pipx/git/docker)
    ├── tools/                    30 thin subprocess wrappers
    ├── modules/
    │   ├── recon/                ars0n-style 3-round pipeline + OSINT mode
    │   ├── wstg/                 97 WSTG-XXX-NN runners (12 category files)
    │   └── bbb/                  25 Bug Bounty Bootcamp chapter workflows
    ├── report/                   Jinja2 templates + 4 CSS themes + reporter
    ├── data/                     wstg_checklist.json, bbbootcamp_workflows.json, …
    ├── payloads/                 xss / sqli / ssti / ssrf / lfi / open_redirect / cmdi
    └── tui/                      Textual launcher
```

---

## Authorization & ethics

`wpf` is for **authorized testing only** - bug-bounty programs you're enrolled in, pentests with a signed SoW, or your own labs. The scope guard is a hard gate, not a suggestion. The `--aggressive` flag in `scope.yml` is required for any module that actively exploits (sqlmap, ssrfmap, dalfox confirmation). If you don't have written permission for a target, do not run anything against it.

---

## Caveats

- **18/97 WSTG runners are real, 79 are manual stubs.** Stubs surface the PDF methodology + tool list so they're useful for an engagement, and the modular design means you can flesh out individual tests without touching anything else.
- **14/25 BBB chapters are real workflows, 11 are manual stubs.** Same logic.
- **Active recon (shuffledns brute-force)** is a hook point - install `massdns` + `shuffledns` and the pipeline auto-engages. `--mode active` is a clean no-op when those tools are missing.
- **WeasyPrint quirks.** PDF render quality depends on system Pango/Cairo. The reporter falls back to HTML if WeasyPrint imports fail, with a clear error.
- **No paid APIs by default.** Shodan/Censys/SecurityTrails/Whoxy/ProjectDiscovery PDCP cloud/WPScan/GitHub PAT - detected from env vars; absent means the stage is silently skipped.

---

## Acknowledgements

Built from:
- **OWASP WSTG v4.2** - *OWASP Web Security Testing Guide v4.2*
- *Bug Bounty Bootcamp: The Guide to Finding and Reporting Web Vulnerabilities* by **Vickie Li** (No Starch Press, 2021)
- The recon pipeline shape of [R-s0n/ars0n-framework-v2](https://github.com/R-s0n/ars0n-framework-v2)
- The ProjectDiscovery toolchain, tomnomnom's tooling, and everything else listed in `wpf/data/tooling_inventory.json`

## License

[GPL-3.0-or-later](LICENSE).
