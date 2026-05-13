"""wpf — command-line entry point. `python -m wpf` or `wpf` (via console_script)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table

from . import __version__
from .core.config import PATHS
from .core.engagement import EngagementContext
from .core.finding import Finding
from .core.logging import banner, console, error, info, ok, setup_logging, step, warn
from .core.scope import (Scope, ScopeError, active_engagement, default_scope_path,
                          delete_engagement, engagement_path, list_engagements, set_active)
from .core.store import (dump_engagement_findings, get_or_create_engagement,
                          insert_finding, store)
from .install import doctor as _doctor
from .install import installer as _installer

app = typer.Typer(help="wpf — Web Pentest Framework (WSTG v4.2 + Bug Bounty Bootcamp + ars0n recon)",
                  no_args_is_help=True, rich_markup_mode="rich")


# ----- options shared across subcommands -----

VerboseOpt = typer.Option(0, "-v", "--verbose", count=True, help="-v / -vv")


def _load_scope(path: Optional[Path] = None) -> Scope:
    s = Scope.load(path)
    if not s.in_scope:
        warn(f"no in-scope entries in {s.source_path or default_scope_path()}; active probes will be refused")
    return s


# =========================================================================
# version / banner
# =========================================================================

@app.command()
def version():
    """Print version and exit."""
    typer.echo(f"wpf {__version__}")


@app.callback()
def main(verbose: int = VerboseOpt):
    setup_logging(verbose)


# =========================================================================
# doctor / install
# =========================================================================

@app.command()
def doctor():
    """Show which of the 91 supported tools are installed on this system."""
    banner()
    raise typer.Exit(_doctor.main())


@app.command(name="install")
def install_cmd(
    tools: list[str] = typer.Argument(None, help="Tool names, bundle names, or 'all'."),
    methods: Optional[str] = typer.Option(None, "--methods", help="Comma-list of allowed methods (apt,go,pipx,git,docker,npm,cargo)."),
    list_bundles: bool = typer.Option(False, "--list-bundles", help="Print install bundles and exit."),
):
    """Install tools or bundles via apt/go/pipx/git/docker.

    Bundles (use the bundle NAME as a tool argument):
      passive  recon  probe  crawl  fuzz  xss  sqli  ssrf  ssti  cors
      jwt      cms    takeover  params  vuln  smuggle  cloud  mobile  proxy

    Examples:
      wpf install passive            # install the passive-recon bundle
      wpf install recon xss          # bundles can be chained
      wpf install sqlmap httpx       # specific tools
      wpf install all                # everything in install_matrix.json
      wpf install --list-bundles     # see what each bundle expands to
    """
    if list_bundles:
        from .install.installer import BUNDLES
        tbl = Table(title=f"install bundles ({len(BUNDLES)})")
        tbl.add_column("Bundle", style="bold")
        tbl.add_column("Tools")
        for k in sorted(BUNDLES):
            tbl.add_row(k, ", ".join(BUNDLES[k]))
        console.print(tbl)
        return
    allowed = set(methods.split(",")) if methods else None
    if not tools:
        from .install.matrix import load_install_matrix
        names = sorted(load_install_matrix().keys())
        info(f"{len(names)} tools available — run 'wpf install <name|bundle>...' or 'wpf install all'")
        info("bundles: passive recon probe crawl fuzz xss sqli ssrf ssti cors jwt cms takeover params vuln smuggle cloud mobile proxy")
        info("see `wpf install --list-bundles` for contents")
        for n in names:
            console.print(f"  • {n}")
        return
    if len(tools) == 1 and tools[0].lower() == "all":
        results = _installer.install_all(allowed_methods=allowed)
    else:
        resolved = _installer.resolve_targets(tools)
        if set(resolved) != set(tools):
            info(f"expanded to {len(resolved)} tools: {', '.join(resolved)}")
        results = _installer.install_many(resolved, allowed_methods=allowed)
    n_ok = sum(1 for r in results if r.success)
    info(f"installed {n_ok}/{len(results)} tools")


# =========================================================================
# scope / engagement
# =========================================================================

scope_app = typer.Typer(help="Authorization scope management")
app.add_typer(scope_app, name="scope")


def _resolve_scope_path(name: Optional[str]) -> Path:
    """Return the scope file for an engagement name, or the active one if None.

    Raises typer.Exit(2) with a helpful message if nothing matches.
    """
    if name:
        p = engagement_path(name)
        if not p.exists():
            error(f"no such engagement: {name}")
            available = list_engagements()
            if available:
                info("available: " + ", ".join(available))
            else:
                info("no engagements yet — run: wpf engagement --name X --type bug_bounty")
            raise typer.Exit(2)
        return p
    p = default_scope_path()
    if not p.exists():
        error("no active engagement and no scope file at " + str(p))
        info("run: wpf engagement --name X --type bug_bounty")
        raise typer.Exit(2)
    return p


@scope_app.command("init")
def scope_init(name: str = typer.Option("default", "--name"),
               type_: str = typer.Option("lab", "--type", help="bug_bounty | pentest | lab"),
               authorized_by: str = typer.Option("", "--authorized-by")):
    """Create a starter scope file for an engagement and make it active."""
    s = Scope()
    s.engagement.name = name
    s.engagement.type = type_
    s.engagement.authorized_by = authorized_by
    out = s.save(engagement_path(name))
    set_active(name)
    ok(f"created {out} (now active) — edit `in:` to authorize targets")


@scope_app.command("list")
def scope_list():
    """List every engagement scope file under ./scope/ (marks the active one)."""
    names = list_engagements()
    active = active_engagement()
    if not names:
        warn("no engagements yet — run: wpf engagement --name X --type bug_bounty")
        return
    tbl = Table(title=f"engagements ({len(names)})")
    tbl.add_column("Name", style="bold")
    tbl.add_column("Active")
    tbl.add_column("Type")
    tbl.add_column("In scope")
    tbl.add_column("Path")
    for n in names:
        try:
            s = Scope.load(engagement_path(n))
        except Exception:
            continue
        tbl.add_row(n, "[green]✓[/green]" if n == active else "",
                    s.engagement.type, str(len(s.in_scope)),
                    str(engagement_path(n)))
    console.print(tbl)


@scope_app.command("use")
def scope_use(name: str):
    """Switch the active engagement."""
    try:
        link = set_active(name)
    except FileNotFoundError:
        error(f"no such engagement: {name}")
        raise typer.Exit(2)
    ok(f"active = {name}  ({link} → {engagement_path(name).name})")


@scope_app.command("add")
def scope_add(entry: str,
              out: bool = typer.Option(False, "--out", help="Add to out-of-scope instead."),
              engagement: Optional[str] = typer.Option(None, "--engagement", "-e",
                                                       help="Target engagement (default: active).")):
    """Add an entry to the active (or named) engagement's in-scope list."""
    path = _resolve_scope_path(engagement)
    s = Scope.load(path)
    (s.add_out if out else s.add_in)(entry)
    s.save(path)
    ok(f"{'out-of-scope' if out else 'in-scope'} += {entry}  ({path.name})")


@scope_app.command("show")
def scope_show(name: Optional[str] = typer.Argument(None,
                help="Engagement to show. Defaults to the active engagement.")):
    """Show an engagement's scope file. With no argument, shows the active one.

    Examples:
      wpf scope show                # active engagement
      wpf scope show tesla-bb       # named engagement
    """
    path = _resolve_scope_path(name)
    s = Scope.load(path)
    active = active_engagement()
    flag = "[green](active)[/green]" if s.engagement.name == active else ""
    console.print(f"[bold]engagement:[/bold] {s.engagement.name}  type={s.engagement.type} {flag}")
    console.print(f"[bold]authorized_by:[/bold] {s.engagement.authorized_by or '—'}")
    console.print(f"[bold]source:[/bold] {path}")
    console.print(f"[bold]in:[/bold]  {s.in_scope}")
    console.print(f"[bold]out:[/bold] {s.out_scope}")
    console.print(f"[bold]aggressive:[/bold] {s.aggressive}, [bold]rate_limit_rps:[/bold] {s.rate_limit_rps}")


@scope_app.command("check")
def scope_check(host: str,
                engagement: Optional[str] = typer.Option(None, "--engagement", "-e")):
    """Exit 0 if HOST is in scope of the active (or named) engagement, non-zero otherwise."""
    path = _resolve_scope_path(engagement)
    s = Scope.load(path)
    if s.is_in_scope(host):
        ok(f"{host} is in scope ({s.engagement.name})")
        raise typer.Exit(0)
    error(f"{host} is NOT in scope ({s.engagement.name})")
    raise typer.Exit(2)


@scope_app.command("remove")
def scope_remove(name: str = typer.Argument(..., help="Engagement name to remove."),
                  yes: bool = typer.Option(False, "--yes", "-y",
                       help="Skip the interactive confirmation."),
                  purge_db: bool = typer.Option(False, "--purge-db",
                       help="Also delete the engagement's rows from the SQLite store.")):
    """Remove an entire engagement (its scope file, and optionally its DB row).

    Examples:
      wpf scope remove tesla-bb            # delete scope/tesla-bb.yml (confirm)
      wpf scope remove tesla-bb -y         # no confirmation
      wpf scope remove tesla-bb -y --purge-db   # also wipe findings / runs
    """
    path = engagement_path(name)
    if not path.exists():
        error(f"no such engagement: {name}")
        names = list_engagements()
        if names:
            info("available: " + ", ".join(names))
        raise typer.Exit(2)

    if not yes:
        warn(f"about to delete {path}")
        if purge_db:
            warn("AND its rows from the SQLite store (findings, runs, assets, …)")
        try:
            ans = input("Type the engagement name to confirm: ").strip()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans != name:
            error("confirmation mismatch — aborted")
            raise typer.Exit(1)

    removed, was_active = delete_engagement(name)
    ok(f"removed {removed}")
    if was_active:
        info("(it was the active engagement; the symlink was cleared)")

    if purge_db:
        with store() as conn:
            row = conn.execute("SELECT id FROM engagements WHERE name=?", (name,)).fetchone()
            if row:
                # ON DELETE CASCADE handles targets/tool_runs/assets/findings/notes.
                conn.execute("DELETE FROM engagements WHERE id=?", (row["id"],))
                ok(f"purged engagement #{row['id']} from the DB")
            else:
                info("no matching DB row to purge")


@scope_app.command("edit")
def scope_edit(name: Optional[str] = typer.Argument(None,
                help="Engagement to edit. Defaults to the active engagement.")):
    """Open an engagement's scope file in nano (or $EDITOR if set).

    Examples:
      wpf scope edit                # edit the active engagement
      wpf scope edit tesla-bb       # edit a specific engagement
    """
    import os
    import shutil
    import subprocess

    path = _resolve_scope_path(name)
    editor = (os.environ.get("EDITOR") or os.environ.get("VISUAL")
              or ("nano" if shutil.which("nano") else "vi"))
    info(f"opening {path} in {editor}")
    rc = subprocess.call([editor, str(path)])
    if rc != 0:
        warn(f"editor exited {rc}")
    # Re-load and print so the operator sees the result
    try:
        s = Scope.load(path)
        console.print(f"[green]in:[/green]  {s.in_scope}")
        console.print(f"[green]out:[/green] {s.out_scope}")
    except Exception as e:
        error(f"could not parse {path} after edit: {e}")
        raise typer.Exit(2)


@app.command(name="engagement")
def engagement_init(name: str = typer.Option(..., "--name"),
                    type_: str = typer.Option("lab", "--type"),
                    authorized_by: str = typer.Option("", "--authorized-by")):
    """Scaffold an engagement: write scope/<name>.yml, make it active, create the DB row.

    Each engagement gets its own scope file. The active one is exposed via the
    symlink scope/scope.yml. Switch between engagements with `wpf scope use NAME`.
    """
    s = Scope()
    s.engagement.name = name
    s.engagement.type = type_
    s.engagement.authorized_by = authorized_by
    p = s.save(engagement_path(name))
    set_active(name)
    with store() as conn:
        eid = get_or_create_engagement(conn, name, type_=type_, authorized_by=authorized_by,
                                       scope_path=str(p))
    ok(f"engagement #{eid} '{name}' scaffolded at {p} (now active)")


# =========================================================================
# recon
# =========================================================================

@app.command()
def recon(target: str,
          mode: str = typer.Option("passive", "--mode", help="passive | active | all"),
          max_subdomains: int = typer.Option(2500, "--max-subdomains"),
          max_live: int = typer.Option(500, "--max-live"),
          no_screenshots: bool = typer.Option(False, "--no-screenshots"),
          no_takeover: bool = typer.Option(False, "--no-takeover")):
    """Run the ars0n-style 3-round recon pipeline against TARGET."""
    from .modules.recon import pipeline
    s = _load_scope()
    s.add_in(target.lstrip("*.")) if not s.is_in_scope(target.lstrip("*.")) and s.engagement.type == "lab" else None
    s.save()  # persist any auto-added lab entry
    try:
        result = asyncio.run(pipeline.run(target, scope=s, mode=mode,
                                           max_subdomains=max_subdomains, max_live=max_live,
                                           do_screenshots=not no_screenshots,
                                           do_takeover=not no_takeover))
    except ScopeError as e:
        error(str(e))
        raise typer.Exit(2)
    console.print(result.summary())


# =========================================================================
# scan-wstg / hunt
# =========================================================================

@app.command(name="scan-wstg")
def scan_wstg(
    target: Optional[str] = typer.Argument(None),
    test_id: Optional[str] = typer.Option(None, "--id", help="WSTG-XXX-NN id"),
    category: Optional[str] = typer.Option(None, "--category", help="INFO|CONF|...|APIT"),
    list_: bool = typer.Option(False, "--list", help="List all available test IDs"),
):
    """Run a single WSTG test, all of a category, or list them."""
    from .modules.wstg import REGISTRY
    # Ensure registration ran
    import wpf.modules.wstg  # noqa: F401

    if list_ or not target:
        tbl = Table(title=f"WSTG runners ({len(REGISTRY)} registered)")
        tbl.add_column("ID"); tbl.add_column("Name"); tbl.add_column("Category"); tbl.add_column("Mode")
        for tid in sorted(REGISTRY):
            cls = REGISTRY[tid]
            mode = "automated" if cls.__name__.startswith("WSTG_") and "Manual" not in cls.__bases__[0].__name__ else "manual"
            tbl.add_row(tid, cls.name or tid, cls.category, mode)
        console.print(tbl)
        return

    s = _load_scope()

    ids: list[str] = []
    if test_id:
        ids = [test_id.upper()]
    elif category:
        ids = [tid for tid, cls in REGISTRY.items() if cls.category.upper() == category.upper()]
    else:
        ids = list(REGISTRY.keys())

    findings_total: list[Finding] = []
    for tid in ids:
        cls = REGISTRY.get(tid)
        if not cls:
            warn(f"unknown test id {tid}")
            continue
        step(f"{tid} → {cls.name or tid}")
        try:
            fs = asyncio.run(cls().run(target, scope=s))
        except ScopeError as e:
            error(str(e))
            raise typer.Exit(2)
        except Exception as e:
            warn(f"{tid} failed: {e}")
            continue
        if fs:
            with store() as conn:
                eid = get_or_create_engagement(conn, s.engagement.name or "default",
                                                type_=s.engagement.type or "lab")
                for f in fs:
                    insert_finding(conn, eid, f)
            findings_total.extend(fs)
    ok(f"recorded {len(findings_total)} findings")
    _persist_engagement_findings(s.engagement.name or "default")


@app.command()
def hunt(
    target: Optional[str] = typer.Argument(None),
    chapter: Optional[str] = typer.Option(None, "--chapter", help="e.g. ch06_xss"),
    list_: bool = typer.Option(False, "--list"),
):
    """Run a Bug Bounty Bootcamp chapter workflow against TARGET."""
    import wpf.modules.bbb  # noqa: F401
    from .modules.bbb import REGISTRY
    if list_ or not target:
        tbl = Table(title=f"BBB chapter workflows ({len(REGISTRY)})")
        tbl.add_column("Key"); tbl.add_column("Ch."); tbl.add_column("Title")
        for k, cls in sorted(REGISTRY.items()):
            tbl.add_row(k, str(cls.chapter_number), cls.title)
        console.print(tbl)
        return
    s = _load_scope()
    if chapter:
        cls = REGISTRY.get(chapter)
        if not cls:
            error(f"unknown chapter key {chapter!r}; try `wpf hunt --list`")
            raise typer.Exit(2)
        targets = [cls]
    else:
        targets = list(REGISTRY.values())
    findings_total: list[Finding] = []
    for cls in targets:
        step(f"{cls.key} → {cls.title}")
        try:
            fs = asyncio.run(cls().run(target, scope=s))
        except ScopeError as e:
            error(str(e))
            raise typer.Exit(2)
        except Exception as e:
            warn(f"{cls.key} failed: {e}")
            continue
        if fs:
            with store() as conn:
                eid = get_or_create_engagement(conn, s.engagement.name or "default",
                                                type_=s.engagement.type or "lab")
                for f in fs:
                    insert_finding(conn, eid, f)
            findings_total.extend(fs)
    ok(f"recorded {len(findings_total)} findings")
    _persist_engagement_findings(s.engagement.name or "default")


# =========================================================================
# report
# =========================================================================

@app.command()
def report(
    engagement: Optional[str] = typer.Option(None, "--engagement", "-e",
                  help="Engagement to render. Defaults to the active engagement."),
    formats: str = typer.Option("md,pdf,docx", "--format", "-f"),
    theme: str = typer.Option("corporate", "--theme", "-t",
                  help="corporate|dark|light|minimal"),
    logo: Optional[Path] = typer.Option(None, "--logo", "-l"),
    out: Optional[Path] = typer.Option(None, "--out", "-o",
                  help="Output directory. Defaults to reports/<engagement>/."),
    list_: bool = typer.Option(False, "--list",
                  help="List engagements with finding counts and exit."),
):
    """Render report.md / report.pdf / report.docx for an engagement.

    Examples:
      wpf report                                # render the active engagement
      wpf report -e ACME-2026                   # render a specific engagement
      wpf report -e ACME-2026 -o /tmp/out/      # custom output directory
      wpf report -e ACME-2026 -t dark -l logo.png
      wpf report --list                         # show every engagement + finding count
    """
    from .report import reporter
    from .install import doctor as docmod

    # `--list` — print finding counts for every engagement and exit
    if list_:
        with store() as conn:
            rows = conn.execute(
                "SELECT e.name, e.type, COUNT(f.id) AS findings "
                "FROM engagements e LEFT JOIN findings f ON f.engagement_id=e.id "
                "GROUP BY e.id ORDER BY e.name"
            ).fetchall()
        if not rows:
            warn("no engagements in the store yet")
            return
        active = active_engagement()
        tbl = Table(title=f"engagements ({len(rows)})")
        tbl.add_column("Name", style="bold"); tbl.add_column("Active")
        tbl.add_column("Type"); tbl.add_column("Findings")
        for r in rows:
            tbl.add_row(r["name"],
                        "[green]✓[/green]" if r["name"] == active else "",
                        r["type"] or "", str(r["findings"]))
        console.print(tbl)
        return

    # Resolve which scope file to load
    if engagement:
        p = engagement_path(engagement)
        if not p.exists():
            error(f"no such engagement: {engagement}")
            avail = list_engagements()
            if avail:
                info("available: " + ", ".join(avail))
            raise typer.Exit(2)
        s = Scope.load(p)
    else:
        s = _load_scope()

    formats_set = {x.strip() for x in formats.split(",") if x.strip()}
    artifacts = reporter.generate(scope=s, formats=formats_set, theme=theme, logo=logo, out_dir=out,
                                   tool_status=docmod.status(),
                                   wstg_implemented=_count_implemented_wstg())
    for k, p in artifacts.items():
        ok(f"{k.upper()}: {p}")
    # Always also drop machine-readable findings next to the human report
    try:
        fjson = dump_engagement_findings(s.engagement.name,
                                          Path(out) if out else PATHS.reports)
        if fjson:
            ok(f"FINDINGS: {fjson}")
    except Exception as e:
        warn(f"could not write findings.json: {e}")


def _count_implemented_wstg() -> int:
    import wpf.modules.wstg  # noqa: F401
    from .modules.wstg import REGISTRY
    from .modules.wstg._base import ManualChecklistTest
    return sum(1 for cls in REGISTRY.values() if not issubclass(cls, ManualChecklistTest) or cls is ManualChecklistTest)


def _persist_engagement_findings(engagement_name: str) -> None:
    """Write reports/<engagement>/findings.json + findings_summary.txt after a scan."""
    try:
        path = dump_engagement_findings(engagement_name, PATHS.reports)
        if path:
            ok(f"  findings saved to {path}")
    except Exception as e:  # never fail a scan because of writing the file
        warn(f"could not write findings.json: {e}")


# =========================================================================
# full — interactive end-to-end pentest pipeline
# =========================================================================

@app.command()
def full(
    name:          Optional[str] = typer.Option(None, "--name",          help="Engagement name (skips the prompt)."),
    type_:         Optional[str] = typer.Option(None, "--type",          help="bug_bounty | pentest | lab"),
    authorized_by: Optional[str] = typer.Option(None, "--authorized-by"),
    in_scope:      Optional[str] = typer.Option(None, "--in",            help="Comma-list of in-scope hosts/wildcards/CIDRs."),
    out_scope:     Optional[str] = typer.Option(None, "--out-scope",     help="Comma-list of out-of-scope entries."),
    target:        Optional[str] = typer.Option(None, "--target",        help="Primary URL or host to scan."),
    mode:          str           = typer.Option("passive", "--mode",     help="osint | passive | active | all"),
    theme:         str           = typer.Option("corporate", "--theme"),
    logo:          Optional[Path] = typer.Option(None, "--logo"),
    out_dir:       Optional[Path] = typer.Option(None, "--out", "-o",    help="Output directory."),
    skip_recon:    bool          = typer.Option(False, "--skip-recon"),
    skip_wstg:     bool          = typer.Option(False, "--skip-wstg"),
    skip_hunt:     bool          = typer.Option(False, "--skip-hunt"),
    yes:           bool          = typer.Option(False, "--yes", "-y",    help="Accept all defaults; non-interactive."),
):
    """End-to-end pipeline: ask for engagement + scope + target, run everything, write a report.

    Prompts for what's missing on the command line, then:

      1. Creates the engagement (scope/<name>.yml) and marks it active.
      2. wpf recon TARGET --mode <mode>
      3. wpf scan-wstg TARGET            (every implemented WSTG runner)
      4. wpf hunt TARGET                 (every implemented BBB chapter workflow)
      5. wpf report --format md,pdf,docx --theme <theme> --out <out-dir>

    All findings land in:   reports/<name>/{report.md,.pdf,.docx, findings.json}

    Examples:
      wpf full                                                  # fully interactive
      wpf full --name acme --target https://acme.example        # mostly interactive
      wpf full --name acme --in 'acme.example,*.acme.example' \\
               --target https://acme.example --mode passive -y  # non-interactive
    """
    import wpf.modules.wstg  # noqa: F401
    import wpf.modules.bbb   # noqa: F401
    from .modules.wstg import REGISTRY as WSTG_REGISTRY
    from .modules.bbb  import REGISTRY as BBB_REGISTRY
    from .modules.recon import pipeline as recon_pipeline
    from .report import reporter
    from .install import doctor as docmod

    banner()

    # ── gather inputs (prompt when missing, unless --yes) ─────────────────
    def ask(label: str, default: str = "", required: bool = False) -> str:
        if yes:
            return default
        suffix = f" [{default}]" if default else (" *" if required else "")
        try:
            ans = input(f"  {label}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            error("aborted")
            raise typer.Exit(130)
        return ans or default

    info("interactive setup — press Enter to accept a [default]")
    name          = name          or ask("engagement name", "wpf-full", required=True)
    type_         = type_         or ask("type (bug_bounty | pentest | lab)", "lab")
    authorized_by = authorized_by or ask("authorized by", "self")

    if in_scope is None:
        info("in-scope entries — comma-separated (e.g. 'acme.example, *.acme.example, 10.0.0.0/24')")
        in_scope = ask("in-scope", "")
    if out_scope is None:
        out_scope = ask("out-of-scope (optional)", "")
    if target is None:
        target = ask("primary target URL/host (used for the scans)", "")

    in_list  = [x.strip() for x in (in_scope  or "").split(",") if x.strip()]
    out_list = [x.strip() for x in (out_scope or "").split(",") if x.strip()]
    if not in_list:
        error("no in-scope entries — refusing to scan")
        raise typer.Exit(2)
    if not target:
        error("no target supplied — refusing to scan")
        raise typer.Exit(2)

    # ── 1. scaffold the engagement + scope file + DB row ──────────────────
    step(f"1/5  creating engagement '{name}'")
    s = Scope()
    s.engagement.name = name
    s.engagement.type = type_
    s.engagement.authorized_by = authorized_by
    for entry in in_list:
        s.add_in(entry)
    for entry in out_list:
        s.add_out(entry)
    path = s.save(engagement_path(name))
    set_active(name)
    with store() as conn:
        get_or_create_engagement(conn, name, type_=type_, authorized_by=authorized_by,
                                  scope_path=str(path))
    ok(f"  scope written to {path} (now active)")

    # ── 2. recon ──────────────────────────────────────────────────────────
    if not skip_recon:
        step(f"2/5  recon — mode={mode}")
        try:
            result = asyncio.run(recon_pipeline.run(_strip_url_host(target), scope=s, mode=mode))
            ok(f"  recon: {result.subdomains and len(result.subdomains) or 0} subdomains, "
               f"{len(result.url_facts)} live, "
               f"{len(result.takeover_findings)} takeover findings")
        except ScopeError as e:
            error(str(e)); raise typer.Exit(2)
        except Exception as e:
            warn(f"  recon failed: {e}  (continuing with WSTG/hunt)")
    else:
        info("2/5  recon — skipped (--skip-recon)")

    # ── 3. WSTG full battery ──────────────────────────────────────────────
    if not skip_wstg:
        step(f"3/5  WSTG — running {len(WSTG_REGISTRY)} test runners")
        wstg_findings = 0
        for tid in sorted(WSTG_REGISTRY):
            cls = WSTG_REGISTRY[tid]
            try:
                fs = asyncio.run(cls().run(target, scope=s))
            except ScopeError as e:
                warn(f"  {tid}: refused by scope ({e}) — continuing")
                continue
            except Exception:
                continue
            if fs:
                with store() as conn:
                    eid = get_or_create_engagement(conn, name, type_=type_,
                                                   authorized_by=authorized_by)
                    for f in fs:
                        insert_finding(conn, eid, f)
                wstg_findings += len(fs)
        ok(f"  WSTG: {wstg_findings} findings recorded")
        _persist_engagement_findings(name)
    else:
        info("3/5  WSTG — skipped (--skip-wstg)")

    # ── 4. Bug Bounty Bootcamp full battery ───────────────────────────────
    if not skip_hunt:
        step(f"4/5  BBB — running chapter workflows")
        bbb_findings = 0
        # ch05_recon is delegating to the recon pipeline which already ran above —
        # skip to avoid double-work and the URL-vs-host argument mismatch.
        for key, cls in sorted(BBB_REGISTRY.items()):
            if key == "ch05_recon":
                continue
            try:
                fs = asyncio.run(cls().run(target, scope=s))
            except ScopeError as e:
                warn(f"  {key}: refused by scope ({e}) — continuing")
                continue
            except Exception as e:
                warn(f"  {key}: failed ({e}) — continuing")
                continue
            if fs:
                with store() as conn:
                    eid = get_or_create_engagement(conn, name, type_=type_,
                                                   authorized_by=authorized_by)
                    for f in fs:
                        insert_finding(conn, eid, f)
                bbb_findings += len(fs)
        ok(f"  BBB: {bbb_findings} findings recorded")
        _persist_engagement_findings(name)
    else:
        info("4/5  BBB — skipped (--skip-hunt)")

    # ── 5. render report ──────────────────────────────────────────────────
    step("5/5  rendering report — md, pdf, docx")
    out_dir_resolved = Path(out_dir) if out_dir else (PATHS.reports / name)
    out_dir_resolved.mkdir(parents=True, exist_ok=True)
    artefacts = reporter.generate(scope=s, formats={"md", "pdf", "docx"},
                                   theme=theme, logo=logo, out_dir=out_dir_resolved,
                                   tool_status=docmod.status(),
                                   wstg_implemented=_count_implemented_wstg())
    # Also drop findings.json beside them
    try:
        dump_engagement_findings(name, out_dir_resolved.parent
                                  if out_dir_resolved.name == name else out_dir_resolved)
    except Exception:
        pass

    # ── final summary ─────────────────────────────────────────────────────
    console.print()
    ok(f"engagement:      {name}")
    ok(f"scope file:      {path}")
    ok(f"output folder:   {out_dir_resolved}")
    for k, p in artefacts.items():
        ok(f"  {k.upper()}: {p}")
    info("audit log:       " + str(PATHS.data / "audit.log.jsonl"))


def _strip_url_host(target: str) -> str:
    """Pull the hostname out of a URL for recon (which expects a bare domain)."""
    from urllib.parse import urlparse
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


# =========================================================================
# tui
# =========================================================================

@app.command()
def tui():
    """Open the interactive Textual menu."""
    try:
        from .tui.app import run
    except Exception as e:
        error(f"textual UI not available: {e}")
        raise typer.Exit(2)
    run()


if __name__ == "__main__":  # pragma: no cover
    app()
