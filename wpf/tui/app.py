"""Textual TUI — a compact menu wrapping the same subcommands as the CLI."""
from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, Footer, Header, Static, Input


MENU = [
    ("doctor",           "Inventory installed tools"),
    ("recon (passive)",  "Run passive recon on a target"),
    ("scan-wstg --list", "List WSTG test runners"),
    ("hunt --list",      "List BBB chapter workflows"),
    ("report",           "Render the report (MD/PDF/DOCX)"),
]


class WpfTui(App):
    CSS = """
    Screen { background: $surface; }
    Static.banner { color: cyan; padding: 1 2; }
    Button { width: 36; }
    .row { padding: 0 2; }
    #log { height: 12; border: round white; padding: 0 1; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("wpf — Web Pentest Framework\nPick an action. Real work happens at the CLI; the TUI is a launcher.",
                     classes="banner")
        with Vertical():
            with Horizontal(classes="row"):
                yield Input(placeholder="target (optional)", id="target")
            for label, _desc in MENU:
                yield Button(label, classes="row", id="btn-" + label.replace(" ", "_").replace("(", "").replace(")", "").replace("--", ""))
            yield Static("", id="log")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        log = self.query_one("#log", Static)
        cmd = event.button.label
        target = self.query_one("#target", Input).value.strip()
        log.update(f"$ wpf {cmd} {target if target else ''}\n"
                   "(launchpad only — copy this command into a terminal to execute)")


def run() -> None:
    WpfTui().run()
