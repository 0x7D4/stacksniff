"""CLI entry point for stacksniff."""
# ruff: noqa: B008

from __future__ import annotations

import asyncio
import io
import sys
from pathlib import Path  # noqa: TC003
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from stacksniff import __version__
from stacksniff.scanner import Scanner
from stacksniff.updater import FullUpdateResult, fetch_and_convert
from stacksniff.updater_seclists import fetch_seclists

app = typer.Typer(help="stacksniff -- detect web technology stacks and APIs")

# Reconfigure stdout to UTF-8 on Windows to avoid UnicodeEncodeError from
# Rich block/arrow characters in the legacy Windows console.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass

console = Console(legacy_windows=False)


def version_callback(value: bool) -> None:
    """Print the version and exit."""
    if value:
        console.print(f"stacksniff {__version__}")
        raise typer.Exit()


@app.callback()
def cb(
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
    """Web Technology Stack Sniffer."""


def format_confidence(conf: float) -> str:
    """Format confidence as a shaded block string."""
    num_solid = int(conf * 5)
    pct = int(conf * 100)
    blocks = "█" * num_solid + "░" * (5 - num_solid)
    if conf >= 0.85:
        return f"[bold green]{blocks} {pct}%[/bold green]"
    elif conf >= 0.70:
        return f"[yellow]{blocks} {pct}%[/yellow]"
    else:
        return f"{blocks} {pct}%"


@app.command()
def scan(
    url: str = typer.Argument(..., help="URL to scan"),
    json_output: bool = typer.Option(
        False,
        "--json/--no-json",
        help="Output raw JSON to stdout",
    ),
    browser: bool = typer.Option(
        True,
        "--browser/--no-browser",
        help="Enable headless browser analysis",
    ),
    fingerprints: Path | None = typer.Option(
        None,
        "--fingerprints",
        help="Path to custom tech.yaml fingerprints",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    timeout: float = typer.Option(
        30.0,
        "--timeout",
        help="Timeout in seconds for collectors",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Write JSON report to this file",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Print detailed evidence for matched technologies",
    ),
) -> None:
    """Scan a target URL and detect its stack + API endpoints."""

    async def run_scan() -> Any:
        scanner = Scanner()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
            disable=json_output,
        ) as progress:
            http_task = progress.add_task("[yellow]HTTP analysis", total=100)

            # Pre-check playwright to determine if browser task will run
            playwright_installed = False
            if browser:
                try:
                    import playwright  # noqa: F401

                    playwright_installed = True
                except ImportError:
                    pass

            browser_task = None
            if browser and playwright_installed:
                browser_task = progress.add_task("[cyan]Browser analysis", total=100)

            def progress_callback(phase: str, status: str) -> None:
                if phase == "http":
                    if status == "started":
                        progress.update(
                            http_task,
                            description="[yellow]HTTP analysis: scanning...",
                        )
                    elif status == "completed":
                        progress.update(
                            http_task,
                            completed=100,
                            description="[green]HTTP analysis: done",
                        )
                elif phase == "browser" and browser_task is not None:
                    if status == "started":
                        progress.update(
                            browser_task,
                            description="[cyan]Browser analysis: scanning...",
                        )
                    elif status == "completed":
                        progress.update(
                            browser_task,
                            completed=100,
                            description="[green]Browser analysis: done",
                        )

            return await scanner.scan(
                url,
                browser=browser,
                timeout=timeout,
                fingerprints_path=fingerprints,
                progress_callback=progress_callback,
            )

    if not json_output:
        console.print(
            Panel(
                f"stacksniff — scanning [bold cyan]{url}[/bold cyan]",
                style="bold blue",
            )
        )

    # Run the scan
    result = asyncio.run(run_scan())

    # Write report if requested
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result.to_json())

    if json_output:
        # Print raw JSON directly to stdout
        print(result.to_json())
        return

    # Render Styled CLI tables
    # 1. Tech Table
    table = Table(
        title="Detected Technologies",
        box=None,
        show_header=True,
        header_style="bold blue",
    )
    table.add_column("Technology", style="bold")
    table.add_column("Category")
    table.add_column("Version")
    table.add_column("Confidence")

    for tech in result.technologies:
        table.add_row(
            tech.name,
            tech.category,
            tech.version or "",
            format_confidence(tech.confidence),
        )
        if verbose and tech.evidence:
            for ev in tech.evidence:
                table.add_row(
                    f"  [dim]↳ {ev.source}[/dim]",
                    f"[dim]{ev.key}[/dim]",
                    "",
                    f"[dim]matched: {ev.matched}[/dim]",
                )

    console.print(table)
    console.print()

    # 2. API Endpoints
    panel_title = "[bold cyan]Detected API Endpoints[/bold cyan]"
    if getattr(result, "openapi_spec_found", False):
        panel_title = "[bold cyan]Detected API Endpoints (Full API spec found)[/bold cyan]"

    if result.api_endpoints:
        ep_lines = []
        for ep in result.api_endpoints:
            ct_str = f" → [cyan]{ep.content_type}[/cyan]" if ep.content_type else ""
            pm = ep.pattern_matched or ""
            pat_str = f" [dim]({pm})[/dim]" if pm else ""

            # Color-code SecLists endpoints by status_label embedded in pattern
            if "SecLists/" in pm:
                if "(auth-required)" in pm:
                    method_fmt = f"[AUTH] [yellow]{ep.method:6}[/yellow]"
                elif "(forbidden)" in pm:
                    method_fmt = f"[DENY] [dim]{ep.method:6}[/dim]"
                elif "redirect" in pm.lower():
                    method_fmt = f"[-->] [dim cyan]{ep.method:6}[/dim cyan]"
                else:  # exposed (200)
                    method_fmt = f"[bold green]{ep.method:6}[/bold green]"
            else:
                method_fmt = f"[bold green]{ep.method:6}[/bold green]"

            ep_lines.append(f"• {method_fmt} {ep.url}{ct_str}{pat_str}")
        endpoints_panel = Panel(
            "\n".join(ep_lines),
            title=panel_title,
            title_align="left",
            border_style="cyan",
        )
    else:
        endpoints_panel = Panel(
            "[dim]No API endpoints detected.[/dim]",
            title=panel_title,
            title_align="left",
            border_style="cyan",
        )

    console.print(endpoints_panel)

    # 3. External Domain Dependencies table
    ext_deps = getattr(result, "external_dependencies", [])
    if ext_deps:
        _category_color = {
            "cdn": "blue",
            "analytics": "yellow",
            "security": "green",
            "maps": "cyan",
            "advertising": "magenta",
        }

        ext_table = Table(
            title="External Domain Dependencies",
            box=None,
            show_header=True,
            header_style="bold blue",
        )
        ext_table.add_column("Domain", style="bold")
        ext_table.add_column("Technology")
        ext_table.add_column("Category")
        ext_table.add_column("Types", style="dim")
        ext_table.add_column("Requests", justify="right")

        for dep in sorted(ext_deps, key=lambda d: -d.get("request_count", 0)):
            cat = dep.get("category", "Unclassified")
            cat_lower = cat.lower()
            color = next(
                (v for k, v in _category_color.items() if k in cat_lower),
                "dim",
            )
            tech_name = dep.get("technology_name") or ""
            types_str = ", ".join(dep.get("resource_types", []))
            ext_table.add_row(
                dep.get("domain", ""),
                tech_name,
                f"[{color}]{cat}[/{color}]",
                types_str,
                str(dep.get("request_count", 0)),
            )

        console.print()
        console.print(ext_table)

    # 4. Internal Domain Dependencies table (CT logs)
    int_subs = getattr(result, "internal_subdomains", [])
    console.print()
    int_table = Table(
        title="Internal Domain Dependencies (via CT logs)",
        box=None,
        show_header=True,
        header_style="bold blue",
    )
    int_table.add_column("Subdomain", style="bold")
    int_table.add_column("Status", justify="center")
    int_table.add_column("Technology")
    int_table.add_column("Response Time", justify="right", style="dim")

    if int_subs:
        for sub in int_subs:
            status = sub.get("status_code", 0)
            if status == 200:
                status_fmt = "[green]200[/green]"
            elif status in {301, 302, 307, 308}:
                status_fmt = f"[cyan]{status}[/cyan]"
            elif status in {401, 403}:
                status_fmt = f"[yellow]{status}[/yellow]"
            else:
                status_fmt = str(status)

            tech = sub.get("detected_tech") or ""
            rtime = f"{sub.get('response_time_ms', 0):.0f}ms"
            subdomain_str = sub.get("subdomain", "")

            # Inline redirect for 301/302
            redirect = sub.get("redirect_location")
            if redirect and status in {301, 302, 307, 308}:
                subdomain_str += f" → [dim]{redirect}[/dim]"

            int_table.add_row(subdomain_str, status_fmt, tech, rtime)
    else:
        int_table.add_row("[dim]No subdomains found in CT logs[/dim]", "", "", "")

    console.print(int_table)

    # 5. Footer
    footer_text = (
        f"\n[bold blue]Scanned in {result.meta.duration_seconds:.1f}s | "
        f"{len(result.technologies)} technologies | "
        f"{len(result.api_endpoints)} endpoints"
    )
    if getattr(result, "openapi_spec_found", False):
        footer_text += " | Full API spec found"
    footer_text += "[/bold blue]"
    console.print(footer_text)


@app.command("update-fingerprints")
def update_fingerprints(
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Where to write the new tech.yaml (defaults to bundled location)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Fetch and parse but do not write, just print a summary",
    ),
    timeout: float = typer.Option(
        30.0,
        "--timeout",
        help="Request timeout in seconds",
    ),
) -> None:
    """Fetch live Wappalyzer rules and rebuild tech.yaml fingerprints."""
    if output is None:
        # Bundled path is fingerprints/tech.yaml at repository root
        output = Path(__file__).parents[2] / "fingerprints" / "tech.yaml"

    async def run_update(target_path: Path) -> FullUpdateResult:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[yellow]Fetching live rules", total=27)

            def progress_cb(char: str) -> None:
                progress.update(
                    task,
                    advance=1,
                    description=f"[yellow]Fetching rules: {char}.json",
                )

            wappalyzer_result = await fetch_and_convert(
                target_path,
                timeout=timeout,
                progress_callback=progress_cb,
            )

            # Fetch SecLists wordlists after Wappalyzer completes
            progress.update(task, description="[yellow]Fetching SecLists wordlists...")
            seclists_dir = target_path.parent / "seclists"
            seclists_result = await fetch_seclists(seclists_dir, timeout=timeout)

        return FullUpdateResult(wappalyzer=wappalyzer_result, seclists=seclists_result)

    console.print(
        Panel(
            "stacksniff — updating technology fingerprints",
            style="bold blue",
        )
    )

    if dry_run:
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir) / "tech.yaml"
            full_result = asyncio.run(run_update(temp_path))
    else:
        full_result = asyncio.run(run_update(output))

    result = full_result.wappalyzer
    seclists = full_result.seclists

    # Show results table
    table = Table(
        title="Fingerprints Update Summary",
        box=None,
        show_header=True,
        header_style="bold blue",
    )
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    total_rules = result.techs_added + result.techs_updated + result.techs_preserved
    table.add_row("Technologies Added (Upstream)", f"[green]{result.techs_added}[/green]")
    table.add_row("Technologies Updated (Upstream)", f"[yellow]{result.techs_updated}[/yellow]")
    table.add_row("Technologies Preserved (Custom)", f"[cyan]{result.techs_preserved}[/cyan]")
    table.add_row("Total Technologies", f"[bold]{total_rules}[/bold]")
    if getattr(result, "openapi_spec_found", False):
        table.add_row("Full API spec found", "[green]Yes[/green]")
    table.add_row("SecLists Files Fetched", f"[magenta]{seclists.files_fetched}[/magenta]")
    table.add_row("SecLists Total Paths", f"[magenta]{seclists.total_paths}[/magenta]")

    console.print(table)
    console.print()

    if dry_run:
        console.print("[bold yellow]No file written (--dry-run)[/bold yellow]")
    else:
        console.print(
            f"[bold green]Successfully wrote fingerprints to {result.output_path}[/bold green]"
        )
        console.print(
            f"[bold green]SecLists wordlists written to {seclists.output_dir}[/bold green]"
        )


def main() -> None:
    """CLI main entry point."""
    app()


if __name__ == "__main__":
    main()
