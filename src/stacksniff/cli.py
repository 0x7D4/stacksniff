"""CLI entry point for stacksniff."""
# ruff: noqa: B008

from __future__ import annotations

import asyncio
from pathlib import Path  # noqa: TC003
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from stacksniff import __version__
from stacksniff.scanner import Scanner
from stacksniff.updater import fetch_and_convert

app = typer.Typer(help="stacksniff — detect web technology stacks and APIs")
console = Console()


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
            pat_str = f" [dim]({ep.pattern_matched})[/dim]" if ep.pattern_matched else ""
            ep_lines.append(f"• [bold green]{ep.method:6}[/bold green] {ep.url}{ct_str}{pat_str}")
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

    # 3. Footer
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

    async def run_update(target_path: Path) -> Any:
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

            return await fetch_and_convert(
                target_path,
                timeout=timeout,
                progress_callback=progress_cb,
            )

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
            result = asyncio.run(run_update(temp_path))
    else:
        result = asyncio.run(run_update(output))

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

    console.print(table)
    console.print()

    if dry_run:
        console.print("[bold yellow]No file written (--dry-run)[/bold yellow]")
    else:
        console.print(
            f"[bold green]Successfully wrote fingerprints to {result.output_path}[/bold green]"
        )


def main() -> None:
    """CLI main entry point."""
    app()


if __name__ == "__main__":
    main()
