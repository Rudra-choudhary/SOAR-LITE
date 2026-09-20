#!/usr/bin/env python3
"""
SOAR-Lite: Automated Threat Intelligence & Triage Tool
Author: [Your Name]
"""

import sys
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from utils.input_parser import validate_ioc
from modules import virustotal, abuseipdb, shodan_module, alienvault
from modules.score_engine import calculate_weighted_score, get_recommendation, get_severity_color
from utils.report_generator import generate_markdown_report, generate_pdf_report
from utils.notifier import send_discord_alert

console = Console()


def display_banner():
    banner = """
 ███████╗ ██████╗  █████╗ ██████╗       ██╗     ██╗████████╗███████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔══██╗      ██║     ██║╚══██╔══╝██╔════╝
 ███████╗██║   ██║███████║██████╔╝█████╗██║     ██║   ██║   █████╗
 ╚════██║██║   ██║██╔══██║██╔══██╗╚════╝██║     ██║   ██║   ██╔══╝
 ███████║╚██████╔╝██║  ██║██║  ██║      ███████╗██║   ██║   ███████╗
 ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝      ╚══════╝╚═╝   ╚═╝   ╚══════╝
    """
    console.print(banner, style="bold cyan")
    console.print("  Automated Threat Intelligence & Triage Tool\n", style="bold white")


def scan_ioc(ioc: str) -> dict:
    """Run all threat intelligence modules against an IOC"""

    # Validate input
    ioc_info = validate_ioc(ioc)
    if not ioc_info["valid"]:
        console.print(f"\n[red]✗ Invalid IOC: '{ioc}' - Could not identify type[/red]")
        return None

    ioc_type = ioc_info["type"]
    console.print(f"\n[cyan]🔍 Analyzing: [bold]{ioc}[/bold] (Type: {ioc_type.upper()})[/cyan]\n")

    # Query all sources with progress indicator
    results = []
    sources = [
        ("VirusTotal", virustotal),
        ("AbuseIPDB", abuseipdb),
        ("Shodan", shodan_module),
        ("AlienVault OTX", alienvault),
    ]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        for source_name, module in sources:
            task = progress.add_task(f"Querying {source_name}...", total=None)
            result = module.query(ioc, ioc_type)
            results.append(result)
            progress.update(task, completed=True, description=f"✓ {source_name} complete")
            time.sleep(0.3)  # Slight delay to avoid rate limiting

    # Calculate threat score
    score_data = calculate_weighted_score(results)
    severity = score_data["severity"]
    severity_color = get_severity_color(severity)

    # Display Results Table
    console.print()
    table = Table(title="Source Results", show_header=True, header_style="bold magenta")
    table.add_column("Source", style="cyan", width=18)
    table.add_column("Score", justify="center", width=10)
    table.add_column("Key Finding", width=50)
    table.add_column("Status", justify="center", width=10)

    for result in results:
        source = result["source"]
        score = str(result.get("score", "N/A"))

        if result.get("error"):
            key_finding = result["error"]
            status = "⚠️ Error"
        elif result.get("skipped"):
            key_finding = "Not applicable for this IOC type"
            status = "⏭️ Skip"
        else:
            # Extract most interesting field
            key_finding = _extract_key_finding(result)
            status = "✅ Done"

        table.add_row(source, score, key_finding, status)

    console.print(table)

    # Display Final Verdict
    verdict_panel = Panel(
        f"[bold]IOC:[/bold] {ioc}\n"
        f"[bold]Threat Score:[/bold] [{severity_color}]{score_data['final_score']}/100[/{severity_color}]\n"
        f"[bold]Severity:[/bold] [{severity_color}]{severity}[/{severity_color}]\n\n"
        f"[bold]Recommendation:[/bold]\n{get_recommendation(severity)}",
        title=f"🎯 Final Verdict: {severity}",
        border_style=severity_color,
        padding=(1, 2)
    )
    console.print(verdict_panel)

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "results": results,
        "score_data": score_data
    }


def _extract_key_finding(result: dict) -> str:
    """Extract the most important finding from a result"""
    source = result["source"]

    if source == "VirusTotal":
        return f"Detection: {result.get('detection_ratio', 'N/A')}, Country: {result.get('country', 'N/A')}"
    elif source == "AbuseIPDB":
        return f"Abuse Score: {result.get('abuse_confidence_score', 0)}%, Reports: {result.get('total_reports', 0)}, Tor: {result.get('is_tor', False)}"
    elif source == "Shodan":
        return f"Open Ports: {result.get('num_open_ports', 0)}, Vulns: {result.get('num_vulns', 0)}, OS: {result.get('os', 'N/A')}"
    elif source == "AlienVault OTX":
        return f"Threat Pulses: {result.get('pulse_count', 0)}"
    return str(result.get("score", "N/A"))


def main():
    display_banner()

    if len(sys.argv) > 1:
        ioc = sys.argv[1]
    else:
        ioc = console.input("[bold yellow]Enter IOC (IP, Domain, Hash, or URL): [/bold yellow]").strip()

    if not ioc:
        console.print("[red]No IOC provided. Exiting.[/red]")
        sys.exit(1)

    # Run the scan
    scan_result = scan_ioc(ioc)

    if scan_result is None:
        sys.exit(1)

    # Generate Reports
    console.print("\n[bold cyan]📄 Generating Reports...[/bold cyan]")

    md_path = generate_markdown_report(
        scan_result["ioc"],
        scan_result["ioc_type"],
        scan_result["results"],
        scan_result["score_data"]
    )
    console.print(f"  ✅ Markdown report: [green]{md_path}[/green]")

    pdf_path = generate_pdf_report(
        scan_result["ioc"],
        scan_result["ioc_type"],
        scan_result["results"],
        scan_result["score_data"]
    )
    console.print(f"  ✅ PDF report: [green]{pdf_path}[/green]")

    # Send Discord Alert
    console.print("\n[bold cyan]🔔 Sending Alert...[/bold cyan]")
    alert_sent = send_discord_alert(
        scan_result["ioc"],
        scan_result["ioc_type"],
        scan_result["score_data"]
    )
    if alert_sent:
        console.print("  ✅ Discord alert sent successfully")
    else:
        console.print("  ⚠️  Discord alert skipped or failed")

    console.print("\n[bold green]✓ Triage complete![/bold green]\n")


if __name__ == "__main__":
    main()
