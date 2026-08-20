import argparse
import sys
import time
import threading
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from modules.capture import start_capture

console = Console()

def get_protocol_color(proto: str) -> str:
    colors = {
        "ARP": "yellow",
        "ICMP": "magenta",
        "TCP": "blue",
        "UDP": "cyan",
        "HTTP": "green",
        "DNS": "bright_magenta",
        "HTTPS/TLS": "bright_blue"
    }
    return colors.get(proto, "white")

def main():
    parser = argparse.ArgumentParser(description="NetMon - Educational CLI Network Traffic Analyzer & Security Monitor")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff (e.g. eth0, wlan0)")
    parser.add_argument("-f", "--filter", default="ip or arp", help="BPF filter string (default: 'ip or arp')")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose packet details")
    parser.add_argument("-o", "--output", default=None, help="Save captured logs to a file (e.g. logs.txt)")
    parser.add_argument("--scan-threshold", type=int, default=10, help="Unique ports required for port-scan alert (default: 10)")
    parser.add_argument("--scan-window", type=int, default=5, help="Time window in seconds for port-scan detector (default: 5)")

    args = parser.parse_args()

    table = Table(title="Live Captured Packets", title_style="bold white on blue", expand=True)
    table.add_column("Time", style="dim", width=8)
    table.add_column("Protocol", width=10)
    table.add_column("Source", style="red")
    table.add_column("Destination", style="green")
    table.add_column("Info", style="white")

    latest_stats = {"Total": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "HTTP": 0, "ARP": 0, "HTTPS/TLS": 0}
    active_alert = "None"

    def update_ui_callback(parsed: dict, stats: dict, alert: str | None):
        nonlocal latest_stats, active_alert
        latest_stats = stats
        if alert:
            active_alert = alert

        current_time = time.strftime("%H:%M:%S")
        proto = parsed["proto"]
        color = get_protocol_color(proto)

        info_text = parsed["info"]
        if args.verbose and parsed.get("verbose_details"):
            details = ", ".join([f"{k}: {v}" for k, v in parsed["verbose_details"].items()])
            info_text += f" | {details}"

        table.add_row(
            current_time,
            f"[{color}]{proto}[/{color}]",
            parsed["src"],
            parsed["dst"],
            info_text[:120]
        )

        if len(table.rows) > 200:
            table.rows.pop(0)

    def generate_layout():
        stats_str = (
            f"Total: {latest_stats['Total']} | "
            f"TCP: {latest_stats['TCP']} | "
            f"UDP: {latest_stats['UDP']} | "
            f"ICMP: {latest_stats['ICMP']} | "
            f"DNS: {latest_stats['DNS']} | "
            f"HTTP: {latest_stats['HTTP']} | "
            f"HTTPS/TLS: {latest_stats['HTTPS/TLS']} | "
            f"ARP: {latest_stats['ARP']}"
        )
        stats_panel = Panel(stats_str, title="Traffic Statistics", border_style="cyan")
        alert_style = "bold red" if active_alert != "None" else "dim white"
        alert_panel = Panel(active_alert, title="Security Alert", border_style="red" if active_alert != "None" else "green", style=alert_style)

        layout = Layout()
        layout.split(
            Layout(stats_panel, size=3),
            Layout(alert_panel, size=4),
            Layout(table)
        )
        return layout

    console.print(f"[bold green][*] Starting NetMon on interface: {args.interface}[/bold green]")
    console.print(f"[bold cyan][*] BPF Filter: {args.filter} | Output File: {args.output}[/bold cyan]")
    console.print("[yellow]Press Ctrl+C to stop sniffing...[/yellow]\n")

    try:
        with Live(generate_layout(), refresh_per_second=4, screen=True) as live:
            capture_thread = threading.Thread(
                target=start_capture,
                args=(args.interface, args.filter, args.verbose, args.scan_threshold, args.scan_window, args.output, update_ui_callback),
                daemon=True
            )
            capture_thread.start()

            while capture_thread.is_alive():
                live.update(generate_layout())
                time.sleep(0.25)

    except KeyboardInterrupt:
        console.print("\n[bold red][!] Stopping NetMon. Good bye![/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red][X] {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
