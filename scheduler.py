import os
import time
import yaml
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from apscheduler.schedulers.blocking import BlockingScheduler
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID

from scanner.analyzer import analyze_tarball, iter_tarball_paths, sha256_file
from db import insert_scan, file_exists, record_scan_run

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)

console = Console()
scheduler = BlockingScheduler()


def deep_scan():
    npm_dir = Path(CONFIG["paths"]["npm_cache"])
    workers = max(1, os.cpu_count() or 4)

    console.print(f"[*] Starting deep scan of npm cache...", style="bold blue")
    console.print(f"[*] Scanning directory: {npm_dir}", style="blue")
    console.print(f"[*] Using {workers} worker threads", style="blue")
    start_ts = time.time()

    tarballs = list(iter_tarball_paths(npm_dir))

    if not tarballs:
        console.print("[yellow]No tarballs found to scan.[/yellow]")
        return

    results = []
    skipped = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task: TaskID = progress.add_task(
            f"[cyan]Scanning {len(tarballs)} packages...", total=len(tarballs)
        )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {}

            for tarball in tarballs:
                file_hash = sha256_file(tarball)

                if file_exists(str(tarball), file_hash):
                    skipped += 1
                    progress.update(task, advance=1)
                    continue

                future = executor.submit(analyze_tarball, tarball)
                future_map[future] = (tarball, file_hash)

            for future in as_completed(future_map):
                tarball, file_hash = future_map[future]
                try:
                    score, findings = future.result()
                    results.append((tarball, score, findings))
                    insert_scan(str(tarball), file_hash, score)

                    if score > 0:
                        progress.console.print(
                            f"  [yellow]⚠ {tarball.name} → score: {score}[/yellow]"
                        )
                        for f in findings:
                            progress.console.print(f"    [red]- {f}[/red]")
                except Exception as e:
                    progress.console.print(
                        f"  [red]✗ {tarball.name} → error: {e}[/red]"
                    )

                progress.update(task, advance=1)

    duration = time.time() - start_ts

    total = len(results) + skipped
    suspicious = sum(1 for _, s, _ in results if s >= CONFIG["security"]["risk_threshold"])
    clean = sum(1 for _, s, _ in results if s < CONFIG["security"]["risk_threshold"])
    record_scan_run(total, suspicious, 0, round(duration, 2))

    table = Table(title="Scan Summary", style="cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Count", justify="right")

    table.add_row("Total packages in cache", str(total))
    table.add_row("Scanned (new)", str(len(results)))
    table.add_row("Skipped (already scanned)", str(skipped))
    table.add_row("Clean", str(clean))
    table.add_row("Suspicious", str(suspicious))

    console.print()
    console.print(table)

    if suspicious > 0:
        console.print("\n[red]Top suspicious packages:[/red]")
        for tarball, score, findings in sorted(
            results, key=lambda x: x[1], reverse=True
        )[:5]:
            if score >= CONFIG["security"]["risk_threshold"]:
                console.print(f"  [red]• {tarball.name} (score: {score})[/red]")

    console.print(f"\n[bold green][*] Deep scan completed[/bold green]")


def start_scheduler():
    cron_expr = CONFIG["cron"]["expression"]
    minute, hour, day, month, dow = cron_expr.split()

    scheduler.add_job(
        deep_scan,
        'cron',
        minute=minute,
        hour=hour,
        day=day,
        month=month,
        day_of_week=dow
    )

    console.print(f"[*] Scheduler started with cron expression:", cron_expr)
    scheduler.start()
