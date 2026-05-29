import argparse
import threading
import sys

import yaml

from db import init_db, get_stats, clear_db
from scheduler import deep_scan, start_scheduler
from watcher import start_watcher

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)

def show_stats():
    init_db()
    stats = get_stats()
    print("\n=== NPM Guard DB Stats ===")
    print(f"  Total files scanned:  {stats['total_scanned']}")
    print(f"  Clean:                {stats['clean']}")
    print(f"  Vulnerable (>=50):    {stats['vulnerable']}")
    print(f"  Average risk score:   {stats['avg_score']}")
    print(f"  Highest risk score:   {stats['max_score']}")
    print(f"  Last scan run:        {stats['last_scan_at']}")
    print(f"  Total scan runs:      {stats['total_runs']}")
    print(f"  Last run findings:    {stats['total_packages_across_runs']} pkgs, {stats['total_suspicious_across_runs']} suspicious")
    if stats['top_vulnerable']:
        print("\n  Top vulnerable packages:")
        for name, score, at in stats['top_vulnerable'][:5]:
            print(f"    - {name} (score: {score})")
    print()

def main():
    init_db()

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd in ("--stats", "stats", "-s"):
            show_stats()
            return
        elif cmd in ("--clear", "clear", "-c"):
            confirm = input("Clear all scan data? (y/N): ").strip().lower()
            if confirm == "y":
                clear_db()
                print("DB cleared.")
            else:
                print("Cancelled.")
            return

    mode = CONFIG["scan_mode"]
    if mode == "watcher":
        start_watcher()
    elif mode == "cron":
        start_scheduler()
    elif mode == "hybrid":
        watcher_thread = threading.Thread(target=start_watcher)
        scheduler_thread = threading.Thread(target=start_scheduler)
        watcher_thread.start()
        scheduler_thread.start()
        watcher_thread.join()
        scheduler_thread.join()
    elif mode == "manual":
        deep_scan()

if __name__ == "__main__":
    main()
