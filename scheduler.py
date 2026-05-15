import yaml
from pathlib import Path
from apscheduler.schedulers.blocking import BlockingScheduler

from scanner.analyzer import analyze_tarball, iter_tarball_paths


with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)


scheduler = BlockingScheduler()


# perform a deep scan of the npm cache directory, analyzing all tarballs and printing the results
def deep_scan():
    npm_dir = Path(CONFIG["paths"]["npm_cache"])

    print("[*] Starting deep scan of npm cache...")
    print(f"[*] Scanning directory: {npm_dir}")

    for tarball in iter_tarball_paths(npm_dir):
        print(f"Scanning {tarball}")

        score, findings = analyze_tarball(tarball)

        print(score)

        for finding in findings:
            print(" -", finding)

    print("[*] Deep scan completed")

# start the scheduler with the cron expression from the configuration, scheduling the deep_scan function to run at the specified intervals
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

    print("[*] Scheduler started with cron expression:", cron_expr)

    scheduler.start()
