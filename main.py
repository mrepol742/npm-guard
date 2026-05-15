import threading

import yaml

from db import init_db
from scheduler import deep_scan, start_scheduler
from watcher import start_watcher

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)

# initialize the database and start the appropriate mode based on the configuration
def main():
    init_db()

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
