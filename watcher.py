import time
from pathlib import Path

import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from db import insert_scan
from quarantine import quarantine_file
from scanner.analyzer import analyze_tarball, is_tarball, is_tarball_candidate

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)


NPM_CACHE = Path(CONFIG["paths"]["npm_cache"])

# event handler for the watchdog observer that processes new files created in the npm cache directory, checking if they are tarballs and analyzing them if they are
class NPMWatcher(FileSystemEventHandler):

    # handle the creation of new files in the monitored directory
    def on_created(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)

        if not is_tarball_candidate(path, NPM_CACHE):
            return

        if not is_tarball(path):
            return

        print(f"[+] New package detected: {path}")

        score, findings = analyze_tarball(path)

        print(f"Risk Score: {score}")

        for finding in findings:
            print(" -", finding)

        insert_scan(str(path), "unknown", score)

        if (
            CONFIG["security"]["quarantine_enabled"]
            and score >= CONFIG["security"]["risk_threshold"]
        ):
            quarantine_file(path, CONFIG["paths"]["quarantine"])

# start the watchdog observer to monitor the npm cache directory for new files, using the NPMWatcher event handler to process new files as they are created
def start_watcher():
    observer = Observer()
    observer.schedule(NPMWatcher(), CONFIG["paths"]["npm_cache"], recursive=True)
    observer.start()
    print("[*] NPMGuard watcher started")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
