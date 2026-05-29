import time
import os
import concurrent.futures
from pathlib import Path

import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from db import insert_scan
from quarantine import quarantine_file
from scanner.analyzer import analyze_tarball, sha256_file, is_tarball, is_tarball_candidate

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)

NPM_CACHE = Path(CONFIG["paths"]["npm_cache"])
MAX_WORKERS = os.cpu_count() or 4


class NPMWatcher(FileSystemEventHandler):

    def __init__(self):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def on_created(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)

        if not is_tarball_candidate(path, NPM_CACHE):
            return
        if not is_tarball(path):
            return

        self.executor.submit(self._process_package, path)

    def _process_package(self, path):
        print(f"[+] New package detected: {path}")
        try:
            score, findings = analyze_tarball(path)
            sha = sha256_file(path)

            print(f"   Risk Score: {score}")
            for finding in findings:
                print(f"   - {finding}")

            insert_scan(str(path), sha, score, "; ".join(findings[:5]))

            if (
                CONFIG["security"]["quarantine_enabled"]
                and score >= CONFIG["security"]["risk_threshold"]
            ):
                quarantine_file(path, CONFIG["paths"]["quarantine"])
        except Exception as e:
            print(f"   [!] Error processing {path}: {e}")


def start_watcher():
    observer = Observer()
    handler = NPMWatcher()
    observer.schedule(handler, CONFIG["paths"]["npm_cache"], recursive=True)
    observer.start()
    print("[*] NPMGuard watcher started")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
