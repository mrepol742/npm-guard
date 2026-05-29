import hashlib
import shutil
import time
from pathlib import Path

# move a file to the quarantine directory with a unique timestamp-based name
def quarantine_file(file_path, quarantine_dir):
    quarantine_dir = Path(quarantine_dir)
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    src = Path(file_path)
    ts = int(time.time() * 1000)
    dest = quarantine_dir / f"{src.stem}_{ts}{src.suffix}"

    # ensure unique by appending hash if name collision
    if dest.exists():
        h = hashlib.md5(str(ts).encode()).hexdigest()[:8]
        dest = quarantine_dir / f"{src.stem}_{ts}_{h}{src.suffix}"

    shutil.move(str(src), str(dest))

    print(f"[!] Quarantined: {src} -> {dest}")
