import shutil
from pathlib import Path

# move a file to the quarantine directory
def quarantine_file(file_path, quarantine_dir):
    quarantine_dir = Path(quarantine_dir)
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    src = Path(file_path)
    dest = quarantine_dir / src.name

    shutil.move(str(src), str(dest))

    print(f"[!] Quarantined: {src}")
