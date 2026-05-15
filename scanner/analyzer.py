import hashlib
import json
import tarfile
import tempfile
from pathlib import Path

from scanner.heuristics import analyze_scripts
from scanner.js_scan import scan_js_file
from scanner.osv import check_vulnerability
from scanner.typosquat import detect_typosquat

TARBALL_SUFFIXES = {
    ".tgz",
    ".tar",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
}

# check if the file has a tarball extension
def has_tarball_extension(path: Path):
    return "".join(path.suffixes) in TARBALL_SUFFIXES

# check if the file is a tarball candidate (either has a tarball extension or is in the npm cache content directory without an extension)
def is_tarball_candidate(path: Path, npm_cache_root=None):
    if has_tarball_extension(path):
        return True
    if npm_cache_root is None:
        return False

    content_root = npm_cache_root / "_cacache" / "content-v2"
    return content_root in path.parents and not path.suffixes

# check if the file is a valid tarball by trying to open it
def is_tarball(path: Path):
    try:
        with tarfile.open(path, mode="r:*"):
            return True
    except (tarfile.TarError, OSError, EOFError):
        return False

# iterate over all tarball candidates in the npm cache directory
def iter_tarball_paths(npm_cache_root: Path):
    content_root = npm_cache_root / "_cacache" / "content-v2"
    search_root = content_root if content_root.exists() else npm_cache_root

    for path in search_root.rglob("*"):
        if not path.is_file():
            continue
        if not is_tarball_candidate(path, npm_cache_root):
            continue
        if is_tarball(path):
            yield path

# compute the SHA256 hash of a file
def sha256_file(path):
    sha = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)

    return sha.hexdigest()

# main analysis function that extracts the tarball, looks for package.json files, analyzes scripts, checks for typosquatting, and scans JavaScript files
def analyze_tarball(file_path):
    total_score = 0
    findings = []

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            with tarfile.open(file_path, mode="r:*") as tar:
                tar.extractall(temp_dir)

        except Exception as e:
            findings.append(f"Tar extraction failed: {e}")
            return 100, findings

        package_json_files = list(Path(temp_dir).rglob("package.json"))

        for package_json_path in package_json_files:
            try:
                data = json.loads(package_json_path.read_text(errors="ignore"))

                package_name = data.get("name", "unknown")
                version = data.get("version", "0.0.0")

                score, f = analyze_scripts(data)
                total_score += score
                findings.extend(f)

                score, f = detect_typosquat(package_name)
                total_score += score
                findings.extend(f)

                vulns = check_vulnerability(package_name, version)

                if vulns:
                    total_score += 70
                    findings.append(f"Known vulnerabilities: {len(vulns)}")

            except Exception as e:
                findings.append(str(e))

        js_files = list(Path(temp_dir).rglob("*.js"))

        for js_file in js_files:
            score, f = scan_js_file(js_file)
            total_score += score
            findings.extend(f)

    return total_score, findings
