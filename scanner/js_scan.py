import re
from pathlib import Path


PATTERNS = {
    "eval": r"eval\\(",
    "base64": r"Buffer\\.from\\(.*base64",
    "child_process": r"require\\(['\"]child_process['\"]\\)",
    "curl_pipe": r"curl .*\\|",
}


# simple heuristic scan for JavaScript files
def scan_js_file(path):
    findings = []
    score = 0

    try:
        content = Path(path).read_text(errors="ignore")

        for name, pattern in PATTERNS.items():
            if re.search(pattern, content):
                findings.append(name)
                score += 15

    except Exception:
        pass

    return score, findings
