import re


SUSPICIOUS_PATTERNS = [
    r"eval\(",
    r"Function\(",
    r"child_process",
    r"curl .*\| bash",
    r"wget .*\| sh",
    r"Buffer\.from",
    r"atob\(",
    r"crypto\.createCipher",
]


INSTALL_SCRIPT_KEYS = [
    "preinstall",
    "postinstall",
    "prepare",
]


# heuristic analysis of package.json scripts for potential malicious behavior
def analyze_scripts(package_json):
    score = 0
    findings = []

    scripts = package_json.get("scripts", {})

    for key in INSTALL_SCRIPT_KEYS:
        if key in scripts:
            score += 20
            findings.append(f"Suspicious install script: {key}")

            value = scripts[key]

            # mga babaero
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, value):
                    score += 30
                    findings.append(f"Matched pattern: {pattern}")

    return score, findings
