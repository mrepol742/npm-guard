from Levenshtein import distance

POPULAR_PACKAGES = [
    "react",
    "express",
    "lodash",
    "axios",
    "typescript",
    "next",
    "vue",
    "webpack",
]


# this function checks if the given package name is a potential typosquat of any popular package.
# it calculates the Levenshtein distance between the package name and each popular package.
def detect_typosquat(package_name):
    findings = []
    score = 0

    for legit in POPULAR_PACKAGES:
        d = distance(package_name, legit)

        if 0 < d <= 2:
            score += 40
            findings.append(f"Possible typosquat of '{legit}'")

    return score, findings
