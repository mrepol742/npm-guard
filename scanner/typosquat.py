from Levenshtein import distance

# expanded list of commonly typosquatted packages
POPULAR_PACKAGES = [
    "react", "express", "lodash", "axios", "typescript", "next", "vue", "webpack",
    "chalk", "uuid", "sharp", "dayjs", "dotenv", "moment", "request", "commander",
    "async", "bluebird", "body-parser", "chokidar", "cli-color", "colors", "cors",
    "debug", "eslint", "fs-extra", "glob", "got", "graphql", "gulp", "inquirer",
    "jest", "jsdom", "jsonwebtoken", "mongoose", "morgan", "node-fetch", "nodemailer",
    "ora", "passport", "path", "pino", "prettier", "puppeteer", "redux", "rimraf",
    "semver", "sequelize", "socket.io", "underscore", "validator", "winston", "yargs",
    "zustand", "zod", "prisma", "trpc", "tailwindcss", "babel", "postcss",
]


HOMOGLYPHS = {
    "a": ["а"],  # Cyrillic a
    "e": ["е", "ё"],  # Cyrillic e, yo
    "o": ["о"],  # Cyrillic o
    "c": ["с"],  # Cyrillic c
    "p": ["р"],  # Cyrillic p (er)
    "x": ["х"],  # Cyrillic kh
    "y": ["у"],  # Cyrillic u
}


def has_homoglyph(name):
    """Check if package name contains non-latin homoglyph characters"""
    for char in name:
        cp = ord(char)
        if cp > 127:
            return True
    return False


def normalize_homoglyphs(name):
    """Replace common homoglyphs with latin equivalents"""
    result = []
    for char in name:
        replaced = False
        for latin, cyrillics in HOMOGLYPHS.items():
            if char in cyrillics:
                result.append(latin)
                replaced = True
                break
        if not replaced:
            result.append(char)
    return "".join(result)


# this function checks if the given package name is a potential typosquat of any popular package.
# it calculates the Levenshtein distance between the package name and each popular package.
def detect_typosquat(package_name):
    findings = []
    score = 0

    normalized = package_name

    # if homoglyphs detected, normalize and flag
    if has_homoglyph(package_name):
        normalized = normalize_homoglyphs(package_name)
        if normalized != package_name:
            score += 50
            findings.append(f"Homoglyph characters detected: '{package_name}' -> '{normalized}'")

    for legit in POPULAR_PACKAGES:
        d = distance(normalized, legit)

        if 0 < d <= 2:
            score += 40
            findings.append(f"Possible typosquat of '{legit}' (distance={d})")

    return score, findings
