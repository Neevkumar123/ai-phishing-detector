import hashlib
import math
from pathlib import Path


# ============================================================
# FILE HASH
# ============================================================

def calculate_sha256(file_path, chunk_size=1024 * 1024):
    """
    Calculate SHA-256 without executing or opening the file
    as a program.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(data):
    """
    Calculate Shannon entropy of bytes.

    Higher entropy can indicate compressed or encrypted data.
    It is NOT by itself proof of malware.
    """

    if not data:
        return 0.0

    frequency = [0] * 256

    for byte in data:
        frequency[byte] += 1

    length = len(data)
    entropy = 0.0

    for count in frequency:
        if count == 0:
            continue

        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


# ============================================================
# FILE FEATURES
# ============================================================

def extract_file_features(file_path):
    """
    Extract safe, static characteristics from a file.

    The file is only read as bytes.
    It is never executed.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError("File does not exist.")

    if not path.is_file():
        raise ValueError("The selected path is not a file.")

    file_size = path.stat().st_size

    # Read only the first 1 MB for entropy analysis.
    # This keeps scanning reasonably fast.
    sample_size = min(file_size, 1024 * 1024)

    with open(path, "rb") as file:
        sample = file.read(sample_size)

    entropy = calculate_entropy(sample)

    extension = path.suffix.lower()

    suspicious_extensions = {
        ".exe",
        ".dll",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".msi",
        ".com",
    }

    suspicious_extension = int(
        extension in suspicious_extensions
    )

    # Very large entropy can occur in compressed/encrypted files.
    high_entropy = int(entropy >= 7.2)

    return {
        "file_name": path.name,
        "extension": extension if extension else "none",
        "file_size": file_size,
        "file_size_mb": round(file_size / (1024 * 1024), 2),
        "sha256": calculate_sha256(path),
        "entropy": round(entropy, 4),
        "suspicious_extension": suspicious_extension,
        "high_entropy": high_entropy,
    }


# ============================================================
# RISK ASSESSMENT
# ============================================================

def calculate_file_risk(features):
    """
    Calculate a simple explainable risk score.

    This is a prototype heuristic, not a malware verdict.
    """

    score = 0
    reasons = []

    if features["suspicious_extension"]:
        score += 25
        reasons.append(
            "The file uses an executable or script-related extension."
        )

    if features["high_entropy"]:
        score += 20
        reasons.append(
            "The file has high byte entropy, which can occur in "
            "compressed or encrypted files."
        )

    # Keep the score in the 0-100 range.
    score = min(score, 100)

    if score >= 60:
        level = "HIGH"

    elif score >= 30:
        level = "MEDIUM"

    else:
        level = "LOW"

    if not reasons:
        reasons.append(
            "No strong suspicious characteristics were detected "
            "by this basic static scanner."
        )

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
    }


# ============================================================
# COMPLETE SCAN
# ============================================================

def scan_file(file_path):
    """
    Perform a safe static scan.

    The file is never executed.
    """

    features = extract_file_features(file_path)

    assessment = calculate_file_risk(features)

    return {
        **features,
        **assessment,
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("AI PHISHING WEBSITE DETECTOR")
    print("SAFE LOCAL FILE SCANNER TEST")
    print("=" * 60)

    print()
    print("This module performs static file analysis only.")
    print("It does NOT execute the selected file.")
    print()

    file_input = input(
        "Enter the path of a file to scan: "
    ).strip().strip('"')

    try:

        result = scan_file(file_input)

        print()
        print("=" * 60)
        print("FILE SCAN RESULT")
        print("=" * 60)

        print("File:", result["file_name"])
        print("Extension:", result["extension"])
        print("Size:", result["file_size_mb"], "MB")
        print("SHA-256:", result["sha256"])
        print("Entropy:", result["entropy"])
        print("Risk Score:", result["risk_score"], "/ 100")
        print("Risk Level:", result["risk_level"])

        print()
        print("Reasons:")

        for reason in result["reasons"]:
            print("-", reason)

        print()
        print("=" * 60)

    except Exception as error:

        print()
        print("Scan failed:")
        print(error)