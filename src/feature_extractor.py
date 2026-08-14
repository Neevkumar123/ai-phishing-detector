from urllib.parse import urlparse
from ipaddress import ip_address
import math
import re


# ============================================================
# AI PHISHING WEBSITE DETECTOR
# URL FEATURE EXTRACTOR
# ============================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "password",
    "passwd",
    "credential",
    "bank",
    "banking",
    "paypal",
    "payment",
    "wallet",
    "webscr",
    "recover",
    "suspended",
    "unlock",
    "authenticate",
    "authentication",
    "billing",
    "invoice",
    "admin",
    "wp-admin",
    "wp-login",
]


SUSPICIOUS_CHARACTERS = [
    "@",
    "_",
    "%",
    "=",
    "&",
    ";",
    "~",
]


FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "dot_count",
    "slash_count",
    "hyphen_count",
    "digit_count",
    "query_parameter_count",
    "subdomain_count",
    "has_https",
    "has_ip_address",
    "has_at_symbol",
    "suspicious_character_count",
    "suspicious_keyword_count",

    # New features
    "domain_length",
    "path_length",
    "query_length",
    "fragment_length",
    "has_www",
    "has_port",
    "hostname_digit_count",
    "path_digit_count",
    "path_hyphen_count",
    "query_special_character_count",
    "double_slash_count",
    "is_shortened_url",
    "hostname_entropy",
    "url_entropy",
]


SHORTENED_DOMAINS = {
    "bit.ly",
    "goo.gl",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
}


def normalize_url(url):
    """
    Normalize a URL so urlparse() can correctly identify
    hostname, path, query and other components.

    Dataset URLs often look like:
        google.com
        youtube.com/watch?v=123

    instead of:
        https://google.com
    """

    if url is None:
        return ""

    url = str(url).strip()

    if not url:
        return ""

    # Remove surrounding quotes
    url = url.strip("\"'")

    # Add a scheme when missing.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    return url


def parse_url(url):
    """
    Safely parse URL.

    Invalid URLs should not crash the entire dataset extraction.
    """

    normalized = normalize_url(url)

    try:
        return urlparse(normalized)
    except ValueError:
        return urlparse("")


def get_hostname(url):
    """
    Safely return hostname.
    """

    parsed = parse_url(url)

    try:
        return parsed.hostname or ""
    except ValueError:
        return ""


def get_hostname_length(url):
    return len(get_hostname(url))


def count_subdomains(hostname):
    """
    Count subdomains.

    Example:
        google.com
        -> 0

        mail.google.com
        -> 1

        login.accounts.example.com
        -> 2
    """

    if not hostname:
        return 0

    parts = hostname.split(".")

    # IP addresses are not treated as subdomains.
    if is_ip_address(hostname):
        return 0

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def is_ip_address(hostname):
    """
    Check whether hostname is an IPv4 or IPv6 address.
    """

    if not hostname:
        return False

    try:
        ip_address(hostname)
        return True
    except ValueError:
        return False


def get_query_parameter_count(url):
    parsed = parse_url(url)

    if not parsed.query:
        return 0

    return len(
        [
            parameter
            for parameter in parsed.query.split("&")
            if parameter
        ]
    )


def get_suspicious_keyword_count(url):
    """
    Count suspicious keywords.

    A keyword is counted once for each occurrence.
    """

    url_lower = str(url).lower()

    count = 0

    for keyword in SUSPICIOUS_KEYWORDS:
        count += url_lower.count(keyword)

    return count


def get_suspicious_character_count(url):
    """
    Count suspicious characters in the URL.
    """

    url = str(url)

    count = 0

    for character in SUSPICIOUS_CHARACTERS:
        count += url.count(character)

    return count


def calculate_entropy(value):
    """
    Calculate Shannon entropy.

    Higher entropy can indicate randomly generated
    domains/paths often seen in malicious URLs.
    """

    if not value:
        return 0.0

    value = str(value)

    frequency = {}

    for character in value:
        frequency[character] = frequency.get(character, 0) + 1

    entropy = 0.0
    length = len(value)

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 6)


def get_domain_length(hostname):
    return len(hostname)


def get_path_length(url):
    parsed = parse_url(url)
    return len(parsed.path or "")


def get_query_length(url):
    parsed = parse_url(url)
    return len(parsed.query or "")


def get_fragment_length(url):
    parsed = parse_url(url)
    return len(parsed.fragment or "")


def get_has_www(hostname):
    if hostname.lower().startswith("www."):
        return 1

    return 0


def get_has_port(url):
    parsed = parse_url(url)

    try:
        return 1 if parsed.port is not None else 0
    except ValueError:
        return 0


def get_hostname_digit_count(hostname):
    return sum(character.isdigit() for character in hostname)


def get_path_digit_count(url):
    parsed = parse_url(url)
    path = parsed.path or ""

    return sum(character.isdigit() for character in path)


def get_path_hyphen_count(url):
    parsed = parse_url(url)
    path = parsed.path or ""

    return path.count("-")


def get_query_special_character_count(url):
    parsed = parse_url(url)
    query = parsed.query or ""

    special_characters = "@%=&;_~"

    return sum(
        query.count(character)
        for character in special_characters
    )


def get_double_slash_count(url):
    """
    Count occurrences of // after the scheme.

    Normal:
        https://google.com

    Suspicious examples can contain:
        https://example.com//login
    """

    url = str(url)

    # Remove the normal protocol separator.
    normalized = re.sub(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        "",
        url
    )

    return normalized.count("//")


def get_is_shortened_url(hostname):
    """
    Detect common URL-shortening services.
    """

    hostname = hostname.lower()

    if hostname in SHORTENED_DOMAINS:
        return 1

    return 0


def get_hostname_entropy(hostname):
    return calculate_entropy(hostname)


def get_url_entropy(url):
    return calculate_entropy(url)


def extract_features(url):
    """
    Extract all machine-learning features from a URL.

    Returns:
        Dictionary containing numerical features.
    """

    original_url = "" if url is None else str(url)

    parsed = parse_url(original_url)

    hostname = get_hostname(original_url)

    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    features = {
        # ----------------------------------------------------
        # Original features
        # ----------------------------------------------------

        "url_length": len(original_url),

        "hostname_length": len(hostname),

        "dot_count": original_url.count("."),

        "slash_count": original_url.count("/"),

        "hyphen_count": original_url.count("-"),

        "digit_count": sum(
            character.isdigit()
            for character in original_url
        ),

        "query_parameter_count":
            get_query_parameter_count(original_url),

        "subdomain_count":
            count_subdomains(hostname),

        "has_https":
            1 if parsed.scheme.lower() == "https" else 0,

        "has_ip_address":
            1 if is_ip_address(hostname) else 0,

        "has_at_symbol":
            1 if "@" in original_url else 0,

        "suspicious_character_count":
            get_suspicious_character_count(original_url),

        "suspicious_keyword_count":
            get_suspicious_keyword_count(original_url),

        # ----------------------------------------------------
        # New features
        # ----------------------------------------------------

        "domain_length":
            get_domain_length(hostname),

        "path_length":
            len(path),

        "query_length":
            len(query),

        "fragment_length":
            len(fragment),

        "has_www":
            get_has_www(hostname),

        "has_port":
            get_has_port(original_url),

        "hostname_digit_count":
            get_hostname_digit_count(hostname),

        "path_digit_count":
            get_path_digit_count(original_url),

        "path_hyphen_count":
            get_path_hyphen_count(original_url),

        "query_special_character_count":
            get_query_special_character_count(original_url),

        "double_slash_count":
            get_double_slash_count(original_url),

        "is_shortened_url":
            get_is_shortened_url(hostname),

        "hostname_entropy":
            get_hostname_entropy(hostname),

        "url_entropy":
            get_url_entropy(original_url),
    }

    return features


def main():
    """
    Test the feature extractor with several URLs.
    """

    test_urls = [
        "https://example.com",

        "http://192.168.1.10/login",

        "https://example.com@evil.example/login",

        "http://secure-login-example.com/account",

        "https://example.com/page?id=123&user=test",

        "youtube.com/watch?v=AtTLl_UNAaY",

        "tools.ietf.org/html/rfc1920",

        "https://google.com",

        "https://wikipedia.org",

        "https://github.com",

        "bit.ly/example",
    ]

    print("=" * 60)
    print("AI PHISHING WEBSITE DETECTOR")
    print("FEATURE EXTRACTION TEST")
    print("=" * 60)

    for url in test_urls:

        print("\n" + "=" * 60)
        print("Test URL:")
        print(url)

        features = extract_features(url)

        print("\nExtracted Features:")

        for feature_name in FEATURE_COLUMNS:
            print(
                f"{feature_name}: "
                f"{features[feature_name]}"
            )

    print("\n" + "=" * 60)
    print("FEATURE EXTRACTION TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()