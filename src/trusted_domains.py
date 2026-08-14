from urllib.parse import urlparse


# ============================================================
# TRUSTED DOMAINS
# ============================================================

TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "wikipedia.org",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "reddit.com",
    "stackoverflow.com",
    "python.org",
    "mozilla.org",
    "w3.org",
    "ietf.org",
    "example.com",
}


# ============================================================
# CHECK TRUSTED DOMAIN
# ============================================================

def is_trusted_domain(url):
    """
    Check whether the URL belongs to a known trusted domain.
    """

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return False

        hostname = hostname.lower().strip(".")

        for domain in TRUSTED_DOMAINS:

            if hostname == domain:
                return True

            if hostname.endswith("." + domain):
                return True

        return False

    except Exception:
        return False