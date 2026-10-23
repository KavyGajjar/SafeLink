from difflib import SequenceMatcher
from urllib.parse import urlparse

# Small starter list of trusted domains.
# We can expand this list after testing.
TRUSTED_DOMAINS = [
    # Indian government and citizen services
    "india.gov.in",
    "igod.gov.in",
    "mygov.in",
    "digitalindia.gov.in",
    "uidai.gov.in",
    "aadhaar.uidai.gov.in",
    "digilocker.gov.in",
    "parivahan.gov.in",
    "passportindia.gov.in",
    "incometax.gov.in",
    "incometaxindia.gov.in",
    "gst.gov.in",
    "cbic.gov.in",
    "rbi.org.in",
    "sebi.gov.in",
    "pfrda.org.in",
    "epfindia.gov.in",
    "esic.gov.in",
    "pmkisan.gov.in",
    "pmindia.gov.in",
    "presidentofindia.gov.in",
    "mha.gov.in",
    "mea.gov.in",
    "mof.gov.in",
    "finmin.gov.in",
    "nic.in",
    "nielit.gov.in",
    "upsc.gov.in",
    "ssc.gov.in",
    "nta.ac.in",
    "cbse.gov.in",
    "ncert.nic.in",
    "results.nic.in",
    "irctc.co.in",
    "indianrailways.gov.in",
    "india.gov.in",

    # Indian banks: newer bank.in domains
    "sbi.bank.in",
    "pnb.bank.in",
    "hdfc.bank.in",
    "icici.bank.in",
    "axis.bank.in",
    "kotak.bank.in",
    "bankofbaroda.bank.in",
    "bankofindia.bank.in",
    "bankofmaharashtra.bank.in",
    "canarabank.bank.in",
    "centralbank.bank.in",
    "indianbank.bank.in",
    "iob.bank.in",
    "unionbank.bank.in",
    "uco.bank.in",
    "idfcfirst.bank.in",
    "federal.bank.in",
    "yes.bank.in",
    "rbl.bank.in",
    "bandhan.bank.in",
    "indusind.bank.in",

    # Established bank domains / legacy addresses
    "sbi.co.in",
    "onlinesbi.sbi",
    "pnbindia.in",
    "pnbindia.com",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "kotak.com",
    "bankofbaroda.in",
    "bankofindia.co.in",
    "bankofmaharashtra.in",
    "canarabank.com",
    "centralbankofindia.co.in",
    "indianbank.in",
    "iob.in",
    "unionbankofindia.co.in",
    "ucobank.com",
    "idfcfirstbank.com",
    "federalbank.co.in",
    "yesbank.in",
    "rblbank.com",
    "bandhanbank.com",
    "indusind.com",

    # Payments and financial services
    "npci.org.in",
    "bhimupi.org.in",
    "phonepe.com",
    "paytm.com",
    "razorpay.com",
    "cred.club",
    "cashfree.com",
    "mobikwik.com",
    "paypal.com",

    # Shopping and delivery
    "amazon.in",
    "amazon.com",
    "flipkart.com",
    "myntra.com",
    "ajio.com",
    "meesho.com",
    "nykaa.com",
    "swiggy.com",
    "zomato.com",
    "blinkit.com",
    "zepto.com",
    "bigbasket.com",

    # Technology, email and social platforms
    "google.com",
    "youtube.com",
    "gmail.com",
    "google.co.in",
    "microsoft.com",
    "live.com",
    "outlook.com",
    "apple.com",
    "icloud.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "threads.net",
    "x.com",
    "twitter.com",
    "linkedin.com",
    "github.com",
    "reddit.com",
    "wikipedia.org",
    "telegram.org",
    "discord.com",
    "netflix.com",
    "spotify.com",
    "canva.com",
    "adobe.com",
    "zoom.us",
    "cloudflare.com",
    "axis.com",

    # Education and learning
    "swayam.gov.in",
    "swayamprabha.gov.in",
    "nptel.ac.in",
    "coursera.org",
    "edx.org",
    "khanacademy.org",
]


def get_hostname(url):
    """Extract a normalized hostname from a URL or bare domain."""
    value = url.strip()

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    try:
        hostname = urlparse(value).hostname
        if hostname:
            return hostname.lower().rstrip(".")
    except ValueError:
        pass

    return None


def get_registered_domain(hostname):
    """
    Simple approximation for common domains.
    This is not a complete public-suffix implementation.
    """
    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    # Handle common two-part public suffixes.
    two_part_suffixes = {
        "co.uk", "org.uk", "ac.uk",
        "com.au", "net.au", "org.au",
        "co.in", "firm.in", "net.in", "bank.in",
        "com.br", "co.nz", "com.sg"
    }

    last_two = ".".join(parts[-2:])

    if last_two in two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])

    return last_two


def check_lookalike(url, threshold=0.78):
    """
    Return a possible lookalike match.
    A match is a warning, not proof of maliciousness.
    """
    hostname = get_hostname(url)

    if not hostname:
        return {
            "is_lookalike": False,
            "domain": None,
            "suggestion": None,
            "similarity": 0.0
        }

    domain = get_registered_domain(hostname)

    # Trusted domains and their subdomains should not be flagged.
    if any(
        domain == trusted or domain.endswith("." + trusted)
        for trusted in TRUSTED_DOMAINS
    ):
        return {
            "is_lookalike": False,
            "domain": domain,
            "suggestion": None,
            "similarity": 1.0
        }
    # Detect suspicious extensions for a trusted brand.
    for trusted in TRUSTED_DOMAINS:
        trusted_name = trusted.split(".")[0].lower()

        if domain.split(".")[0].lower() == trusted_name and domain != trusted:
            return {
                "is_lookalike": True,
                "domain": domain,
                "suggestion": trusted,
                "similarity": 1.0
            }

    best_match = None
    best_score = 0.0

    for trusted in TRUSTED_DOMAINS:
        domain_name = domain.split(".")[0].lower()
        trusted_name = trusted.split(".")[0].lower()

        # Compare only different brand names, not duplicate domains.
        if domain_name == trusted_name:
            continue

        score = SequenceMatcher(None, domain_name, trusted_name).ratio()

        # Avoid flagging exact matches and very short/common strings.
        if score > best_score:
            best_score = score
            best_match = trusted

    # Flag close matches only when there is a meaningful difference.
    if best_match and best_score >= threshold and domain != best_match:
        return {
            "is_lookalike": True,
            "domain": domain,
            "suggestion": best_match,
            "similarity": round(best_score * 100, 2)
        }

    return {
        "is_lookalike": False,
        "domain": domain,
        "suggestion": None,
        "similarity": round(best_score * 100, 2)
    }