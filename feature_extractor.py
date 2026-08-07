from urllib.parse import urlparse

def extract_features(url):
    parsed = urlparse(url)

    features = [
    len(url),                      # URL length
    url.count("."),                # dots
    url.count("-"),                # hyphens
    url.count("@"),                # @
    url.count("?"),                # ?
    url.count("="),                # =
    url.count("&"),                # &
    url.count("/"),                # /
    int(parsed.scheme == "https"), # HTTPS
    len(parsed.netloc),            # domain length

    sum(c.isdigit() for c in url),                 # number of digits
    int("login" in url.lower()),                   # login
    int("verify" in url.lower()),                  # verify
    int("secure" in url.lower()),                  # secure
    int("update" in url.lower()),                  # update
    int("account" in url.lower()),                 # account
    int("bank" in url.lower()),                    # bank
    int("paypal" in url.lower()),                  # paypal
    int("signin" in url.lower()),                  # signin
    int("http" in parsed.netloc.lower())           # fake http inside domain
]

    return features