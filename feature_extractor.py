import math
from urllib.parse import urlparse

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def extract_features(url: str) -> dict:
    parsed = urlparse(url if "://" in url else "http://" + url)

    return {
        "url_length": len(url),
        "host_length": len(parsed.netloc),
        "path_length": len(parsed.path),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_digits": sum(c.isdigit() for c in url),
        "has_https": 1 if url.startswith("https") else 0,
        "entropy": calculate_entropy(url),
        "has_login_word": 1 if "login" in url.lower() else 0,
        "has_verify_word": 1 if "verify" in url.lower() else 0,
    }