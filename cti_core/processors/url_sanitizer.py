"""URL parameter sanitization, tracking token removal, and root domain extraction."""

from typing import Optional, Set
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Common tracking / noise query parameters
TRACKING_PARAMS: Set[str] = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "msclkid",
    "_ga",
    "ref",
}


class URLSanitizer:
    """Sanitizes threat URLs by normalizing query parameters, paths, and extracting root domains."""

    @staticmethod
    def strip_tracking_params(url_str: str) -> str:
        """Strip tracking parameters while preserving payload indicators."""
        parsed = urlparse(url_str.strip())
        if not parsed.query:
            return url_str.strip()

        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        filtered_params = [(k, v) for k, v in query_params if k.lower() not in TRACKING_PARAMS]

        new_query = urlencode(filtered_params)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            "",  # Strip fragment identifier
        ))

    @staticmethod
    def extract_root_domain(url_str: str) -> Optional[str]:
        """Extract the root domain or IP host from a URL."""
        try:
            parsed = urlparse(url_str.strip())
            netloc = parsed.netloc.split(":")[0].lower()
            return netloc if netloc else None
        except Exception:
            return None

    @staticmethod
    def get_url_path_segments(url_str: str) -> list[str]:
        """Return non-empty path segments from a URL."""
        parsed = urlparse(url_str.strip())
        return [p for p in parsed.path.split("/") if p]
