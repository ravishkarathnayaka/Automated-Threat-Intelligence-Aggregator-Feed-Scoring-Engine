"""IoC normalization, defanging/refanging, and strict format validation."""

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse

from cti_core.models.indicator import IndicatorType

# Regex patterns
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def refang(ioc: str) -> str:
    """Strip defanging artifacts such as brackets around dots, hxxp, etc."""
    cleaned = ioc.strip()
    # Normalize protocols
    cleaned = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group().lower() else "http://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^fxp://", "ftp://", cleaned, flags=re.IGNORECASE)

    # Remove bracketed characters
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    cleaned = cleaned.replace("[:]", ":").replace("(:)", ":")
    cleaned = cleaned.replace("[/]", "/").replace("(/)", "/")
    cleaned = cleaned.replace("[at]", "@").replace("(at)", "@")
    cleaned = cleaned.replace("[dot]", ".").replace("(dot)", ".")

    # Strip any dangling brackets on outer edges
    cleaned = cleaned.strip("[](){}")
    return cleaned.strip()


def defang(ioc: str) -> str:
    """Defang indicator to prevent accidental clickthroughs in logs or tickets."""
    defanged = ioc.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]")
    return defanged


def identify_indicator_type(raw_val: str) -> Tuple[IndicatorType, str]:
    """Identify the indicator type and return (IndicatorType, refanged_value). Raises ValueError if unrecognized."""
    val = refang(raw_val)

    # 1. Check CVE
    if RE_CVE.match(val):
        return IndicatorType.CVE, val.upper()

    # 2. Check File Hashes
    if RE_MD5.match(val):
        return IndicatorType.MD5, val.lower()
    if RE_SHA1.match(val):
        return IndicatorType.SHA1, val.lower()
    if RE_SHA256.match(val):
        return IndicatorType.SHA256, val.lower()

    # 3. Check IPv4 / IPv6
    try:
        ip_obj = ipaddress.ip_address(val)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return IndicatorType.IPV4, str(ip_obj)
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return IndicatorType.IPV6, str(ip_obj)
    except ValueError:
        pass

    # 4. Check URL
    if "://" in val or val.lower().startswith(("http://", "https://", "ftp://")):
        parsed = urlparse(val if "://" in val else f"http://{val}")
        if parsed.netloc:
            # Canonicalize scheme and lowercase netloc
            scheme = parsed.scheme.lower() or "http"
            netloc = parsed.netloc.lower()
            # Standard port removal
            if (scheme == "http" and netloc.endswith(":80")) or (scheme == "https" and netloc.endswith(":443")):
                netloc = netloc.rsplit(":", 1)[0]
            canonical_url = urlunparse((scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
            return IndicatorType.URL, canonical_url

    # 5. Check Domain
    val_domain = val.lower().rstrip(".")
    if RE_DOMAIN.match(val_domain):
        # Validate label length
        labels = val_domain.split(".")
        if all(1 <= len(label) <= 63 for label in labels):
            return IndicatorType.DOMAIN, val_domain

    raise ValueError(f"Unrecognized or invalid indicator format: '{raw_val}'")


def normalize_indicator(
    raw_val: str,
    expected_type: Optional[IndicatorType] = None,
) -> Tuple[IndicatorType, str, str]:
    """Normalize raw indicator and return (type, normalized_value, defanged_value)."""
    detected_type, normalized_val = identify_indicator_type(raw_val)

    if expected_type is not None:
        # Allow IPV4 vs IP general match
        if expected_type != detected_type:
            # If user specified URL but raw was domain without scheme, permit
            if expected_type == IndicatorType.URL and detected_type == IndicatorType.DOMAIN:
                normalized_val = f"http://{normalized_val}"
                detected_type = IndicatorType.URL
            else:
                raise ValueError(
                    f"Indicator '{raw_val}' was identified as {detected_type.value}, "
                    f"but expected type was {expected_type.value}."
                )

    defanged_val = defang(normalized_val)
    return detected_type, normalized_val, defanged_val
