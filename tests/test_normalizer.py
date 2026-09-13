"""Unit tests validating IP, domain, hash, URL parsing, refanging, and defanging."""

import pytest

from cti_core.models.indicator import IndicatorType
from cti_core.processors.normalizer import (
    defang,
    identify_indicator_type,
    normalize_indicator,
    refang,
)


def test_refanging():
    """Verify stripping of brackets and obfuscations."""
    assert refang("198[.]51[.]100[.]14") == "198.51.100.14"
    assert refang("hxxp://evil-site[.]com/bin") == "http://evil-site.com/bin"
    assert refang("hxxps://c2.darknet[.]xyz") == "https://c2.darknet.xyz"
    assert refang("badguy[at]malware[.]org") == "badguy@malware.org"
    assert refang("[185.220.101.5]") == "185.220.101.5"


def test_defanging():
    """Verify defanging makes indicators safe from unintended clicks."""
    assert defang("1.1.1.1") == "1[.]1[.]1[.]1"
    assert defang("http://evil.com") == "hxxp://evil[.]com"
    assert defang("https://malware.org/path") == "hxxps://malware[.]org/path"


def test_identify_ipv4():
    """Validate IPv4 detection and normalization."""
    ioc_type, val = identify_indicator_type("185[.]220[.]101[.]5")
    assert ioc_type == IndicatorType.IPV4
    assert val == "185.220.101.5"


def test_identify_ipv6():
    """Validate IPv6 detection."""
    ioc_type, val = identify_indicator_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert ioc_type == IndicatorType.IPV6
    assert val == "2001:db8:85a3::8a2e:370:7334"


def test_identify_domain():
    """Validate FQDN domain detection."""
    ioc_type, val = identify_indicator_type("evil-c2-beacon[.]top")
    assert ioc_type == IndicatorType.DOMAIN
    assert val == "evil-c2-beacon.top"


def test_identify_url():
    """Validate URL normalization and port stripping."""
    ioc_type, val = identify_indicator_type("hxxp://185.220.101.5:80/bins/mozi.arm")
    assert ioc_type == IndicatorType.URL
    assert val == "http://185.220.101.5/bins/mozi.arm"


def test_identify_hashes():
    """Validate MD5, SHA1, and SHA256 hashes."""
    md5 = "51dc30dd61c70e45d963b30441030b9a"
    sha1 = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    sha256 = "ed01ebf83334a19370a4a22454232639ac4e404a5e252429fb21861e45235a9f"

    assert identify_indicator_type(md5)[0] == IndicatorType.MD5
    assert identify_indicator_type(sha1)[0] == IndicatorType.SHA1
    assert identify_indicator_type(sha256)[0] == IndicatorType.SHA256
    # Uppercase normalization
    assert identify_indicator_type(sha256.upper()) == (IndicatorType.SHA256, sha256.lower())


def test_identify_cve():
    """Validate CVE identifier parsing."""
    ioc_type, val = identify_indicator_type("cve-2021-44228")
    assert ioc_type == IndicatorType.CVE
    assert val == "CVE-2021-44228"


def test_invalid_indicators():
    """Verify that unparseable and invalid strings raise ValueError."""
    with pytest.raises(ValueError):
        identify_indicator_type("not an indicator at all")
    with pytest.raises(ValueError):
        identify_indicator_type("999.999.999.999")
    with pytest.raises(ValueError):
        identify_indicator_type("http://")


def test_normalize_indicator_pipeline():
    """Verify full normalize_indicator helper output format."""
    ioc_type, norm_val, defanged_val = normalize_indicator("hxxp://evil-site[.]com:80/file.exe")
    assert ioc_type == IndicatorType.URL
    assert norm_val == "http://evil-site.com/file.exe"
    assert "hxxp://" in defanged_val
    assert "[.]" in defanged_val
