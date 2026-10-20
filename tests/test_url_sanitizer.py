"""Unit tests verifying URL parameter sanitization and root domain extraction."""

from cti_core.processors.url_sanitizer import URLSanitizer


def test_strip_tracking_params():
    """Verify utm_* and advertising query tokens are stripped while malicious payloads remain."""
    dirty_url = "http://evil-malware.cc/download.php?payload=trojan.exe&utm_source=spam&utm_medium=email"
    cleaned = URLSanitizer.strip_tracking_params(dirty_url)
    assert "utm_source=spam" not in cleaned
    assert "utm_medium=email" not in cleaned
    assert "payload=trojan.exe" in cleaned
    assert cleaned == "http://evil-malware.cc/download.php?payload=trojan.exe"


def test_extract_root_domain():
    """Verify extracting host/domain from various URL structures."""
    url1 = "https://sub.evil-domain.cc:8443/gate.php"
    assert URLSanitizer.extract_root_domain(url1) == "sub.evil-domain.cc"

    url2 = "http://185.220.101.5:8080/mozi.arm"
    assert URLSanitizer.extract_root_domain(url2) == "185.220.101.5"


def test_get_url_path_segments():
    """Verify path token splitting."""
    url = "https://c2.org/api/v1/beacons/checkin"
    segments = URLSanitizer.get_url_path_segments(url)
    assert segments == ["api", "v1", "beacons", "checkin"]
