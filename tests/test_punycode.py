"""Unit tests verifying Punycode conversion and homograph attack detection."""

from cti_core.processors.punycode import PunycodeProcessor


def test_punycode_roundtrip():
    """Verify Unicode domains convert to xn-- punycode and back."""
    unicode_domain = "münchen.de"
    punycode = PunycodeProcessor.to_punycode(unicode_domain)
    assert punycode == "xn--mnchen-3ya.de"

    decoded = PunycodeProcessor.to_unicode(punycode)
    assert decoded == unicode_domain


def test_ascii_domain_unchanged():
    """Verify standard ASCII domains remain unchanged."""
    ascii_domain = "evil-c2-server.com"
    assert PunycodeProcessor.to_punycode(ascii_domain) == ascii_domain
    assert PunycodeProcessor.to_unicode(ascii_domain) == ascii_domain


def test_homograph_detection():
    """Verify mixed-script Cyrillic-Latin homograph spoofing is caught."""
    # "gооgle.com" with Cyrillic 'о' (U+043E)
    cyrillic_o = "\u043e"
    spoofed = f"g{cyrillic_o}{cyrillic_o}gle.com"

    is_homo, reason = PunycodeProcessor.detect_homograph(spoofed)
    assert is_homo is True
    assert "Mixed Script Homograph Attack" in str(reason)
    assert "CYRILLIC" in str(reason)

    # Clean domain
    clean_is_homo, clean_reason = PunycodeProcessor.detect_homograph("google.com")
    assert clean_is_homo is False
    assert clean_reason is None
