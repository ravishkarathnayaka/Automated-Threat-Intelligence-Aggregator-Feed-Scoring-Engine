"""Unit tests verifying false positive prevention for critical infrastructure and RFC 1918."""

from cti_core.processors.whitelist_filter import WhitelistFilter


def test_public_dns_resolvers_whitelisted():
    """Ensure essential public resolvers are strictly whitelisted."""
    resolvers = [
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "208.67.222.222",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ]
    for ip in resolvers:
        is_wl, reason = WhitelistFilter.is_whitelisted("ipv4" if ":" not in ip else "ipv6", ip)
        assert is_wl is True, f"Failed to whitelist public DNS: {ip}"
        assert reason is not None


def test_rfc1918_private_ips_whitelisted():
    """Ensure internal private subnets cannot be blocked."""
    private_ips = [
        "10.0.0.1",
        "10.254.1.50",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.100.55",
        "127.0.0.1",       # Loopback
        "169.254.10.20",   # Link-Local
    ]
    for ip in private_ips:
        is_wl, reason = WhitelistFilter.is_whitelisted("ipv4", ip)
        assert is_wl is True, f"Failed to whitelist private IP: {ip}"
        assert "RFC 1918" in reason or "Loopback" in reason or "Link-Local" in reason


def test_top_domains_whitelisted():
    """Ensure high-traffic legitimate domains and subdomains are whitelisted."""
    domains = [
        "google.com",
        "microsoft.com",
        "github.com",
        "cloudflare.com",
        "login.microsoft.com",   # Subdomain check
        "mail.google.com",        # Subdomain check
        "api.github.com",         # Subdomain check
    ]
    for d in domains:
        is_wl, reason = WhitelistFilter.is_whitelisted("domain", d)
        assert is_wl is True, f"Failed to whitelist legitimate domain: {d}"
        assert reason is not None


def test_malicious_indicators_not_whitelisted():
    """Verify that actual malicious indicators are NOT flagged by whitelist."""
    malicious_iocs = [
        ("ipv4", "185.220.101.5"),
        ("ipv4", "194.26.29.112"),
        ("domain", "c2-beacon.darknet-ops.cc"),
        ("domain", "evil-payload-distribution.xyz"),
        ("url", "http://evil-payload-distribution.xyz/invoice.exe"),
        ("sha256", "ed01ebf83334a19370a4a22454232639ac4e404a5e252429fb21861e45235a9f"),
    ]
    for ioc_type, val in malicious_iocs:
        is_wl, reason = WhitelistFilter.is_whitelisted(ioc_type, val)
        assert is_wl is False, f"Malicious IoC was falsely whitelisted: {val}"
        assert reason is None
