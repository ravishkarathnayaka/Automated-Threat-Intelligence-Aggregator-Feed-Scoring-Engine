"""Synthetic, high-fidelity mock threat intelligence dataset for offline $0 verification."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

now = datetime.now(timezone.utc)


def get_synthetic_indicators() -> List[Dict[str, Any]]:
    """Return a rich dataset of realistic indicators across multiple threat types."""
    return [
        # --- Multi-Source Confirmed High-Risk Threats ---
        {
            "value": "185.220.101.5",
            "type": "ipv4",
            "source": "abuseipdb",
            "source_weight": 0.85,
            "reported_confidence": 100.0,
            "reported_at": (now - timedelta(hours=3)).isoformat(),
            "tags": ["tor-exit", "brute-force", "ssh-scan"],
            "reference_url": "https://www.abuseipdb.com/check/185.220.101.5",
            "raw_metadata": {"isp": "Tor Relay Service", "reports": 512},
        },
        {
            "value": "185.220.101.5",
            "type": "ipv4",
            "source": "urlhaus",
            "source_weight": 0.85,
            "reported_confidence": 95.0,
            "reported_at": (now - timedelta(hours=2)).isoformat(),
            "tags": ["mozi", "botnet", "arm"],
            "reference_url": "https://urlhaus.abuse.ch/browse/",
            "raw_metadata": {"threat": "malware_download"},
        },
        {
            "value": "194.26.29.112",
            "type": "ipv4",
            "source": "abuseipdb",
            "source_weight": 0.85,
            "reported_confidence": 92.0,
            "reported_at": (now - timedelta(days=1)).isoformat(),
            "tags": ["cobalt-strike", "c2", "web-exploit"],
            "reference_url": "https://www.abuseipdb.com/check/194.26.29.112",
        },
        {
            "value": "194.26.29.112",
            "type": "ipv4",
            "source": "otx",
            "source_weight": 0.75,
            "reported_confidence": 88.0,
            "reported_at": (now - timedelta(days=1, hours=2)).isoformat(),
            "tags": ["cobalt-strike", "apt29-cozybear"],
            "reference_url": "https://otx.alienvault.com/indicator/ip/194.26.29.112",
        },

        # --- Malicious Domains & URLs (some defanged) ---
        {
            "value": "c2-beacon[.]darknet-ops[.]cc",
            "type": "domain",
            "source": "threatfox",
            "source_weight": 0.85,
            "reported_confidence": 95.0,
            "reported_at": (now - timedelta(hours=6)).isoformat(),
            "tags": ["cobalt-strike", "c2", "dns-tunneling"],
            "reference_url": "https://threatfox.abuse.ch/ioc/1001",
        },
        {
            "value": "evil-payload-distribution.xyz",
            "type": "domain",
            "source": "urlhaus",
            "source_weight": 0.85,
            "reported_confidence": 90.0,
            "reported_at": (now - timedelta(days=2)).isoformat(),
            "tags": ["redline", "stealer", "phishing"],
            "reference_url": "https://urlhaus.abuse.ch/url/10102/",
        },
        {
            "value": "hxxp://evil-payload-distribution[.]xyz/invoice.exe",
            "type": "url",
            "source": "urlhaus",
            "source_weight": 0.85,
            "reported_confidence": 92.0,
            "reported_at": (now - timedelta(days=2)).isoformat(),
            "tags": ["redline", "stealer", "executable"],
            "reference_url": "https://urlhaus.abuse.ch/url/10102/",
        },

        # --- File Hashes ---
        {
            "value": "ed01ebf83334a19370a4a22454232639ac4e404a5e252429fb21861e45235a9f",
            "type": "sha256",
            "source": "virustotal",
            "source_weight": 0.80,
            "reported_confidence": 100.0,
            "reported_at": (now - timedelta(days=5)).isoformat(),
            "tags": ["wannacry", "ransomware", "eternalblue"],
            "reference_url": "https://www.virustotal.com/gui/file/ed01ebf83334a19370a4a22454232639ac4e404a5e252429fb21861e45235a9f",
        },
        {
            "value": "51dc30dd61c70e45d963b30441030b9a",
            "type": "md5",
            "source": "manual_entry",
            "source_weight": 0.90,
            "reported_confidence": 95.0,
            "reported_at": (now - timedelta(days=3)).isoformat(),
            "tags": ["lockbit", "ransomware", "dropper"],
        },

        # --- CISA KEV Vulnerabilities ---
        {
            "value": "CVE-2021-44228",
            "type": "cve",
            "source": "cisa_kev",
            "source_weight": 1.00,
            "reported_confidence": 100.0,
            "reported_at": "2021-12-10T00:00:00Z",
            "tags": ["cisa-kev", "actively-exploited", "log4shell", "ransomware-associated"],
            "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
        {
            "value": "CVE-2023-46805",
            "type": "cve",
            "source": "cisa_kev",
            "source_weight": 1.00,
            "reported_confidence": 100.0,
            "reported_at": "2024-01-12T00:00:00Z",
            "tags": ["cisa-kev", "actively-exploited", "vendor:ivanti", "auth-bypass"],
            "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-46805",
        },

        # --- Benign Assets for Whitelist Testing (Should Score 0) ---
        {
            "value": "8.8.8.8",
            "type": "ipv4",
            "source": "community_feed",
            "source_weight": 0.60,
            "reported_confidence": 80.0,
            "reported_at": now.isoformat(),
            "tags": ["false-positive-test"],
        },
        {
            "value": "1.1.1.1",
            "type": "ipv4",
            "source": "community_feed",
            "source_weight": 0.60,
            "reported_confidence": 90.0,
            "reported_at": now.isoformat(),
            "tags": ["false-positive-test"],
        },
        {
            "value": "192.168.1.1",
            "type": "ipv4",
            "source": "community_feed",
            "source_weight": 0.60,
            "reported_confidence": 75.0,
            "reported_at": now.isoformat(),
            "tags": ["internal-router"],
        },
        {
            "value": "google.com",
            "type": "domain",
            "source": "community_feed",
            "source_weight": 0.60,
            "reported_confidence": 85.0,
            "reported_at": now.isoformat(),
            "tags": ["false-positive-test"],
        },
    ]
