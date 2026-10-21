# Threat Intelligence Feed Taxonomy & Reliability Matrix

SENTINEL CTI Engine aggregates, deduplicates, and normalizes telemetry across 16+ open-source, commercial, and community threat feeds.

---

## 1. Feed Taxonomy Breakdown

| Feed Name | Threat Category | Indicator Types | Update Cadence | Baseline Weight | False Positive Risk |
|-----------|-----------------|-----------------|----------------|-----------------|---------------------|
| **Feodo Tracker** | Botnet C2 (Dridex, Emotet, Qakbot) | IPv4 | 15 mins | 0.95 | Very Low |
| **Abuse.ch ThreatFox** | Multi-family Malware IoCs | IP, Domain, URL, Hash | 10 mins | 0.90 | Low |
| **Abuse.ch URLhaus** | Malware Distribution URLs | URL, Domain | 5 mins | 0.85 | Low |
| **Spamhaus DROP / EDROP** | Hijacked & Stolen Netblocks | IPv4 (CIDR) | 60 mins | 0.95 | Minimal |
| **VXVault** | Direct Malware Download URLs | URL, Hash | 30 mins | 0.85 | Low |
| **GreyNoise** | Internet-wide Benign/Malicious Scanners | IPv4 | 60 mins | 0.85 | Low |
| **CINS Army** | Verified Brute-Force & Bot IPs | IPv4 | 60 mins | 0.80 | Low |
| **GreenSnow** | SSH, RDP, SQL Attack Sources | IPv4 | 30 mins | 0.75 | Low-Medium |
| **Dataplane** | Protocol-Level Attackers (SSH, SIP, VNC) | IPv4 | 30 mins | 0.75 | Low-Medium |
| **Blocklist.de** | Fail2Ban Automated Reports | IPv4 | 30 mins | 0.75 | Medium |
| **Tor Project** | Onion Router Exit Nodes | IPv4 | 30 mins | 0.60 | High (Privacy Tool) |
| **OpenPhish** | Active Phishing URLs | URL | 15 mins | 0.85 | Low-Medium |
| **PhishTank** | Verified Phishing Community | URL | 30 mins | 0.80 | Low-Medium |
| **TweetFeed** | Social OSINT Malware Mentions | IP, Domain, Hash | Real-time | 0.70 | Medium |
| **AlienVault OTX** | Pulses & Community Threat Feeds | Multi-format | Real-time | 0.70 | Medium |
| **URLScan.io** | Automated DOM & HTTP Scans | Domain, URL, IP | Real-time | 0.75 | Low |

---

## 2. Ingestion & Normalization Standard

Every ingested indicator undergoes an 8-stage normalization pipeline:
1. **Refanging**: Stripping safety brackets (`hxxp://`, `[.]`, `[:]`).
2. **Type Identification**: Strict regex and cryptographic validation (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, CVE).
3. **Punycode Decoding**: IDNA decode to catch Cyrillic/Greek homograph spoofing.
4. **Bogon & RFC 1918 Filtering**: Automatic exclusion of private and loopback addresses.
5. **Whitelist Verification**: Matching against global Alexa/Cisco Umbrella Top 1M, Microsoft, Google, AWS subnets.
6. **Enrichment**: Autonomous System (ASN), Shannon entropy, GeoIP, and MITRE ATT&CK mapping.
7. **Consensus & Bayesian Updating**: Cross-feed correlation calculation.
8. **Decay Evaluation**: Half-life or logistic sigmoid confidence reduction.
