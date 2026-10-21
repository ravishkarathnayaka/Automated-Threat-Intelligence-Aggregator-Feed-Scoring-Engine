# Changelog

All notable changes to the **Automated Threat Intelligence Aggregator & Feed Scoring Engine** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.4.0] - 2026-10-21

### Added
- **Enterprise SIEM & SOAR Exporters**:
  - `ElasticExporter`: Elasticsearch and OpenSearch bulk NDJSON export endpoint (`/api/v1/export/elastic.ndjson`).
  - `WazuhExporter`: Wazuh Constant Database (CDB) list threat rule generator (`/api/v1/export/wazuh.cdb`).
  - `AWSNetworkFirewallExporter`: Stateful IP drop rule group JSON specification (`/api/v1/export/aws-firewall.json`).
  - `AzureFirewallExporter`: Azure Firewall IP Groups ARM template exporter.
  - `QRadarExporter`: IBM QRadar Reference Set CSV and Reference Map JSON exporter.
  - `SigmaExporter`: Vendor-neutral Sigma detection rule generator (`/api/v1/export/sigma.yml`).
  - `SentinelOneExporter`: SentinelOne Deep Visibility S1QL query exporter (`/api/v1/export/sentinelone.s1ql`).
  - `MicrosoftSentinelExporter`: Microsoft Sentinel and Defender KQL hunting query exporter (`/api/v1/export/kql.txt`).
  - `CrowdStrikeExporter`: CrowdStrike Falcon Custom IOC CSV exporter (`/api/v1/export/crowdstrike.csv`).
  - `OpenDNSUmbrellaExporter`: Cisco Umbrella destination blocklist exporter.

- **Threat Feed Collectors**:
  - `GreyNoiseCollector`: Benign internet noise and malicious scanner IP collector.
  - `VXVaultCollector`: Malware distribution repository URL collector.
  - `CINSScoreCollector`: CINS Army malicious IP score feed collector.
  - `SpamhausDROPCollector`: Spamhaus Don't Route Or Peer (DROP/EDROP) network block collector.
  - `GreenSnowCollector`: GreenSnow automated attack IP blocklist collector.
  - `TweetFeedCollector`: Social intelligence OSINT malware indicator collector.
  - `PhishTankCollector`: Community verified phishing URL collector.
  - `DataplaneCollector`: Dataplane protocol attack feed collector.

- **Advanced Indicator Processors**:
  - `ASNReputationProcessor`: Autonomous System Number reputation and bulletproof host classifier.
  - `SubdomainFlattener`: Dynamic DNS (DDNS) detection and subdomain extractor.
  - `SSDeepComparator`: Context-triggered piecewise fuzzy hashing similarity matcher.
  - `CVSSParser`: CVE CVSS v3.1 vector parser and metrics extractor.
  - `UserAgentValidator`: Malicious HTTP User-Agent scanner fingerprint detector.
  - `MACNormalizer`: Hardware EUI-48 and EUI-64 MAC address sanitizer.
  - `EmailAddressSanitizer`: Phishing email recipient and sender domain validator.
  - `PortServiceMapper`: Known protocol service anomaly classifier.

- **Scoring Engine Models**:
  - `BayesianScorer`: Sequential likelihood ratio updater for multi-feed evidence synthesis.
  - `FeedReliabilityTracker`: Dynamic feed precision tracker with Laplace smoothing.
  - `LogisticSigmoidDecayModel`: Campaign zero-day exploitation life cycle decay model.

- **Interactive Portal & CLI Tools**:
  - Web portal export cards for Elasticsearch, Wazuh, AWS Network Firewall, and Sigma.
  - CLI subcommands: `asn`, `dga-check`, `sigma-gen`, `bayesian`, and `--banner` diagnostics.
  - Indicator taxonomy summary endpoint: `GET /api/v1/indicators/types/summary`.

- **Technical Documentation**:
  - `docs/SIEM_INTEGRATION_GUIDE.md`: Enterprise SIEM/SOAR ingestion guide.
  - `docs/THREAT_FEED_TAXONOMY.md`: Threat intelligence feed taxonomy and reliability matrix.
  - `docs/SCORING_MATH_SPECIFICATION.md`: Mathematical scoring specification and formulas.

### Changed
- Refactored `cti_core/exporters/elastic_exporter.py` for full ECS schema compatibility and stringified source tagging.
- Updated main `README.md` with comprehensive API endpoints, CLI syntax, and documentation references.
- Upgraded test suite coverage to 198 tests with 100% pass rate.
