# Changelog

All notable changes to the **Automated Threat Intelligence Aggregator & Feed Scoring Engine** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.5.0] - 2026-10-22

### Added
- **Modern Enterprise SIEM / SOAR & Firewall Exporters**:
  - `SplunkLookupExporter`: Splunk ES threat intelligence lookup table CSV generator (`/api/v1/export/splunk.csv`).
  - `TaniumExporter`: Tanium Threat Response OpenIOC package JSON generator (`/api/v1/export/tanium.json`).
  - `PaloAltoEDLExporter`: Palo Alto Networks PAN-OS External Dynamic List generator (`/api/v1/export/palo-alto-edl.txt`).
  - `Snort3Exporter`: Modern Snort 3 IPS Lua rule generator (`/api/v1/export/snort3.rules`).
  - `VyOSExporter`: VyOS and EdgeRouter firewall address-group script generator (`/api/v1/export/vyos.sh`).
  - `ZeekNoticeExporter`: Zeek Bro notice policy and alarm script generator.
  - `CrowdStrikeFDRExporter`: CrowdStrike Falcon Data Replicator Athena SQL query exporter.
  - `MISPFeedManifestExporter`: MISP Feed manifest and warninglist exporter.

- **Advanced Threat Telemetry Collectors**:
  - `InversionDNSBLCollector`: Malicious spam and spammer IP blocklist collector.
  - `RutgersBadHostsCollector`: Rutgers bad hosts automated scanner IP collector.
  - `BambenekC2Collector`: Bambenek Consulting master C2 domain intelligence collector.
  - `MalwareBazaarCollector`: Abuse.ch MalwareBazaar SHA256 malware payload collector.
  - `ThreatViewCSCollector`: ThreatView.io high-confidence Cobalt Strike C2 collector.
  - `ViriBackC2Collector`: ViriBack C2 Tracker malware panel and command node collector.
  - `FeodoTrackerCollector`: Feodo Tracker aggressive botnet C2 IP collector.
  - `SSLBLBotnetCollector`: Abuse.ch SSLBL botnet C2 IP and port collector.

- **Next-Generation Indicator Processors**:
  - `WhoisRegistrarClassifier`: Domain registrar reputation and privacy guard classifier.
  - `JA4FingerprintProcessor`: Fox-IT JA4 TLS client network fingerprint analyzer.
  - `ASNPeerEvaluator`: BGP upstream transit and ASN peer connectivity risk evaluator.
  - `FaviconHashCalculator`: Web application favicon MurmurHash3 fingerprint calculator.
  - `CoOccurrenceClusterer`: Indicator co-occurrence clusterer for APT campaign attribution.
  - `CertificateSerialNormalizer`: X.509 certificate serial number and thumbprint normalizer.
  - `DGANgramClassifier`: Domain character bigram transition probability classifier for DGAs.
  - `UserAgentAnomalyDetector`: User-Agent structure anomaly and entropy evaluator.

- **Stochastic Scoring & Mathematical Models**:
  - `MarkovThreatStateModel`: Discrete-time Markov chain threat infrastructure life cycle transition model.
  - `InformationGainEvaluator`: Shannon information gain evaluator for multi-feed corroboration.
  - `WeibullReliabilityModel`: 2-parameter Weibull distribution hazard rate model for infrastructure obsolescence.
  - `KalmanConfidenceFilter`: 1-Dimensional Kalman filter for dynamic confidence state estimation.
  - `GiniFeedDiversity`: Gini-Simpson feed diversity index for vendor independence assessment.

- **API Endpoints & CLI Capabilities**:
  - Mathematical simulation endpoint: `POST /api/v1/scoring/simulate`.
  - Modern export endpoints: `/api/v1/export/splunk.csv`, `/palo-alto-edl.txt`, `/tanium.json`, `/snort3.rules`, `/vyos.sh`.
  - CLI subcommands: `ja4`, `favicon`, `markov`, `kalman`, `telemetry`.
  - CLI export flag: `--json-export` for JSON metadata wrapping.

- **Technical Documentation & Web Portal UI**:
  - `docs/MATHEMATICAL_MODELS_V2.md`: Formal mathematical specification of Markov, Weibull, and Kalman filters.
  - `docs/ENTERPRISE_SIEM_TAXONOMY.md`: Enterprise SIEM/SOAR ingestion reference matrix.
  - Interactive UI export cards and client generation logic for Splunk, Tanium, Palo Alto EDL, and Snort 3.

### Changed
- Synchronized web portal assets from `web/` to `api/web/`.
- Upgraded test suite coverage to 259 passing tests with 100% pass rate.

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
