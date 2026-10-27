# Changelog

All notable changes to the **Automated Threat Intelligence Aggregator & Feed Scoring Engine** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.5.0] - 2026-10-27

### Added
- **Cloud-Native Service Mesh & Zero Trust Enforcers**:
  - `IstioPolicyExporter`: Istio Service Mesh AuthorizationPolicy DENY manifest exporter (`/api/v1/export/istio-policy.yaml`).
  - `CiliumPolicyExporter`: Cilium eBPF NetworkPolicy L3/L4/L7 egress denial manifest exporter (`/api/v1/export/cilium-policy.yaml`).
  - `EnvoyProxyExporter`: Envoy Proxy RBAC network filter denial configuration exporter.
  - `OktaZoneExporter`: Okta Identity Cloud Network Zone IP blocklist REST API payload exporter (`/api/v1/export/okta-zone.json`).
  - `TailscaleACLExporter`: Tailscale Tailnet ACL kernel drop policy exporter.
  - `CloudflareZeroTrustExporter`: Cloudflare Zero Trust Gateway list items exporter.
  - `OpenSearchMonitorExporter`: OpenSearch Security Analytics threat detector monitor JSON exporter.

- **Next-Gen Threat Telemetry Collectors**:
  - `CybercrimeTrackerCollector`: Malware control panel & C2 host intelligence collector.
  - `ThreatFoxCollector`: ThreatFox payload download URL and SHA256 IOC collector.
  - `OpenPhishCollector`: OpenPhish verified phishing URL telemetry collector.
  - `AbuseIPDBCollector`: High-confidence AbuseIPDB IP blacklist collector.
  - `IPSumCollector`: Multi-source aggregated reputation threat IP collector.
  - `StratosphereLabCollector`: IoT botnet C2 network capture feed collector.
  - `MalcodeCollector`: Drive-by malware payload domain database collector.

- **Deep Threat Feature Processors**:
  - `JA4SFingerprintProcessor`: Fox-IT JA4S TLS server response fingerprint analyzer.
  - `JA4XCertificateProcessor`: Fox-IT JA4X X.509 certificate extension fingerprint analyzer.
  - `DNSOverHTTPSDetector`: DNS-over-HTTPS (DoH) and DoT egress evasion detector.
  - `DGAHellingerClassifier`: Hellinger distance character frequency DGA classifier.
  - `BeaconJitterAnalyzer`: C2 beacon inter-arrival regularity and jitter variance estimator.
  - `TLSALPNAnomalyClassifier`: TLS ALPN application layer protocol negotiation anomaly classifier.
  - `SSLCertificateValidityEvaluator`: X.509 certificate lifespan anomaly evaluator.

- **Stochastic Scoring & Information Geometry Models**:
  - `DirichletMultinomialScorer`: Dirichlet-Multinomial Bayesian multi-category threat classifier.
  - `HITSAuthorityScorer`: Kleinberg HITS threat hub and authority centrality model.
  - `GumbelExtremeValueModel`: Gumbel Type-I extreme value distribution for rare APT volume surges.
  - `KLDivergenceEvaluator`: Relative entropy and Jensen-Shannon feed drift evaluator.
  - `LaplaceSmoothingTracker`: Additive Laplace precision smoothing estimator.
  - `MahalanobisDistanceScorer`: Regularized multivariate outlier detector for correlated telemetry.
  - `BrayCurtisDissimilarityTracker`: Bray-Curtis ecological dissimilarity for feed portfolio uniqueness.

- **REST API Endpoints & CLI Subcommands**:
  - Added `/api/v1/export/istio-policy.yaml`, `/api/v1/export/cilium-policy.yaml`, and `/api/v1/export/okta-zone.json`.
  - Added `/api/v1/scoring/dirichlet` and `/api/v1/scoring/jitter-analysis`.
  - Added CLI commands `ja4s`, `jitter`, `dirichlet`, and `doh`.
  - Updated web portal dashboard with Istio, Cilium, and Okta Zero Trust export cards.

---

## [3.0.0] - 2026-10-24

### Added
- **Next-Gen Enterprise Firewalls & Cloud-Native Exporters**:
  - CiscoFirepowerExporter: Cisco Firepower Management Center (FMC) Host & Network Object JSON generator (/api/v1/export/cisco-firepower.json).
  - JuniperSRXExporter: Juniper Junos SRX dynamic address-book and address-set CLI generator (/api/v1/export/juniper-srx.set).
  - SonicWallExporter: SonicWall SonicOS Address Object and Group configuration generator.
  - AristaEOSExporter: Arista EOS IP access-list drop rule configuration exporter.
  - F5BigIPExporter: F5 BIG-IP AFM IP intelligence internal data-group TMSH generator.
  - ModSecurityWAFExporter: OWASP ModSecurity Core Rule Set (CRS) SecRule enforcement generator.
  - K8sNetworkPolicyExporter: Kubernetes NetworkPolicy egress restriction manifest exporter (/api/v1/export/k8s-policy.yaml).

- **Advanced Threat Telemetry Collectors**:
  - AlienVaultOTXCollector: AlienVault Open Threat Exchange (OTX) pulse indicator collector.
  - PaloAltoUnit42Collector: Palo Alto Networks Unit 42 research playbook and threat actor indicator collector.
  - CryptojackingPoolCollector: Illicit Monero mining pool and stratum endpoint blocklist collector.
  - RansomwareTrackerCollector: Active ransomware C2 payment and extortion portal collector.
  - TorExitNodeCollector: Official Tor Project exit consensus relay collector.
  - PhishuntCollector: Phishunt.io suspicious credential phishing URL and domain collector.
  - CertStreamCollector: Certificate Transparency (CT) log SSL/TLS certificate brand spoof collector.

- **High-Performance Threat Processors**:
  - JA3SFingerprintProcessor: TLS Server Hello JA3S cryptographic fingerprint classifier.
  - HasshSSHProcessor: SSH client and server HASSH network fingerprint analyzer.
  - DomainTyposquatEvaluator: Levenshtein edit distance typosquatting and brand impersonation evaluator.
  - IPv6EUI64Extractor: SLAAC modified EUI-64 embedded physical MAC address and OUI extractor.
  - HTTPHeaderEntropyEvaluator: HTTP response header ordering, entropy, and C2 fingerprint evaluator.
  - BGPCommunityRiskEvaluator: BGP route community attribute and blackhole signaling risk evaluator.
  - PayloadEntropyEvaluator: Binary payload Shannon entropy and Chi-square packing detector.

- **Stochastic Scoring & Graph Models**:
  - BetaDistributionScorer: Conjugate Beta-Binomial Bayesian confidence and epistemic variance model (/api/v1/scoring/beta-distribution).
  - PageRankThreatGraph: Random-walk PageRank indicator influence in infrastructure co-occurrence graph (/api/v1/scoring/pagerank).
  - ParetoDecayModel: Heavy-tailed Pareto power-law decay model for persistent APT infrastructure.
  - AnomalyZScoreDetector: Rolling Z-score anomaly detector for feed volumetric surges.
  - EMASmoother: Dual-window Exponential Moving Average confidence and volatility smoother.
  - CosineSimilarityClusterer: Multi-hot vector cosine similarity clusterer for APT campaign attribution.
  - JaccardOverlapTracker: Multi-feed pairwise Jaccard similarity tracker for vendor redundancy.

- **CLI & Web Portal Enhancements**:
  - CLI subcommands: 	yposquat, pagerank, hassh, eta-score.
  - Portal UI export cards and client preview handlers for Cisco Firepower, Juniper SRX, and Kubernetes.
  - Comprehensive architectural guides: docs/STOCHASTIC_GRAPH_MODELS_V3.md and docs/CLOUD_NATIVE_ENFORCEMENT_GUIDE.md.

### Changed
- Promoted engine version to v3.0.0.
- Synchronized web portal static assets to FastAPI backend distribution directory.
- Test suite expanded to 287 passing tests with 100% pass rate.



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
