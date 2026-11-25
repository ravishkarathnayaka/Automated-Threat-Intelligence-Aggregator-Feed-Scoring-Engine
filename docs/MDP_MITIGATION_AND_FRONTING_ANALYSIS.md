# Advanced Threat Evasion Detection & Markov Decision Mitigation (v4.5.0)

This document specifies the algorithmic mechanisms for protocol evasion detection and automated incident response mitigation introduced in **SENTINEL CTI Engine v4.5.0**.

---

## 1. Fox-IT JA4SSH Interactive SSH Fingerprinting

Adversaries frequently use automated SSH brute-force tools (such as Hydra, Medusa, and Patator) that exhibit distinct handshake packet counts and absence of terminal window negotiations compared to human administrators.

- **Class**: `JA4SSHFingerprintProcessor`
- **Pattern**: `^[cs]_\d+_\d+_\d+_\d+$` (client/server packet and byte profile)
- **Risk Assessment**:
  - `c_1_0_0_0`: +35.0 penalty (Automated Hydra/Medusa brute-force)
  - `c_2_1_0_0`: +30.0 penalty (Multi-threaded dictionary sprayer)
  - Interactive admin sessions: 0.0 penalty (benign shell behavior)

---

## 2. TLS SNI vs HTTP Host Header Domain Fronting Detection

Adversary C2 channels often leverage domain fronting over multi-tenant CDNs (Cloudflare, CloudFront, Fastly, Azure Edge) by negotiating TLS with a benign domain (e.g., `cdn.cloudflare.com`) while sending an internal HTTP `Host: attacker-c2.com` header.

- **Class**: `DomainFrontingDetector`
- **Detection Logic**:
  $$\text{Mismatch} = \text{Clean}(\text{SNI}) \neq \text{Clean}(\text{Host})$$
- When the SNI domain belongs to recognized CDNs, a high-severity +35.0 confidence penalty is levied, flagging the session as an evasive C2 channel.

---

## 3. Dangling CNAME Subdomain Takeover Risk Engine

Identifies abandoned third-party cloud assets (e.g. GitHub Pages, AWS S3 buckets, Heroku apps, Azure App Services) where an enterprise DNS CNAME record remains active, enabling adversary takeover.

- **Class**: `SubdomainTakeoverProcessor`
- **Signatures**: Detects 404/not-found fingerprints across 6 major cloud providers.
- **Penalty**: +20.0 for unresolved cloud CNAME, +35.0 for verified dangling signature.

---

## 4. Shannon Entropy & Compression Anomaly Scoring

Detects packed, encrypted, or algorithmically obfuscated payload strings and script snippets.

- **Class**: `EntropyCompressionScorer`
- Combines character Shannon entropy $H(X) = -\sum P(x) \log_2 P(x)$ with Deflate compression ratios to distinguish random ciphertext and shellcode from natural language domains.

---

## 5. Markov Decision Process (MDP) Optimal Threat Mitigation

To bridge the gap between static confidence scores and dynamic operational response, the engine evaluates automated mitigation actions as an optimal decision problem.

- **Class**: `ThreatMitigationMDP`
- **Action Space**: `ALLOW`, `ALERT`, `TARPIT`, `QUARANTINE`, `BLOCK_IMMEDIATE`
- **Objective**: Maximize expected net utility while penalizing false-positive disruptions against business availability:
  $$U(\text{action}) = P(\text{malicious}) \cdot R(\text{mitigate}) - P(\text{benign}) \cdot C(\text{disruption})$$
