# Mathematical Scoring Engine & Probability Models Specification

The SENTINEL CTI Engine computes dynamic threat confidence scores ($0.0 \le S \le 100.0$) using probabilistic inference, information theory, and temporal decay functions.

---

## 1. Multi-Source Consensus Boost

When an indicator is corroborated across $N$ independent feeds, its confidence increases with sub-linear diminishing returns:

$$\text{Factor}(N) = 1.0 + \alpha \cdot \ln(N)$$

Where:
- $N$: Number of distinct reporting sources
- $\alpha = 0.35$: Consensus dampening coefficient
- Maximum consensus multiplier is capped at $2.2\times$.

---

## 2. Temporal Decay Models

### A. Physical Half-Life Model (Exponential)
Suitable for dynamic threats such as rotating proxy IPs and rapid phishing teardowns:

$$S(t) = S_0 \cdot \left(\frac{1}{2}\right)^{\frac{t}{t_{1/2}}}$$

Where:
- $t$: Age in days since last observation
- $t_{1/2}$: Half-life in days (Phishing URLs: 3 days, Malicious IPs: 7 days, Hashes: 180 days)

### B. Logistic Sigmoid Campaign Model
Models threat life cycles where adversary infrastructure maintains peak activity before collapsing once reported:

$$S(t) = \frac{S_0}{1 + e^{k \cdot (t - t_0)}}$$

Where:
- $t_0$: Campaign inflection midpoint (e.g., 5 days for C2 servers)
- $k$: Logistic decay steepness ($k \approx 0.5$)

---

## 3. Bayesian Likelihood Ratio Updating

Sequentially combines likelihood ratios across reporting feeds against an empirical base rate:

$$\text{Odds}_{\text{post}} = \text{Odds}_{\text{prior}} \times \prod_{i=1}^{M} \text{LR}_i \times \prod_{j=1}^{K} \text{LR}_{\text{benign}, j}$$

$$\text{Posterior Probability } P(M \mid E) = \frac{\text{Odds}_{\text{post}}}{1 + \text{Odds}_{\text{post}}}$$

$$\text{Confidence Score} = P(M \mid E) \times 100.0$$

---

## 4. Shannon Entropy for DGA Detection

Measures randomness in domain names to identify Algorithmically Generated Domains:

$$H(D) = -\sum_{i=1}^{m} P(c_i) \log_2 P(c_i)$$

Where:
- $c_i$: Unique characters in domain second-level label
- Threshold: $H(D) \ge 3.85 \implies \text{DGA Suspect}$
