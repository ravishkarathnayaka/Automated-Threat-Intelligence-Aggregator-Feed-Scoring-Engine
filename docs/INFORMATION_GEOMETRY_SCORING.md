# Information Geometry & Stochastic Threat Scoring Models

The **SENTINEL CTI Engine** implements advanced statistical, information-geometric, and Bayesian scoring models to quantify uncertainty, mitigate cognitive bias, and evaluate multi-category threat telemetry.

---

## 1. Dirichlet-Multinomial Multi-Category Classifier

Extends binary Beta-Binomial conjugate Bayesian updates to arbitrary discrete threat categories (e.g., $K = \{\text{c2}, \text{malware}, \text{phishing}, \text{scanner}, \text{benign}\}$).

- **Hyperparameters**: $\boldsymbol{\alpha} = (\alpha_1, \dots, \alpha_K)$
- **Posterior Expectation**:
  $$\mathbb{E}[p_k] = \frac{\alpha_k + x_k}{\sum_{i=1}^K (\alpha_i + x_i)}$$
- **Epistemic Variance**:
  $$\text{Var}(p_k) = \frac{\alpha_k (\alpha_0 - \alpha_k)}{\alpha_0^2 (\alpha_0 + 1)}, \quad \alpha_0 = \sum \alpha_i$$
- **Shannon Entropy**:
  $$H(\mathbf{p}) = -\sum_{k=1}^K p_k \ln(p_k)$$

---

## 2. Kleinberg HITS Hub & Authority Centrality

Adapted from hyperlink analysis to uncover dual relationships in adversary infrastructure:

- **Authorities**: Target infrastructure nodes heavily leveraged by malware (e.g. C2 staging IPs, payload drops).
- **Hubs**: Pivots and service brokers (e.g. bulletproof nameservers, fast-flux proxy relays) directing traffic to authorities.
- **Power Iteration**:
  $$a(v) = \sum_{u \to v} h(u), \quad h(u) = \sum_{u \to v} a(v)$$
  Normalized using Euclidean $L_2$ norm.

---

## 3. Gumbel Extreme Value Distribution (Type I)

Models the asymptotic distribution of sample maximums to identify statistically rare APT velocity surges and DDoS flash attacks:

- **Cumulative Distribution**:
  $$F(x) = \exp\left(-\exp\left(-\frac{x - \mu}{\beta}\right)\right)$$
- **Return Period**:
  $$T = \frac{1}{1 - F(x)}$$

---

## 4. Relative Entropy & Jensen-Shannon Drift Evaluator

Detects distribution shift and concept drift across intelligence feeds over time:

- **Kullback-Leibler Divergence**:
  $$D_{KL}(P \parallel Q) = \sum_{i} P(i) \ln \frac{P(i)}{Q(i)}$$
- **Jensen-Shannon Divergence**:
  $$JSD(P \parallel Q) = \frac{1}{2} D_{KL}(P \parallel M) + \frac{1}{2} D_{KL}(Q \parallel M), \quad M = \frac{1}{2}(P + Q)$$

---

## 5. Additive Laplace Smoothing

Calibrates feed precision under extreme data sparsity (e.g. 1 observation, 1 hit):

$$\hat{p} = \frac{x + \alpha}{N + \alpha K}$$

Eliminates overconfident 0% and 100% boundary pathologies.

---

## 6. Mahalanobis Distance Multivariate Outlier Detector

Accounts for covariance across heterogeneous threat metrics (e.g., lexical entropy, query frequency, TTL lifespan):

$$D_M(\mathbf{x}) = \sqrt{(\mathbf{x} - \boldsymbol{\mu})^T \boldsymbol{\Sigma}^{-1} (\mathbf{x} - \boldsymbol{\mu})}$$

Regularized with Tikhonov ridge stabilization $\boldsymbol{\Sigma}_{\text{reg}} = \boldsymbol{\Sigma} + \lambda \mathbf{I}$.

---

## 7. Bray-Curtis Ecological Dissimilarity

Measures indicator portfolio overlap across threat feeds:

$$BC_{jk} = \frac{\sum_i |x_{ij} - x_{ik}|}{\sum_i (x_{ij} + x_{ik})}$$

Used to eliminate vendor feed redundancy and maximize threat perimeter visibility.
