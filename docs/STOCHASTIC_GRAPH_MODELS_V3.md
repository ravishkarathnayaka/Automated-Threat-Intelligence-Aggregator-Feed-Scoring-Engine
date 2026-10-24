# Stochastic & Graph-Theoretic Threat Modeling Specification (v3.0.0)

This document formalizes the stochastic, graph-theoretic, and epistemic uncertainty algorithms introduced in SENTINEL-CTI v3.0.0.

---

## 1. Beta-Binomial Conjugate Bayesian Threat Model

To move beyond point estimates of confidence and explicitly model epistemic uncertainty under small sample sizes, SENTINEL-CTI leverages the conjugate Beta-Binomial Bayesian framework.

### Formulation
Let $\theta \in [0, 1]$ represent the true latent probability that an indicator is actively malicious. We assign a Beta prior distribution:

$$P(\theta) = \text{Beta}(\alpha_0, \beta_0) = \frac{1}{\text{B}(\alpha_0, \beta_0)} \theta^{\alpha_0 - 1} (1 - \theta)^{\beta_0 - 1}$$

With uninformative / slightly conservative default parameters $\alpha_0 = 1.0, \beta_0 = 4.0$ ($\mathbb{E}[\theta] = 0.20$).

Given $k$ corroborating malicious feed reports and $m$ benign / whitelist confirmations, the conjugate posterior distribution is:

$$P(\theta \mid k, m) = \text{Beta}(\alpha_0 + k, \beta_0 + m)$$

### Metrics
- **Posterior Expectation (Confidence)**:
  $$\mathbb{E}[\theta] = \frac{\alpha}{\alpha + \beta}$$
- **Epistemic Variance (Uncertainty)**:
  $$\text{Var}[\theta] = \frac{\alpha \beta}{(\alpha + \beta)^2 (\alpha + \beta + 1)}$$

As evidence accumulates ($\alpha + \beta \to \infty$), epistemic variance contracts toward zero.

---

## 2. Threat Infrastructure PageRank Centrality

Adversary campaigns link multiple heterogeneous indicator types into complex infrastructure graphs (IP $\to$ FQDN $\to$ SSL Certificate $\to$ Executable Payload).

### Formulation
Let $G = (V, E)$ represent the threat co-occurrence graph. The PageRank score $PR(u)$ of indicator $u$ is defined by:

$$PR(u) = \frac{1 - d}{|V|} + d \sum_{v \in \mathcal{N}_{in}(u)} \frac{PR(v)}{\text{deg}_{out}(v)}$$

Where:
- $d = 0.85$ is the damping factor representing the probability that a random analyst jump traverses an infrastructure pivot link.
- $\mathcal{N}_{in}(u)$ is the set of indicators with co-occurrence links to $u$.

Nodes with highest normalized centrality represent critical C2 hub nodes whose disruption dismantles the surrounding cluster.

---

## 3. Heavy-Tailed Pareto Power-Law Decay

Traditional exponential decay $S(t) = S_0 e^{-\lambda t}$ models memoryless obsolescence, but fails for persistent nation-state APT infrastructure and dormant sleep beacons. SENTINEL utilizes the Pareto power-law distribution:

### Formulation
$$S(t) = S_0 \cdot \left( \frac{t_{\min}}{\max(t_{\min}, t)} \right)^\alpha$$

Where:
- $t_{\min}$ is the threshold before decay begins (e.g., 3 days for IPs, 30 days for file hashes).
- $\alpha > 0$ is the Pareto tail index. Lower $\alpha$ values produce heavy tails that sustain defensive alert states for long-dormant infrastructure.

---

## 4. Multi-Feed Jaccard Overlap Redundancy Index

To prevent artificial confidence inflation caused by mirrored open-source intelligence feeds, SENTINEL computes pairwise Jaccard similarity across feed indicator sets:

$$J(A, B) = \frac{|A \cap B|}{|A \cup B|}$$

When $J(A, B) \ge 0.70$, feeds $A$ and $B$ are classified as redundant, down-weighting the corroboration boost to maintain statistical independence.
