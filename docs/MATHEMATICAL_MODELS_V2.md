# Mathematical Models & Stochastic Scoring Specification (v2.5.0)

This document provides the formal mathematical derivations, stochastic formulations, and calibration parameters powering the analytical scoring engine in SENTINEL-CTI.

---

## 1. Discrete Markov Chain Threat State Transition Model

Adversary infrastructure follows distinct life cycle stages. SENTINEL models this trajectory as a discrete-time Markov chain $(X_t)_{t \ge 0}$ defined over the state space:

$$\mathcal{S} = \{\text{Dormant}, \text{Active}, \text{Monitored}, \text{Remediated}\}$$

### Stochastic Transition Matrix

The one-step transition probabilities $P_{ij} = \mathbb{P}(X_{t+1} = j \mid X_t = i)$ are represented by the stochastic matrix $P \in \mathbb{R}^{4 \times 4}$:

$$P = \begin{pmatrix}
0.85 & 0.12 & 0.02 & 0.01 \\
0.05 & 0.70 & 0.15 & 0.10 \\
0.20 & 0.15 & 0.50 & 0.15 \\
0.05 & 0.02 & 0.03 & 0.90
\end{pmatrix}$$

Where:
- **Dormant** infrastructure exhibits high self-persistence ($P_{00} = 0.85$) until weaponization ($P_{01} = 0.12$).
- **Active** C2 nodes degrade into monitored honeypot traps or sinkholes ($P_{12} = 0.15$) or undergo takedown ($P_{13} = 0.10$).
- **Remediated** indicators act as absorbing-like states with high persistence ($P_{33} = 0.90$).

Marginal state distributions at step $n$ are calculated recursively:

$$\mathbf{\pi}^{(n)} = \mathbf{\pi}^{(0)} P^n$$

---

## 2. Weibull Distribution Hazard Rate & Infrastructure Obsolescence

Unlike memoryless exponential decay models, adversary indicators experience variable failure rates over time. SENTINEL utilizes the 2-parameter Weibull distribution:

### Reliability & Hazard Rate Functions

1. **Reliability (Survival) Function $R(t)$**:
   $$R(t) = \exp\left( - \left(\frac{t}{\lambda}\right)^k \right)$$

2. **Instantaneous Hazard Rate $h(t)$**:
   $$h(t) = \frac{k}{\lambda} \left(\frac{t}{\lambda}\right)^{k-1}$$

Where:
- $\lambda > 0$ is the scale parameter (characteristic indicator lifespan in days).
- $k > 0$ is the dimensionless shape parameter.

### Indicator Type Parameterization

| Indicator Type | Scale $\lambda$ (days) | Shape $k$ | Regime | Physical Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **URL** | 2.5 | 0.75 | $k < 1$ (Infant Mortality) | Fast triage and domain takedown burn phishing links rapidly. |
| **IPv4 / IPv6** | 8.0 | 1.20 | $k > 1$ (Wear-out) | Cloud VPS rotations and SOC blacklisting increase hazard over time. |
| **Domain** | 25.0 | 1.35 | $k > 1$ (Wear-out) | C2 domain registrar revocation and sinkholing cycle. |
| **SHA256** | 180.0 | 0.95 | $k \approx 1$ (Constant) | Malware binary hashes remain persistent across long attack campaigns. |

Decayed threat confidence is governed by:

$$S(t) = \max\left(\text{floor}, S_0 \cdot R(t)\right)$$

---

## 3. 1-Dimensional Kalman Filter for Dynamic Feed Confidence

When multiple disparate threat feeds report confidence scores sequentially, observations contain stochastic sensor noise $v_t \sim \mathcal{N}(0, R)$ while adversary infrastructure drifts according to process noise $w_t \sim \mathcal{N}(0, Q)$.

### System Equations

$$\text{State equation: } x_t = x_{t-1} + w_t, \quad w_t \sim \mathcal{N}(0, Q)$$

$$\text{Observation equation: } z_t = x_t + v_t, \quad v_t \sim \mathcal{N}(0, R)$$

### Recursive Estimation Algorithm

1. **Time Update (Predict)**:
   $$\hat{x}_t^- = \hat{x}_{t-1}$$
   $$P_t^- = P_{t-1} + Q \cdot \Delta t$$

2. **Measurement Update (Correct)**:
   $$K_t = \frac{P_t^-}{P_t^- + R} \quad \text{(Kalman Gain)}$$
   $$\hat{x}_t = \hat{x}_t^- + K_t \left( z_t - \hat{x}_t^- \right)$$
   $$P_t = (1 - K_t) P_t^- \quad \text{(Posterior Error Variance)}$$

Where default engine parameters are configured as:
- Initial estimate $\hat{x}_0 = 50.0$
- Initial variance $P_0 = 100.0$
- Process noise variance $Q = 4.0$
- Sensor noise variance $R = 25.0$

---

## 4. Shannon Information Gain Corroboration

Feed corroboration uncertainty is quantified through Shannon entropy:

$$H(X) = - \sum_{i=1}^n p(x_i) \log_2 p(x_i)$$

The information gain $IG(T, F)$ achieved when feed $F$ corroborates an indicator is:

$$IG(T, F) = H(T) - H(T \mid F)$$

A higher information gain increases the cross-source corroboration multiplier without inflating false-positive weights.

---

## 5. Gini-Simpson Diversity Index for Vendor Independence

To safeguard against feed redundancy where multiple feeds mirror identical underlying sources, SENTINEL computes the Gini-Simpson index:

$$D = 1 - \sum_{i=1}^M p_i^2$$

Where $p_i = \frac{n_i}{N}$ is the proportion of total corroborations provided by vendor $i$. 
- $D = 0$: Monopolistic dependence on a single telemetry source.
- $D \to 1$: Uniform, multi-source corroboration across independent intelligence providers.
