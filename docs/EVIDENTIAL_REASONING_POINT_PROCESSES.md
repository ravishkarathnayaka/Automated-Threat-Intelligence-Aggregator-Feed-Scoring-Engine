# Dempster-Shafer Evidence Theory, Point Processes & Sequential Change-Point Models

The **SENTINEL CTI Engine v4.0.0** introduces advanced evidential reasoning, self-exciting point processes, optimal transport drift metrics, and sequential change-point detection.

---

## 1. Dempster-Shafer Evidence Theory (`DempsterShaferScorer`)

Unlike point-valued Bayesian probabilities, Dempster-Shafer theory models explicit **epistemic ignorance** over the frame of discernment $\Theta = \{\text{Malicious } (M), \text{Benign } (B)\}$ with power set $2^\Theta = \{\emptyset, \{M\}, \{B\}, \{M, B\}\}$.

- **Basic Probability Assignment (BPA)**: $m: 2^\Theta \to [0, 1]$ such that $m(\{M\}) + m(\{B\}) + m(\{M, B\}) = 1$.
- **Dempster's Rule of Combination**:
  $$m_{1 \oplus 2}(A) = \frac{1}{1 - K} \sum_{B \cap C = A} m_1(B) m_2(C), \quad K = m_1(\{M\})m_2(\{B\}) + m_1(\{B\})m_2(\{M\})$$
- **Belief & Plausibility Interval**:
  $$\text{Bel}(M) = m(\{M\}), \quad \text{Pl}(M) = m(\{M\}) + m(\{M, B\})$$
- **Pignistic Probability Transform**:
  $$\text{BetP}(M) = \text{Bel}(M) + \frac{1}{2} m(\{M, B\})$$

---

## 2. Hawkes Self-Exciting Point Process (`HawkesProcessIntensityModel`)

Captures temporal clustering and self-excitation in coordinated APT intrusions and botnet C2 swarms:

$$\lambda(t) = \mu + \sum_{t_i < t} \alpha \exp(-\beta (t - t_i))$$

- $\mu$: Exogenous baseline arrival rate.
- $\alpha$: Endogenous jump intensity per sighting.
- $\beta$: Exponential relaxation rate.
- **Branching Ratio**: $n^* = \frac{\alpha}{\beta}$ measures the expected number of secondary sightings triggered by a single event.

---

## 3. 1-D Wasserstein (Earth Mover's) Distance (`WassersteinDriftEvaluator`)

Measures minimum-cost optimal transport between empirical feed confidence distributions $P$ and $Q$:

$$W_1(P, Q) = \int_0^1 \left| F_P^{-1}(q) - F_Q^{-1}(q) \right| dq$$

Unlike Kullback-Leibler divergence, $W_1$ is a true metric and remains bounded and informative even when distributions have non-overlapping supports.

---

## 4. Page's Tabular CUSUM Change-Point Detector (`CUSUMChangePointDetector`)

Detects abrupt upward step-changes in threat indicator velocity:

$$S_t = \max\left(0, S_{t-1} + (x_t - \mu_0 - k)\right)$$

Triggers an APT velocity surge alert when $S_t \ge h$.

---

## 5. Thompson Sampling Multi-Armed Bandit (`ThompsonSamplingBandit`)

Optimizes threat feed polling schedules under rate-limit constraints by modeling each feed $i$ as a Beta-Bernoulli arm $\text{Beta}(\alpha_i, \beta_i)$ and ranking feeds by posterior mean plus epistemic exploration bonus:

$$I_i = \frac{\alpha_i}{\alpha_i + \beta_i} + \sqrt{\frac{\alpha_i \beta_i}{(\alpha_i + \beta_i)^2 (\alpha_i + \beta_i + 1)}}$$

---

## 6. Brier Quadratic Proper Scoring Rule (`BrierScoreCalibrator`)

Quantifies empirical calibration accuracy of threat feeds against verified SOC incident outcomes:

$$\text{BS} = \frac{1}{N} \sum_{i=1}^N (f_i - o_i)^2$$

---

## 7. Bhattacharyya Coefficient & Distance (`BhattacharyyaDistanceScorer`)

Evaluates MITRE ATT&CK TTP and tag distribution overlap for threat actor campaign attribution:

$$BC(P, Q) = \sum_{x \in \mathcal{X}} \sqrt{P(x) Q(x)}, \quad D_B(P, Q) = -\ln(BC(P, Q))$$
