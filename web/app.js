/**
 * SENTINEL CTI - Threat Intelligence & Feed Scoring Engine Portal
 * Standalone & Live-API Dual Compatible Client Logic
 */

// Configuration
const API_BASE = "http://localhost:8000/api/v1";
let isLiveApi = false;
let currentIndicators = [];
let filteredIndicators = [];

// Synthetic Fallback Dataset for Standalone Vercel Showcase
const MOCK_DATASET = [
  {
    id: "ioc-001",
    value: "185.220.101.5",
    normalized_value: "185.220.101.5",
    type: "ipv4",
    confidence_score: 98.4,
    confidence_tier: "CRITICAL",
    severity: "critical",
    tags: ["tor-exit", "ssh-bruteforce", "mozi-c2", "scanner"],
    is_whitelisted: false,
    first_seen: new Date(Date.now() - 3600000 * 24).toISOString(),
    last_seen: new Date(Date.now() - 3600000 * 2).toISOString(),
    sources: [
      { source_name: "abuseipdb", confidence: 100, reference_url: "https://www.abuseipdb.com/check/185.220.101.5" },
      { source_name: "urlhaus", confidence: 95, reference_url: "https://urlhaus.abuse.ch/browse/" }
    ],
    score_breakdown: {
      source_weight: 0.85,
      cross_source_factor: 1.25,
      decay_factor: 0.999,
      enrichment_boost: 18.0,
      final_score: 98.4,
      tier: "CRITICAL"
    },
    enrichment: {
      virustotal: { malicious_count: 42, suspicious_count: 5 },
      otx: { pulse_count: 8, malware_families: ["Mozi", "CobaltStrike"] }
    }
  },
  {
    id: "ioc-002",
    value: "194.26.29.112",
    normalized_value: "194.26.29.112",
    type: "ipv4",
    confidence_score: 89.2,
    confidence_tier: "CRITICAL",
    severity: "high",
    tags: ["cobalt-strike", "c2", "apt29-cozybear"],
    is_whitelisted: false,
    first_seen: new Date(Date.now() - 3600000 * 48).toISOString(),
    last_seen: new Date(Date.now() - 3600000 * 12).toISOString(),
    sources: [
      { source_name: "abuseipdb", confidence: 92, reference_url: "https://www.abuseipdb.com/check/194.26.29.112" },
      { source_name: "otx", confidence: 88, reference_url: "https://otx.alienvault.com/indicator/ip/194.26.29.112" }
    ],
    score_breakdown: {
      source_weight: 0.85,
      cross_source_factor: 1.25,
      decay_factor: 0.975,
      enrichment_boost: 14.0,
      final_score: 89.2,
      tier: "CRITICAL"
    }
  },
  {
    id: "ioc-003",
    value: "c2-beacon[.]darknet-ops[.]cc",
    normalized_value: "c2-beacon.darknet-ops.cc",
    type: "domain",
    confidence_score: 85.0,
    confidence_tier: "CRITICAL",
    severity: "high",
    tags: ["cobalt-strike", "dns-tunneling", "c2"],
    is_whitelisted: false,
    first_seen: new Date(Date.now() - 3600000 * 36).toISOString(),
    last_seen: new Date(Date.now() - 3600000 * 6).toISOString(),
    sources: [
      { source_name: "urlhaus", confidence: 90, reference_url: "https://urlhaus.abuse.ch/" }
    ],
    score_breakdown: {
      source_weight: 0.85,
      cross_source_factor: 1.0,
      decay_factor: 0.988,
      enrichment_boost: 12.0,
      final_score: 85.0,
      tier: "CRITICAL"
    }
  },
  {
    id: "ioc-004",
    value: "hxxp://evil-payload-distribution[.]xyz/invoice.exe",
    normalized_value: "http://evil-payload-distribution.xyz/invoice.exe",
    type: "url",
    confidence_score: 81.5,
    confidence_tier: "HIGH",
    severity: "high",
    tags: ["redline", "stealer", "executable", "urlhaus"],
    is_whitelisted: false,
    first_seen: new Date(Date.now() - 3600000 * 72).toISOString(),
    last_seen: new Date(Date.now() - 3600000 * 24).toISOString(),
    sources: [
      { source_name: "urlhaus", confidence: 92, reference_url: "https://urlhaus.abuse.ch/url/10102/" }
    ],
    score_breakdown: {
      source_weight: 0.85,
      cross_source_factor: 1.0,
      decay_factor: 0.951,
      enrichment_boost: 10.0,
      final_score: 81.5,
      tier: "HIGH"
    }
  },
  {
    id: "ioc-005",
    value: "ed01ebf83334a19370a4a22454232639ac4e404a5e252429fb21861e45235a9f",
    normalized_value: "ed01ebf83334a19370a4a22454232639ac4e404a5e252429fb21861e45235a9f",
    type: "sha256",
    confidence_score: 88.0,
    confidence_tier: "CRITICAL",
    severity: "critical",
    tags: ["wannacry", "ransomware", "eternalblue"],
    is_whitelisted: false,
    first_seen: new Date(Date.now() - 3600000 * 120).toISOString(),
    last_seen: new Date(Date.now() - 3600000 * 48).toISOString(),
    sources: [
      { source_name: "manual_entry", confidence: 95, reference_url: "https://virustotal.com" }
    ],
    score_breakdown: {
      source_weight: 0.90,
      cross_source_factor: 1.0,
      decay_factor: 0.902,
      enrichment_boost: 15.0,
      final_score: 88.0,
      tier: "CRITICAL"
    }
  },
  {
    id: "ioc-006",
    value: "CVE-2021-44228",
    normalized_value: "CVE-2021-44228",
    type: "cve",
    confidence_score: 75.0,
    confidence_tier: "HIGH",
    severity: "critical",
    tags: ["cisa-kev", "actively-exploited", "log4shell", "ransomware-associated"],
    is_whitelisted: false,
    first_seen: "2021-12-10T00:00:00Z",
    last_seen: new Date().toISOString(),
    sources: [
      { source_name: "cisa_kev", confidence: 100, reference_url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" }
    ],
    score_breakdown: {
      source_weight: 1.00,
      cross_source_factor: 1.0,
      decay_factor: 1.0,
      enrichment_boost: 5.0,
      final_score: 75.0,
      tier: "HIGH"
    }
  },
  {
    id: "ioc-007",
    value: "8.8.8.8",
    normalized_value: "8.8.8.8",
    type: "ipv4",
    confidence_score: 0.0,
    confidence_tier: "LOW",
    severity: "info",
    tags: ["google-dns", "infrastructure", "false-positive-test"],
    is_whitelisted: true,
    whitelist_reason: "Critical Public Infrastructure: Google Public DNS Primary",
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    sources: [
      { source_name: "community_feed", confidence: 75 }
    ],
    score_breakdown: {
      source_weight: 0.0,
      cross_source_factor: 1.0,
      decay_factor: 1.0,
      enrichment_boost: 0.0,
      final_score: 0.0,
      tier: "LOW",
      is_whitelisted: true,
      whitelist_reason: "Critical Public Infrastructure: Google Public DNS Primary"
    }
  },
  {
    id: "ioc-008",
    value: "192.168.1.1",
    normalized_value: "192.168.1.1",
    type: "ipv4",
    confidence_score: 0.0,
    confidence_tier: "LOW",
    severity: "info",
    tags: ["private-network", "rfc1918"],
    is_whitelisted: true,
    whitelist_reason: "RFC 1918 / Private IP Range: 192.168.1.1",
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    sources: [
      { source_name: "community_feed", confidence: 80 }
    ],
    score_breakdown: {
      final_score: 0.0,
      tier: "LOW",
      is_whitelisted: true,
      whitelist_reason: "RFC 1918 / Private IP Range: 192.168.1.1"
    }
  }
];

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
  initClock();
  probeApiAndLoadData();
  initSandboxDefault();
});

// Live Clock
function initClock() {
  const clockEl = document.getElementById("utc-clock");
  setInterval(() => {
    const now = new Date();
    clockEl.textContent = now.toUTCString().split(" ").slice(4, 5)[0] + " UTC";
  }, 1000);
}

// API Probe & Data Loader
async function probeApiAndLoadData() {
  const statusBadge = document.getElementById("api-status-badge");
  const label = document.getElementById("backend-label");

  try {
    const res = await fetch(`${API_BASE}/indicators?limit=100`, { signal: AbortSignal.timeout(1500) });
    if (res.ok) {
      const data = await res.json();
      currentIndicators = data;
      isLiveApi = true;
      label.textContent = "LIVE API CONNECTED";
      statusBadge.style.color = "var(--emerald-safe)";
      statusBadge.style.borderColor = "rgba(16, 185, 129, 0.4)";
    } else {
      throw new Error("API non-200");
    }
  } catch (err) {
    // Graceful fallback to standalone demo mode
    isLiveApi = false;
    currentIndicators = MOCK_DATASET;
    label.textContent = "STANDALONE SHOWCASE MODE";
    statusBadge.style.color = "var(--amber-primary)";
    statusBadge.style.borderColor = "rgba(245, 158, 11, 0.4)";
  }

  filteredIndicators = [...currentIndicators];
  updateMetrics();
  renderIndicatorsTable();
}

// Update Top Metrics
function updateMetrics() {
  const total = currentIndicators.length;
  const highThreats = currentIndicators.filter(i => i.confidence_score >= 70 && !i.is_whitelisted).length;
  const whitelisted = currentIndicators.filter(i => i.is_whitelisted).length;

  document.getElementById("stat-total-iocs").textContent = total;
  document.getElementById("stat-high-threats").textContent = highThreats;
  document.getElementById("stat-whitelisted").textContent = whitelisted;
  document.getElementById("badge-ioc-count").textContent = total;
}

// Render Indicators Table
function renderIndicatorsTable() {
  const tbody = document.getElementById("indicators-tbody");
  tbody.innerHTML = "";

  if (filteredIndicators.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No threat indicators matched the selected criteria.</td></tr>`;
    return;
  }

  filteredIndicators.forEach(ioc => {
    const tr = document.createElement("tr");
    tr.onclick = () => openModal(ioc);

    const scoreColor = ioc.is_whitelisted ? "#10b981" : (ioc.confidence_score >= 85 ? "#ef4444" : (ioc.confidence_score >= 70 ? "#f59e0b" : "#6ee7b7"));
    const tierClass = `tier-${(ioc.confidence_tier || "low").toLowerCase()}`;

    const tagsHtml = (ioc.tags || []).slice(0, 3).map(t => `<span class="tag-pill">${t}</span>`).join("");
    const sourcesHtml = (ioc.sources || []).map(s => s.source_name).join(", ");

    tr.innerHTML = `
      <td>
        <div class="font-mono" style="font-weight: 600; color: #fff;">${escapeHtml(ioc.normalized_value || ioc.value)}</div>
        <div style="font-size: 0.72rem; color: var(--text-muted);">${ioc.is_whitelisted ? 'BENIGN INFRASTRUCTURE' : 'CONFIRMED THREAT'}</div>
      </td>
      <td><span class="type-badge type-${ioc.type}">${ioc.type}</span></td>
      <td>
        <div class="score-meter">
          <span class="score-num" style="color: ${scoreColor};">${ioc.confidence_score}</span>
          <div class="score-bar-bg">
            <div class="score-bar-fill" style="width: ${ioc.confidence_score}%; background: ${scoreColor};"></div>
          </div>
        </div>
      </td>
      <td><span class="tier-badge ${tierClass}">${ioc.confidence_tier || 'LOW'}</span></td>
      <td style="color: var(--text-secondary); font-size: 0.8rem;" class="font-mono">${sourcesHtml || 'Internal'}</td>
      <td>${tagsHtml}</td>
      <td style="text-align: right;">
        <button class="nav-btn nav-btn-secondary" style="padding: 0.25rem 0.55rem; font-size: 0.75rem;">Inspect &rarr;</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Filters
function applyFilters() {
  const query = document.getElementById("filter-search").value.toLowerCase().trim();
  const typeVal = document.getElementById("filter-type").value;
  const minScore = parseFloat(document.getElementById("filter-min-score").value);

  filteredIndicators = currentIndicators.filter(ioc => {
    // Search query
    const matchQuery = !query || 
      (ioc.value && ioc.value.toLowerCase().includes(query)) ||
      (ioc.normalized_value && ioc.normalized_value.toLowerCase().includes(query)) ||
      (ioc.tags && ioc.tags.some(t => t.toLowerCase().includes(query)));

    // Type filter
    const matchType = typeVal === "all" || ioc.type.toLowerCase() === typeVal;

    // Score filter
    const matchScore = ioc.confidence_score >= minScore;

    return matchQuery && matchType && matchScore;
  });

  renderIndicatorsTable();
}

function updateScoreFilter(val) {
  document.getElementById("score-slider-val").textContent = val;
  applyFilters();
}

function resetFilters() {
  document.getElementById("filter-search").value = "";
  document.getElementById("filter-type").value = "all";
  document.getElementById("filter-min-score").value = 0;
  document.getElementById("score-slider-val").textContent = 0;
  filteredIndicators = [...currentIndicators];
  renderIndicatorsTable();
}

async function triggerFeedRefresh() {
  const btn = event.target;
  btn.textContent = "Syncing...";
  btn.disabled = true;

  if (isLiveApi) {
    try {
      await fetch(`${API_BASE}/pipeline/run?live=false`, { method: "POST" });
    } catch(e) {}
  }
  await probeApiAndLoadData();
  btn.textContent = "↻ Sync Feeds";
  btn.disabled = false;
}

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));

  const targetBtn = document.getElementById(`tab-btn-${tabId}`);
  const targetPanel = document.getElementById(`panel-${tabId}`);
  if (targetBtn && targetPanel) {
    targetBtn.classList.add("active");
    targetPanel.classList.add("active");
  }
}

// Modal Inspection
function openModal(ioc) {
  document.getElementById("modal-title").textContent = ioc.normalized_value || ioc.value;
  const typeBadge = document.getElementById("modal-type-badge");
  typeBadge.textContent = ioc.type;
  typeBadge.className = `type-badge type-${ioc.type}`;

  const tierBadge = document.getElementById("modal-tier-badge");
  tierBadge.textContent = `CONFIDENCE: ${ioc.confidence_score}/100 (${ioc.confidence_tier || 'LOW'})`;
  tierBadge.className = `tier-badge tier-${(ioc.confidence_tier || 'low').toLowerCase()}`;

  const wlBadge = document.getElementById("modal-whitelist-badge");
  if (ioc.is_whitelisted) {
    wlBadge.textContent = `WHITELISTED: ${ioc.whitelist_reason || 'BENIGN ASSET'}`;
    wlBadge.style.color = "#10b981";
  } else {
    wlBadge.textContent = "VERDICT: ACTIONABLE MALICIOUS INDICATOR";
    wlBadge.style.color = "#f59e0b";
  }

  document.getElementById("modal-first-seen").textContent = ioc.first_seen ? new Date(ioc.first_seen).toUTCString() : "N/A";
  document.getElementById("modal-last-seen").textContent = ioc.last_seen ? new Date(ioc.last_seen).toUTCString() : "N/A";

  const sourcesList = document.getElementById("modal-sources-list");
  sourcesList.innerHTML = (ioc.sources || []).map(s => `
    <div style="background: rgba(0,0,0,0.25); padding: 0.5rem 0.75rem; border-radius: 6px; margin-bottom: 0.4rem; font-size: 0.8rem; display: flex; justify-content: space-between;">
      <span style="font-weight: 600; color: #fff;" class="font-mono">${s.source_name}</span>
      <span style="color: var(--text-muted);">${s.reference_url ? `<a href="${s.reference_url}" target="_blank" style="color: var(--amber-primary);">Reference Link &rarr;</a>` : 'Confidence: ' + (s.confidence || 80)}</span>
    </div>
  `).join("") || `<div style="color: var(--text-muted); font-size: 0.8rem;">Internal pipeline submission</div>`;

  // STIX Pattern preview
  let stixPattern = `[${ioc.type}-addr:value = '${ioc.normalized_value}']`;
  if (ioc.type === "domain") stixPattern = `[domain-name:value = '${ioc.normalized_value}']`;
  if (ioc.type === "url") stixPattern = `[url:value = '${ioc.normalized_value}']`;
  if (ioc.type.includes("sha") || ioc.type.includes("md5")) stixPattern = `[file:hashes.'${ioc.type.toUpperCase()}' = '${ioc.normalized_value}']`;
  if (ioc.type === "cve") stixPattern = `[vulnerability:name = '${ioc.normalized_value}']`;

  document.getElementById("modal-stix-pattern").textContent = stixPattern;
  document.getElementById("modal-json-dump").textContent = JSON.stringify(ioc, null, 2);

  document.getElementById("detail-modal").classList.add("active");
}

function closeModal(e) {
  document.getElementById("detail-modal").classList.remove("active");
}

// Client-Side Scoring Sandbox Logic (Mirrors Python scoring_engine.py & normalizer.py)
function handleSandboxSubmit(e) {
  e.preventDefault();
  const rawInput = document.getElementById("sb-input-value").value.trim();
  const daysOld = parseFloat(document.getElementById("sb-days-old").value) || 0;
  const enrichLevel = document.getElementById("sb-enrichment-level").value;

  // 1. Refang
  let refanged = rawInput
    .replace(/hxxps?:\/\//i, m => m.toLowerCase().includes("s") ? "https://" : "http://")
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
    .replace(/\[\:\]|\(\:\)/g, ":")
    .replace(/\[\/\]/g, "/")
    .replace(/\[at\]/gi, "@")
    .trim();

  // 2. Identify Type & Whitelist
  let type = "unknown";
  let isWhitelisted = false;
  let wlReason = "";

  if (/^cve-\d{4}-\d{4,}$/i.test(refanged)) {
    type = "cve";
  } else if (/^[a-fA-F0-9]{64}$/.test(refanged)) {
    type = "sha256";
  } else if (/^[a-fA-F0-9]{32}$/.test(refanged)) {
    type = "md5";
  } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(refanged)) {
    type = "ipv4";
    // Check RFC 1918 & Public DNS
    if (refanged === "8.8.8.8" || refanged === "8.8.4.4") {
      isWhitelisted = true;
      wlReason = "Critical Infrastructure: Google Public DNS";
    } else if (refanged === "1.1.1.1" || refanged === "1.0.0.1") {
      isWhitelisted = true;
      wlReason = "Critical Infrastructure: Cloudflare DNS";
    } else if (refanged.startsWith("192.168.") || refanged.startsWith("10.") || refanged.startsWith("172.16.")) {
      isWhitelisted = true;
      wlReason = "RFC 1918 Private Subnet Address";
    }
  } else if (refanged.includes("://")) {
    type = "url";
  } else if (refanged.includes(".")) {
    type = "domain";
    if (refanged.includes("google.com") || refanged.includes("microsoft.com") || refanged.includes("github.com")) {
      isWhitelisted = true;
      wlReason = "Tranco Top 10k Domain Whitelist";
    }
  }

  // 3. Gather Feeds
  const sources = [];
  if (document.getElementById("sb-feed-cisa").checked) sources.push({ name: "cisa_kev", weight: 1.0 });
  if (document.getElementById("sb-feed-abuse").checked) sources.push({ name: "abuseipdb", weight: 0.85 });
  if (document.getElementById("sb-feed-urlhaus").checked) sources.push({ name: "urlhaus", weight: 0.85 });
  if (document.getElementById("sb-feed-otx").checked) sources.push({ name: "otx", weight: 0.75 });

  if (sources.length === 0) sources.push({ name: "community_feed", weight: 0.60 });

  // 4. Scoring Algorithm Calculation
  let breakdownLog = [];
  breakdownLog.push(`[STAGE 1: NORMALIZATION]`);
  breakdownLog.push(`  Input: ${rawInput}`);
  breakdownLog.push(`  Refanged: ${refanged}`);
  breakdownLog.push(`  Detected Type: ${type.toUpperCase()}`);
  breakdownLog.push("");

  breakdownLog.push(`[STAGE 2: WHITELIST EVALUATION]`);
  if (isWhitelisted) {
    breakdownLog.push(`  STATUS: HIT BENIGN WHITELIST`);
    breakdownLog.push(`  Reason: ${wlReason}`);
    breakdownLog.push(`  RULE TRIGGERED: Hard Score Override -> 0.0`);
    breakdownLog.push(`  Enforcement Action: Bypasses Firewall/DNS blocklists`);

    document.getElementById("sb-score-big").textContent = "0.0";
    document.getElementById("sb-score-big").style.color = "var(--emerald-safe)";
    document.getElementById("sb-score-comment").textContent = `Whitelisted (${wlReason})`;
    document.getElementById("sb-result-tier").textContent = "BENIGN / WHITELISTED";
    document.getElementById("sb-result-tier").className = "tier-badge tier-low font-mono";
    document.getElementById("sb-code-breakdown").textContent = breakdownLog.join("\n");
    return;
  }
  breakdownLog.push(`  STATUS: PASS (Clean, non-whitelisted indicator)`);
  breakdownLog.push("");

  // Base Source Weight
  const maxWeight = Math.max(...sources.map(s => s.weight));
  const basePoints = maxWeight * 70.0;
  breakdownLog.push(`[STAGE 3: SOURCE RELIABILITY WEIGHTING]`);
  breakdownLog.push(`  Highest Feed Weight: ${maxWeight.toFixed(2)} (Base scale: ${basePoints.toFixed(1)} / 70.0)`);
  breakdownLog.push(`  Reporting Feeds: ${sources.map(s => s.name).join(", ")}`);
  breakdownLog.push("");

  // Cross Confirmation Multiplier
  const crossFactors = { 1: 1.0, 2: 1.25, 3: 1.45, 4: 1.6 };
  const count = Math.min(4, sources.length);
  const crossMult = crossFactors[count] || 1.0;
  breakdownLog.push(`[STAGE 4: CROSS-SOURCE CONFIRMATION MULTIPLIER]`);
  breakdownLog.push(`  Confirmed Feeds: ${sources.length} -> Multiplier: ${crossMult.toFixed(2)}x`);
  breakdownLog.push("");

  // Time Decay
  const decay = Math.pow(0.95, daysOld);
  breakdownLog.push(`[STAGE 5: EXPONENTIAL TIME DECAY]`);
  breakdownLog.push(`  Decay Base: 0.95 ^ ${daysOld} days = ${decay.toFixed(4)}`);
  breakdownLog.push("");

  // Enrichment Boost
  let enrichBoost = 0.0;
  if (enrichLevel === "high") enrichBoost = 18.0;
  if (enrichLevel === "medium") enrichBoost = 9.0;
  breakdownLog.push(`[STAGE 6: ENRICHMENT TELEMETRY BOOST]`);
  breakdownLog.push(`  Enrichment Level: ${enrichLevel.toUpperCase()} (+${enrichBoost.toFixed(1)} pts)`);
  breakdownLog.push("");

  // Composite Score
  const rawScore = (basePoints * crossMult * decay) + enrichBoost;
  const finalScore = Math.min(100.0, Math.max(0.0, Math.round(rawScore * 10) / 10));

  let tier = "LOW";
  let tierColor = "#10b981";
  if (finalScore >= 85) { tier = "CRITICAL"; tierColor = "#ef4444"; }
  else if (finalScore >= 70) { tier = "HIGH"; tierColor = "#f59e0b"; }
  else if (finalScore >= 40) { tier = "MEDIUM"; tierColor = "#eab308"; }

  breakdownLog.push(`[FINAL COMPOSITE CALCULATION]`);
  breakdownLog.push(`  Formula: min(100, (${basePoints.toFixed(1)} * ${crossMult.toFixed(2)} * ${decay.toFixed(4)}) + ${enrichBoost.toFixed(1)})`);
  breakdownLog.push(`  Raw Score: ${rawScore.toFixed(2)}`);
  breakdownLog.push(`  FINAL CLAMPED SCORE: ${finalScore.toFixed(1)} / 100.0`);
  breakdownLog.push(`  CATEGORICAL TIER: ${tier}`);

  document.getElementById("sb-score-big").textContent = finalScore.toFixed(1);
  document.getElementById("sb-score-big").style.color = tierColor;
  document.getElementById("sb-score-comment").textContent = `Composite Risk Score: ${tier}`;
  document.getElementById("sb-result-tier").textContent = `${tier} THREAT`;
  document.getElementById("sb-result-tier").className = `tier-badge tier-${tier.toLowerCase()} font-mono`;
  document.getElementById("sb-code-breakdown").textContent = breakdownLog.join("\n");
}

function initSandboxDefault() {
  document.getElementById("sb-days-old").value = 1;
  const form = document.getElementById("sandbox-form");
  if (form) {
    const fakeEvent = { preventDefault: () => {} };
    handleSandboxSubmit(fakeEvent);
  }
}

// Export Preview & Downloads
function generateExportContent(format) {
  const highIocs = currentIndicators.filter(i => !i.is_whitelisted && i.confidence_score >= 70);

  if (format === "firewall") {
    const ips = highIocs.filter(i => i.type === "ipv4" || i.type === "ipv6").map(i => i.normalized_value);
    const dateStr = new Date().toUTCString();
    return `# =====================================================================\n# Automated Threat Intelligence Firewall Blocklist\n# Generated: ${dateStr}\n# Minimum Confidence Score Threshold: 70.0\n# Total Blocked IPs: ${ips.length}\n# Compatible with: iptables, pfSense, Palo Alto EDL, Fortinet Threat Feeds\n# =====================================================================\n` + ips.join("\n");
  }

  if (format === "stix") {
    const stixObjects = highIocs.map(i => {
      let pattern = `[${i.type}-addr:value = '${i.normalized_value}']`;
      if (i.type === "domain") pattern = `[domain-name:value = '${i.normalized_value}']`;
      if (i.type === "url") pattern = `[url:value = '${i.normalized_value}']`;
      if (i.type.includes("sha") || i.type.includes("md5")) pattern = `[file:hashes.'${i.type.toUpperCase()}' = '${i.normalized_value}']`;
      if (i.type === "cve") pattern = `[vulnerability:name = '${i.normalized_value}']`;

      return {
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--${crypto.randomUUID ? crypto.randomUUID() : 'f47ac10b-58cc-4372-a567-0e02b2c3d479'}`,
        name: `Threat Indicator: ${i.normalized_value}`,
        pattern: pattern,
        pattern_type: "stix",
        confidence: Math.round(i.confidence_score),
        labels: i.tags || ["threat-indicator"],
        valid_from: new Date().toISOString()
      };
    });

    const bundle = {
      type: "bundle",
      id: `bundle--${crypto.randomUUID ? crypto.randomUUID() : 'b85dc19e-97c0-4372-a567-0e02b2c3d479'}`,
      objects: stixObjects
    };
    return JSON.stringify(bundle, null, 2);
  }

  if (format === "rpz") {
    const domains = highIocs.filter(i => i.type === "domain").map(i => i.normalized_value);
    const dateStr = new Date().toUTCString();
    let lines = [
      `; ===================================================================`,
      `; DNS Response Policy Zone (RPZ) for BIND / Pi-hole / Unbound`,
      `; Generated: ${dateStr}`,
      `; ===================================================================`,
      `$TTL 300`,
      `@ IN SOA localhost. root.localhost. ( 2026091301 3600 1800 604800 300 )`,
      `@ IN NS localhost.`,
      ``
    ];
    domains.forEach(d => {
      lines.push(`${d} CNAME .`);
      lines.push(`*.${d} CNAME .`);
    });
    return lines.join("\n");
  }

  if (format === "suricata") {
    let lines = [
      `# ===================================================================`,
      `# Suricata IDS/IPS Rules - Automated Threat Intelligence Feed`,
      `# ===================================================================`
    ];
    let sid = 1000001;
    highIocs.forEach(i => {
      if (i.type === "ipv4") {
        lines.push(`alert ip any any -> ${i.normalized_value} any (msg:"CTI-ENGINE - Outbound traffic to malicious indicator [${i.normalized_value}] (Score: ${i.confidence_score})"; classtype:trojan-activity; sid:${sid++}; rev:1;)`);
      } else if (i.type === "domain") {
        lines.push(`alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"CTI-ENGINE - Suspicious TLS SNI to [${i.normalized_value}]"; tls.sni; content:"${i.normalized_value}"; nocase; endswith; classtype:trojan-activity; sid:${sid++}; rev:1;)`);
      }
    });
    return lines.join("\n");
  }

  return "";
}

function previewExport(format) {
  const content = generateExportContent(format);
  document.getElementById("export-preview-title").textContent = `Preview: ${format.toUpperCase()} Feed`;
  document.getElementById("export-preview-content").textContent = content;
}

function downloadExport(format) {
  const content = generateExportContent(format);
  const ext = format === "stix" ? "json" : (format === "rpz" ? "zone" : (format === "suricata" ? "rules" : "txt"));
  const filename = `threat_intel_${format}.${ext}`;
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function copyExportPreview() {
  const text = document.getElementById("export-preview-content").textContent;
  navigator.clipboard.writeText(text).then(() => {
    alert("Export preview copied to clipboard!");
  });
}

function escapeHtml(str) {
  return (str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
