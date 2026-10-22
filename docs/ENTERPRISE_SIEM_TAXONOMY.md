# Enterprise SIEM & SOAR Enforcement Taxonomy Matrix (v2.5.0)

This matrix documents the integration specifications, API endpoints, MIME types, and automated deployment commands for SENTINEL-CTI enforcement outputs across modern enterprise security infrastructure.

---

## 1. Enterprise Integration Matrix

| Platform | Format / Standard | API Endpoint | Content-Type | Default Delivery File |
| :--- | :--- | :--- | :--- | :--- |
| **Splunk ES** | Threat Intel Lookup CSV | `/api/v1/export/splunk.csv` | `text/csv` | `splunk_threat_intel.csv` |
| **Tanium Threat Response** | Threat IOC Package JSON | `/api/v1/export/tanium.json` | `application/json` | `Sentinel-Threat-Package.json` |
| **Palo Alto Networks** | External Dynamic List (EDL) | `/api/v1/export/palo-alto-edl.txt` | `text/plain` | `pan_os_edl.txt` |
| **Snort 3 IPS** | Modern Snort 3 IPS Ruleset | `/api/v1/export/snort3.rules` | `text/plain` | `snort3_sentinel.rules` |
| **VyOS / EdgeRouter** | Address-Group Configuration | `/api/v1/export/vyos.sh` | `text/plain` | `sentinel_drop_group.sh` |
| **Zeek Network Security** | Bro Notice Policy Script | Exporter Module | `text/plain` | `sentinel_notices.zeek` |
| **CrowdStrike FDR** | AWS Athena SQL Partition Query | Exporter Module | `application/sql` | `athena_threat_hunt.sql` |
| **MISP Project** | Event Manifest & Warninglist | Exporter Module | `application/json` | `manifest.json` |

---

## 2. Platform Ingestion Details

### 2.1 Splunk Enterprise Security (ES)
- **Mechanism**: Threat Intelligence Framework input lookup table.
- **Lookup Definition**: `sentinel_threat_lookup`
- **Fields Provided**: `threat_key`, `indicator`, `type`, `confidence`, `threat_category`, `weight`, `description`
- **Curl Ingestion**:
  ```bash
  curl -s "https://cti.company.internal/api/v1/export/splunk.csv?min_score=75" -o /opt/splunk/etc/apps/DA-ESS-ThreatIntelligence/lookups/sentinel_intel.csv
  ```

### 2.2 Tanium Threat Response
- **Mechanism**: Automated IOC package sensor targeting endpoint telemetry.
- **Schema**: OpenIOC 2.0 JSON format with structured indicator criteria (IPAddress, URL, Hash, FilePath).
- **Severity Mapping**:
  - Score $\ge 85$: `Critical`
  - Score $\ge 70$: `High`
  - Score $\ge 40$: `Medium`

### 2.3 Palo Alto Networks PAN-OS (EDL)
- **Mechanism**: Dynamic external address / domain list auto-refreshed via cron or management polling.
- **Supported Categories**: `ip` (IPv4 & IPv6), `domain` (FQDNs), `url`.
- **Curl Verification**:
  ```bash
  curl -s "https://cti.company.internal/api/v1/export/palo-alto-edl.txt?category=ip&min_score=80"
  ```

### 2.4 Snort 3 Modern IPS
- **Mechanism**: Snort 3 Lua ruleset utilizing modern action keywords (`reject`, `drop`, `alert`) with custom metadata tags.
- **Example Rule**:
  ```snort
  reject tcp $HOME_NET any -> 185.220.101.5 any (msg:"SENTINEL-CTI High Confidence C2 Connection"; sid:4000001; rev:1; classtype:trojan-activity; metadata:engine sentinel_cti, confidence 88.5;)
  ```

### 2.5 VyOS / EdgeRouter CLI
- **Mechanism**: Executable configuration shell script adding addresses to `SENTINEL_DROP_GROUP`.
- **Ingestion**:
  ```bash
  curl -s "https://cti.company.internal/api/v1/export/vyos.sh?group_name=BLACKHOLE_GROUP" | sudo vbash
  ```

---

## 3. Automation & Ingestion Best Practices
1. **Polling Frequency**: We recommend polling dynamic blocklists every 5 to 15 minutes for perimeter firewalls, and hourly for SIEM lookup tables.
2. **Confidence Thresholding**:
   - Production Inline Drops / Rejections: `min_score >= 85.0`
   - Perimeter Logging & Alerting: `min_score >= 70.0`
   - Retrospective Threat Hunting (Athena / Splunk): `min_score >= 50.0`
3. **Fail-Open Safeguard**: Ensure upstream firewalls maintain cached copies if downstream connectivity to the CTI engine is interrupted.
