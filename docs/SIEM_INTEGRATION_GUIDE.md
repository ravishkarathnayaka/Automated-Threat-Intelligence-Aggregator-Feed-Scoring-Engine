# Enterprise SIEM & SOAR Integration Guide

This guide details automated ingestion pipelines connecting SENTINEL CTI Engine with enterprise Security Information and Event Management (SIEM), Security Orchestration, Automation, and Response (SOAR), and Next-Generation Firewalls (NGFW).

---

## 1. Elasticsearch & OpenSearch (ECS Bulk NDJSON)

Stream scored threat indicators directly into your Elastic Common Schema (ECS) indices.

### Ingestion Endpoint
`GET /api/v1/export/elastic.ndjson?min_score=70&index_name=threat-intel-indicators`

### Automated Ingestion via Cron
```bash
curl -s "http://cti-engine.internal:8000/api/v1/export/elastic.ndjson?min_score=75" \
  | curl -s -X POST "http://elasticsearch.internal:9200/_bulk" \
    -H "Content-Type: application/x-ndjson" \
    --data-binary @-
```

---

## 2. Wazuh SIEM Constant Database (CDB) Lists

Wazuh uses CDB lists for O(1) in-memory key-value matching within analysis rules.

### Ingestion Endpoint
`GET /api/v1/export/wazuh.cdb?min_score=70`

### Integration Steps
1. Fetch and compile the CDB list on your Wazuh Manager:
```bash
curl -s "http://cti-engine.internal:8000/api/v1/export/wazuh.cdb?min_score=75" \
  -o /var/ossec/etc/lists/sentinel_threats
/var/ossec/bin/wazuh-makelists
```
2. Reference the list in `/var/ossec/etc/rules/local_rules.xml`:
```xml
<rule id="100500" level="12">
  <if_sid>5715</if_sid>
  <list field="srcip" lookup="address_match_key">etc/lists/sentinel_threats</list>
  <description>SSH authentication attempt from confirmed CTI high-risk IP</description>
  <group>authentication_failed,pci_dss_10.2.4,</group>
</rule>
```

---

## 3. AWS Network Firewall (Rule Group JSON)

Automatically populate stateful DROP rule groups in AWS VPCs.

### Ingestion Endpoint
`GET /api/v1/export/aws-firewall.json?min_score=80`

### Deployment via AWS CLI
```bash
curl -s "http://cti-engine.internal:8000/api/v1/export/aws-firewall.json?min_score=80" \
  -o rule-group.json

aws network-firewall update-rule-group \
  --rule-group-name Sentinel-CTI-Blocklist \
  --type STATEFUL \
  --rule-group file://rule-group.json
```

---

## 4. Azure Firewall (IP Groups ARM Template)

Export declarative ARM / Bicep configurations defining threat IP Groups.

### Ingestion Endpoint
Export via Python SDK or CLI:
```bash
python -c "from cti_core.exporters import AzureFirewallExporter; print(AzureFirewallExporter.export_json(indicators))"
```

---

## 5. Sigma Generic Detection Rules

Vendor-neutral detection logic compatible with Splunk, Elastic, QRadar, and Microsoft Sentinel.

### Ingestion Endpoint
`GET /api/v1/export/sigma.yml?min_score=80`

### Convert to Target SIEM via pySigma
```bash
curl -s "http://cti-engine.internal:8000/api/v1/export/sigma.yml" -o sentinel_threats.yml
sigma convert -t splunk -p sysmon sentinel_threats.yml -o splunk_alert.spl
```

---

## 6. SentinelOne Deep Visibility (S1QL)

Query real-time EDR endpoint process and network telemetry for active compromises.

### Ingestion Endpoint
`GET /api/v1/export/sentinelone.s1ql?min_score=75`

### Query Execution
Paste the generated query into SentinelOne Management Console -> Visibility -> Query:
```text
(DstIP in ("185.220.101.5", "198.51.100.22")) or (DNSRequest in ("evil-domain.com"))
```

---

## 7. Microsoft Sentinel & Defender (KQL)

Hunt across `DeviceNetworkEvents` and `CommonSecurityLog` in Azure Log Analytics.

### Ingestion Endpoint
`GET /api/v1/export/kql.txt?min_score=75`

---

## 8. Cisco Umbrella (OpenDNS) Sinkhole Sync

Synchronize malicious domains with Cisco Umbrella Destination Lists for automated perimeter sinkholing.

### Automated Sync Script
```bash
curl -s "http://cti-engine.internal:8000/api/v1/export/opendns.csv" \
  -H "Authorization: Bearer $UMBRELLA_API_KEY"
```
