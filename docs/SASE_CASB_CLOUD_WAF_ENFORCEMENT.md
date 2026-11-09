# SASE, CASB & Cloud WAF Enforcement Architecture Guide

The **SENTINEL CTI Engine v4.0.0** extends automated enforcement to Secure Access Service Edge (SASE), Cloud Access Security Brokers (CASB), Cloud WAFs, and Kubernetes CNI policy layers.

---

## 1. Netskope CASB & Secure Web Gateway (`NetskopeCASBExporter`)

Synchronizes high-confidence threat domains, URLs, and IPs into Netskope REST API v2 Custom URL Lists.

- **Endpoint**: `/api/v1/export/netskope-casb.json?min_score=75`
- **Format**: Netskope v2 URL List JSON (`{"name": "Sentinel-CTI-Block-List", "data": {"urls": [...], "type": "exact"}}`)
- **Integration**:
  ```bash
  curl -X POST "https://{tenant}.goskope.com/api/v2/policy/urllist" \
    -H "Netskope-Api-Token: ${NETSKOPE_TOKEN}" \
    -H "Content-Type: application/json" \
    -d @<(curl -s http://cti-engine:8000/api/v1/export/netskope-casb.json)
  ```

---

## 2. Zscaler Internet Access (ZIA) Custom URL Categories (`ZscalerZIAExporter`)

Automates custom URL category and IP range updates for Zscaler SWG inline inspection.

- **Endpoint**: `/api/v1/export/zscaler-zia.json?min_score=75`
- **Category Type**: `USER_DEFINED` (`customCategory: true`)
- **Fields**: Populates both `urls` and `ipRanges` arrays.

---

## 3. Google Cloud Armor Edge WAF (`GoogleCloudArmorExporter`)

Generates Google Cloud Armor SecurityPolicy rules using `SRC_IPS_V1` expressions, automatically chunking IP CIDR blocks into 10-CIDR rule groups per GCP limits.

- **Endpoint**: `/api/v1/export/cloud-armor.json?min_score=75`
- **Action**: `deny(403)`
- **Expression**: `versionedExpr: SRC_IPS_V1`

---

## 4. AWS WAFv2 Regional & CloudFront IPSets (`AWSWAFv2Exporter`)

Exports IPv4 `/32` and IPv6 `/128` threat indicators into AWS WAFv2 `CreateIPSet` / `UpdateIPSet` payloads for Application Load Balancers (ALB), API Gateway, and Amazon CloudFront.

---

## 5. Project Calico Kubernetes GlobalNetworkPolicy (`CalicoPolicyExporter`)

Enforces cluster-wide zero-trust ingress and egress denial across all Kubernetes nodes and pods using Calico v3 `GlobalNetworkPolicy`.

- **Endpoint**: `/api/v1/export/calico-policy.yaml?min_score=75`
- **Resource**: `projectcalico.org/v3:GlobalNetworkPolicy`
- **Application**:
  ```bash
  curl -s http://cti-engine:8000/api/v1/export/calico-policy.yaml | kubectl apply -f -
  ```

---

## 6. Kong API Gateway & Datadog Cloud SIEM

- **Kong API Gateway (`KongGatewayExporter`)**: Generates `ip-restriction` plugin configurations blocking malicious IPs at the API gateway edge.
- **Datadog Cloud SIEM (`DatadogSIEMExporter`)**: Exports structured Reference Tables (`sentinel_cti_threat_indicators`) for real-time log enrichment and correlation rules.
