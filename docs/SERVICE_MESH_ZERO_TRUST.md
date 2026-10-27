# Service Mesh & Zero Trust Architecture Enforcement Guide

The **SENTINEL CTI Engine** provides cloud-native zero trust and service mesh enforcement exporters, allowing automated synchronization of verified threat intelligence directly into modern distributed infrastructure.

---

## 1. Istio Service Mesh (`AuthorizationPolicy`)

Istio provides zero-trust mTLS and ingress/egress policy enforcement across Kubernetes workloads.

- **Endpoint**: `/api/v1/export/istio-policy.yaml?min_score=75`
- **Resource**: `security.istio.io/v1beta1:AuthorizationPolicy`
- **Action**: `DENY`
- **Application**:
  ```bash
  curl -s http://cti-engine:8000/api/v1/export/istio-policy.yaml | kubectl apply -f -
  ```

### Example Manifest:
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: sentinel-block-threat-actors
  namespace: istio-system
spec:
  action: DENY
  rules:
  - from:
    - source:
        ipBlocks:
        - "185.220.101.5/32"
        - "45.154.255.88/32"
```

---

## 2. Cilium eBPF Network Security (`CiliumNetworkPolicy`)

Cilium provides eBPF-powered line-rate L3/L4/L7 packet filtering without iptables connection-tracking overhead.

- **Endpoint**: `/api/v1/export/cilium-policy.yaml?min_score=75`
- **Resource**: `cilium.io/v2:CiliumNetworkPolicy`
- **Action**: `egressDeny` to CIDR and FQDN targets
- **Application**:
  ```bash
  curl -s http://cti-engine:8000/api/v1/export/cilium-policy.yaml | kubectl apply -f -
  ```

---

## 3. Okta Identity Cloud Network Zones

Okta Network Zones allow identity teams to dynamically quarantine malicious IP addresses and force authentication denial or MFA step-up.

- **Endpoint**: `/api/v1/export/okta-zone.json?min_score=75`
- **Format**: Okta Network Zone REST API schema (`type: IP`, `gateways: [{"type": "CIDR", "value": "..."}]`)
- **Integration**: Push directly to Okta Admin API:
  ```bash
  curl -X POST "https://{yourOktaDomain}/api/v1/zones" \
    -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
    -H "Content-Type: application/json" \
    -d @<(curl -s http://cti-engine:8000/api/v1/export/okta-zone.json)
  ```

---

## 4. Tailscale Tailnet ACL Policies

Tailscale ACLs enforce drop rules at the WireGuard kernel layer across peer-to-peer enterprise overlays.

- **Exporter**: `TailscaleACLExporter`
- **Action**: `"action": "drop"` targeting `"dst": ["185.220.101.5/32:*", ...]`

---

## 5. Cloudflare Zero Trust Gateway

Synchronizes malicious indicators into Cloudflare Zero Trust Gateway lists via the Cloudflare v4 API for DNS and HTTP proxy egress filtering.

- **Exporter**: `CloudflareZeroTrustExporter`
- **Format**: Cloudflare Gateway List Items JSON array (`{"value": "185.220.101.5", "comment": "SENTINEL-CTI: Abuse.ch"}`)

---

## 6. Envoy Proxy RBAC Network Filter

Injects RBAC denial rules into Envoy front-proxy and service-proxy configurations to terminate TCP connections from threat IPs at the edge.

- **Exporter**: `EnvoyProxyExporter`
- **Filter**: `envoy.filters.network.rbac` with action `DENY`
