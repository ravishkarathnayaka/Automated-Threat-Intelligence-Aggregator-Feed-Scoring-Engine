# Cloud Ingress Gateways, Global WAF & IAM Threat Enforcement (v4.5.0)

The **SENTINEL CTI Engine v4.5.0** introduces next-generation perimeter protection across Kubernetes Ingress controllers, Global Content Delivery Networks, and Identity and Access Management (IAM) authentication flows.

---

## 1. Traefik Ingress Controller Middleware (`TraefikMiddlewareExporter`)

Generates Kubernetes Custom Resource Definitions (CRD) for Traefik Ingress controllers (`traefik.io/v1alpha1`) to enforce ingress perimeter isolation.

- **Endpoint**: `/api/v1/export/traefik-middleware.yaml?min_score=75&namespace=traefik-system`
- **Resource Kind**: `Middleware` (`spec.ipWhiteList` / `spec.ipStrategy`)
- **Integration**:
  ```bash
  kubectl apply -f http://cti-engine:8000/api/v1/export/traefik-middleware.yaml
  ```

---

## 2. Azure Front Door (AFD) Global WAF (`AzureFrontDoorWAFExporter`)

Exports custom rule sets for Microsoft Azure Front Door and Azure Application Gateway WAF policies, enabling geo-distributed edge IP rate limiting and blocking.

- **Endpoint**: `/api/v1/export/azure-front-door.json?min_score=75&policy_name=SentinelFrontDoorWAFPolicy`
- **Rule Type**: `CustomRule` with `IPMatch` operator and `Block` action
- **Azure CLI Deployment**:
  ```bash
  az afd security-policy create \
    --resource-group cti-rg \
    --profile-name cti-frontdoor \
    --security-policy-name SentinelPolicy \
    --waf-policy-json @<(curl -s http://cti-engine:8000/api/v1/export/azure-front-door.json)
  ```

---

## 3. Auth0 ThreatGuard Post-Login Action (`Auth0ActionThreatGuardExporter`)

Produces production-ready Node.js scripts for Auth0 Actions to block malicious IP logins and botnet credential stuffers at the identity provider tier.

- **Endpoint**: `/api/v1/export/auth0-action.js?min_score=75`
- **Runtime**: Auth0 Actions Node 18+ Runtime
- **Denial Reason**: `api.access.deny('Access denied: High-risk threat actor detected by SENTINEL CTI')`

---

## 4. Next-Gen Commercial & Curated Intel Collectors

- **`CuratedIntelCollector`**: High-confidence curated incident response and APT indicator feeds.
- **`ThreatFoxASNCollector`**: abused.ch ThreatFox ASN infrastructure aggregation.
- **`MaltiverseIOCCollector`**: Maltiverse OSINT multi-threat reputation intelligence.
