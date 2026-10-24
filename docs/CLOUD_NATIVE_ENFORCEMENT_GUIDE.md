# Cloud-Native & Next-Gen Firewall Enforcement Guide (v3.0.0)

This guide documents the automated ingestion architectures for Kubernetes cloud-native microservices and enterprise perimeter firewalls using SENTINEL-CTI enforcement outputs.

---

## 1. Kubernetes Egress Denial (NetworkPolicy)

### Ingestion Flow
1. Fetch latest YAML policy:
   ```bash
   curl -s "https://cti.company.internal/api/v1/export/k8s-policy.yaml?namespace=production&min_score=80" -o /tmp/sentinel-policy.yaml
   ```
2. Apply declaratively via `kubectl`:
   ```bash
   kubectl apply -f /tmp/sentinel-policy.yaml
   ```

### Architecture
The generated policy applies an `egress.to.ipBlock` with `except:` CIDRs corresponding to active high-confidence threat infrastructure. Workload pods retain normal internet connectivity while automated hardware C2 callbacks are rejected at the CNI plugin tier (Calico, Cilium).

---

## 2. Cisco Firepower Management Center (FMC)

### REST API Synchronization
Cisco FMC supports bulk creation of Host and FQDN Network Objects via `/api/fmc_config/v1/domain/{domainUUID}/object/networkobjects`.

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-auth-access-token: ${FMC_TOKEN}" \
  -d @<(curl -s "https://cti.company.internal/api/v1/export/cisco-firepower.json?min_score=85") \
  "https://fmc.company.internal/api/fmc_config/v1/domain/default/object/networkobjects"
```

Once loaded, network objects can be assigned to Access Control Policy (ACP) block rules.

---

## 3. Juniper Junos SRX Security Zones

### CLI Script Ingestion
Automated cron execution on Junos SRX devices:
```bash
ssh admin@srx-cluster "cat << 'EOF' | cli\nconfigure\n$(curl -s "https://cti.company.internal/api/v1/export/juniper-srx.set?zone_name=untrust")\ncommit\nexit\nEOF"
```

This dynamically populates the `address-set SENTINEL_BLOCK_SET` in the untrusted perimeter security zone without disrupting active connections.
