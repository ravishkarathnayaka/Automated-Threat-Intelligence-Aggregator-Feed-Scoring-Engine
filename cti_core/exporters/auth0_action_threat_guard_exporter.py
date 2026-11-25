"""Auth0 Post-Login Action JavaScript blocklist code generator."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class Auth0ActionThreatGuardExporter:
    """Exports threat IPs into Auth0 Actions post-login JavaScript middleware blocklist."""

    @classmethod
    def export_action_javascript(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        action_name: str = "sentinel-threat-guard-action",
        min_score: float = 75.0,
    ) -> str:
        """Generates Auth0 Actions Node.js code with blocked IP Set."""
        blocked_ips: List[str] = []

        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "").lower()
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                ioc_type = item.type.value.lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
            else:
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)

            if is_whitelisted or score < min_score or not norm_val:
                continue

            if ioc_type in ("ipv4", "ipv6"):
                blocked_ips.append(norm_val)

        ip_json = json.dumps(blocked_ips or ["255.255.255.255"])

        code = f"""/**
 * Auth0 Post-Login Action: {action_name}
 * Generated automatically by SENTINEL-CTI Engine.
 * Blocks logins originating from known high-confidence threat IPs.
 */
exports.onExecutePostLogin = async (event, api) => {{
  const blockedIPs = new Set({ip_json});
  const clientIP = event.request.ip;

  if (blockedIPs.has(clientIP)) {{
    api.access.deny('Access denied: Authentication attempt from confirmed threat IP ' + clientIP);
  }}
}};
"""
        return code
