"""Dangling DNS CNAME and cloud provider subdomain takeover vulnerability processor."""

from typing import Dict, Optional, Tuple


class SubdomainTakeoverProcessor:
    """Evaluates DNS CNAME records against known cloud provider abandonment signatures (S3, GitHub, Heroku, Azure)."""

    VULNERABLE_PROVIDERS: Dict[str, Tuple[str, str]] = {
        "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
        "s3.amazonaws.com": ("AWS S3 Bucket", "The specified bucket does not exist"),
        "herokuapp.com": ("Heroku App", "No such app"),
        "azurewebsites.net": ("Azure App Service", "404 Web Site not found"),
        "ghost.io": ("Ghost Blog", "The thing you were looking for is no longer here"),
        "trafficmanager.net": ("Azure Traffic Manager", "Not Found"),
    }

    @classmethod
    def evaluate(
        cls,
        cname_target: Optional[str],
        http_response_body: Optional[str] = None,
    ) -> Tuple[bool, float, str]:
        """Evaluates whether a CNAME points to an unclaimed cloud resource.

        Returns:
            Tuple[bool, float, str]: (is_takeover_vulnerable, risk_penalty, description)
        """
        if not cname_target:
            return False, 0.0, "missing_cname_target"

        target_clean = cname_target.strip().lower().rstrip(".")

        matched_provider = None
        expected_sig = None
        for suffix, (provider, sig) in cls.VULNERABLE_PROVIDERS.items():
            if target_clean.endswith(suffix):
                matched_provider = provider
                expected_sig = sig
                break

        if not matched_provider:
            return False, 0.0, "cname_not_vulnerable_service"

        if http_response_body and expected_sig and expected_sig.lower() in http_response_body.lower():
            return True, 35.0, f"verified_subdomain_takeover: dangling CNAME {target_clean} ({matched_provider})"

        # Dangling CNAME to provider without active confirmation
        return True, 20.0, f"potential_subdomain_takeover_cname_risk: points to {matched_provider}"
