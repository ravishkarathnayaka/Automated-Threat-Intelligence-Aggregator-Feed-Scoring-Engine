"""Port service mapper and anomalous backdoor/C2 listener classifier."""

from typing import Dict, Optional, Tuple


class PortServiceMapper:
    """Classifies destination network ports into standard services or high-risk C2/backdoor channels."""

    HIGH_RISK_PORTS: Dict[int, str] = {
        4444: "Metasploit default payload listener",
        1337: "Custom adversary backdoor listener",
        31337: "Elite backdoor / trojan port",
        5555: "Android ADB exploitation port",
        6667: "IRC botnet command channel",
        8888: "Alternative C2 HTTP proxy",
        9999: "Urgent reverse shell listener",
        4443: "Cobalt Strike alternative TLS port",
    }

    STANDARD_SERVICES: Dict[int, str] = {
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        22: "SSH",
        21: "FTP",
        25: "SMTP",
        3389: "RDP",
    }

    @classmethod
    def evaluate_port(cls, port: Optional[int]) -> Tuple[bool, str, float]:
        """Evaluate if port is anomalous or associated with offensive C2 frameworks.

        Returns:
            Tuple[bool, str, float]: (is_anomalous, service_name_or_threat, risk_penalty)
        """
        if port is None or port <= 0 or port > 65535:
            return False, "invalid_or_missing_port", 0.0

        if port in cls.HIGH_RISK_PORTS:
            return True, cls.HIGH_RISK_PORTS[port], 25.0

        if port in cls.STANDARD_SERVICES:
            return False, cls.STANDARD_SERVICES[port], 0.0

        # High ephemeral port
        if port > 49152:
            return False, "ephemeral_dynamic_port", 5.0

        return False, "unassigned_or_custom_service", 10.0
