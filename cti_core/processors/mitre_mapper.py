"""MITRE ATT&CK Enterprise taxonomy mapping engine for threat tags and behaviors."""

from typing import Any, Dict, List, Set

TAG_TO_ATTACK: Dict[str, Dict[str, str]] = {
    "c2": {"tactic": "TA0011 - Command and Control", "technique_id": "T1071", "technique": "Application Layer Protocol"},
    "cobalt-strike": {"tactic": "TA0011 - Command and Control", "technique_id": "T1071.001", "technique": "Web Protocols"},
    "brute-force": {"tactic": "TA0006 - Credential Access", "technique_id": "T1110", "technique": "Brute Force"},
    "ssh-scan": {"tactic": "TA0007 - Discovery", "technique_id": "T1046", "technique": "Network Service Discovery"},
    "phishing": {"tactic": "TA0001 - Initial Access", "technique_id": "T1566", "technique": "Phishing"},
    "credential-harvesting": {"tactic": "TA0006 - Credential Access", "technique_id": "T1056", "technique": "Input Capture"},
    "stealer": {"tactic": "TA0009 - Collection", "technique_id": "T1005", "technique": "Data from Local System"},
    "ransomware": {"tactic": "TA0040 - Impact", "technique_id": "T1486", "technique": "Data Encrypted for Impact"},
    "botnet": {"tactic": "TA0011 - Command and Control", "technique_id": "T1584.005", "technique": "Compromise Infrastructure: Botnet"},
    "tor-exit": {"tactic": "TA0011 - Command and Control", "technique_id": "T1090.003", "technique": "Proxy: Multi-hop Proxy"},
    "exploit": {"tactic": "TA0001 - Initial Access", "technique_id": "T1190", "technique": "Exploit Public-Facing Application"},
    "log4shell": {"tactic": "TA0001 - Initial Access", "technique_id": "T1190", "technique": "Exploit Public-Facing Application"},
}


class MitreMapper:
    """Maps IoC tags and threat categories to MITRE ATT&CK Enterprise Tactics and Techniques."""

    @staticmethod
    def map_tags(tags: List[str]) -> List[Dict[str, str]]:
        """Map a list of raw indicator tags to recognized MITRE ATT&CK techniques."""
        mappings: List[Dict[str, str]] = []
        seen_techniques: Set[str] = set()

        for tag in tags:
            tag_clean = tag.lower().strip()
            if tag_clean in TAG_TO_ATTACK:
                item = TAG_TO_ATTACK[tag_clean]
                tech_id = item["technique_id"]
                if tech_id not in seen_techniques:
                    seen_techniques.add(tech_id)
                    mappings.append({
                        "tag": tag_clean,
                        "tactic": item["tactic"],
                        "technique_id": tech_id,
                        "technique": item["technique"],
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                    })

        return mappings

    @staticmethod
    def enrich_indicator(indicator: Dict[str, Any]) -> Dict[str, Any]:
        """Attach MITRE ATT&CK mapping metadata to an indicator dictionary."""
        tags = indicator.get("tags") or []
        mitre_data = MitreMapper.map_tags(tags)
        indicator_copy = dict(indicator)
        indicator_copy["mitre_attack"] = mitre_data
        return indicator_copy
