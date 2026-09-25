"""CIDR subnet processor, bogon IP detector, and network containment validator."""

import ipaddress
from typing import List, Optional, Tuple, Union

# Full Bogon IP ranges (RFC 5735, RFC 6598, IANA Special-Purpose Address Registry)
BOGON_V4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # Private-Use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space / CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link Local (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-Use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation / TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),     # Private-Use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation / TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation / TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for Future Use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast (RFC 919)
]

BOGON_V6_NETWORKS = [
    ipaddress.ip_network("::/128"),             # Unspecified (RFC 4291)
    ipaddress.ip_network("::1/128"),            # Loopback (RFC 4291)
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped (RFC 4291)
    ipaddress.ip_network("100::/64"),           # Discard-Only (RFC 6666)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ipaddress.ip_network("fc00::/7"),           # Unique-Local (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-Local (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast (RFC 4291)
]


class CIDRFilter:
    """Utilities for IP subnet classification, bogon detection, and CIDR containment."""

    @staticmethod
    def is_bogon(ip_str: str) -> Tuple[bool, Optional[str]]:
        """Determine if an IP address is a bogon (unroutable on public Internet)."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False, None

        if isinstance(ip_obj, ipaddress.IPv4Address):
            for net in BOGON_V4_NETWORKS:
                if ip_obj in net:
                    return True, f"IPv4 Bogon: {net}"
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            for net in BOGON_V6_NETWORKS:
                if ip_obj in net:
                    return True, f"IPv6 Bogon: {net}"

        return False, None

    @staticmethod
    def is_ip_in_subnets(
        ip_str: str,
        subnets: List[Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network]],
    ) -> Tuple[bool, Optional[str]]:
        """Check if an IP address falls within any provided CIDR subnet ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False, None

        for subnet in subnets:
            try:
                net_obj = ipaddress.ip_network(subnet, strict=False) if isinstance(subnet, str) else subnet
                if ip_obj in net_obj:
                    return True, str(net_obj)
            except ValueError:
                continue

        return False, None

    @staticmethod
    def aggregate_subnets(subnets: List[str]) -> List[str]:
        """Collapse redundant CIDR subnets into supernets (e.g. 192.168.0.0/24 + 192.168.1.0/24 -> 192.168.0.0/23)."""
        valid_nets = []
        for s in subnets:
            try:
                valid_nets.append(ipaddress.ip_network(s.strip(), strict=False))
            except ValueError:
                continue

        collapsed = ipaddress.collapse_addresses(valid_nets)
        return [str(net) for net in collapsed]
