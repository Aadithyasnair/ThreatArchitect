"""
app.ai.mitre.mapper — Local offline database mapper for MITRE ATT&CK techniques.
"""

from __future__ import annotations

import urllib.request
from typing import Dict, Any, Optional

class MitreTechnique:
    """Dataclass holding MITRE ATT&CK technique details."""
    
    def __init__(self, id_str: str, name: str, tactic: str, description: str) -> None:
        self.id = id_str
        self.name = name
        self.tactic = tactic
        self.description = description

    def get_url(self) -> str:
        """Returns the official MITRE link for this technique."""
        # Replace sub-techniques like T1557.002 with T1557/002 in URL paths
        url_id = self.id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{url_id}"


class MitreMapper:
    """Offline MITRE mapping catalog requiring no internet connection for standard lookups."""

    # Static technique catalog
    CATALOG: Dict[str, MitreTechnique] = {
        "Port Scan": MitreTechnique(
            id_str="T1046",
            name="Network Service Scanning",
            tactic="Discovery",
            description="Adversaries may attempt to get a listing of services running on remote hosts."
        ),
        "SYN Flood": MitreTechnique(
            id_str="T1498.001",
            name="Network Denial of Service: Reflection/Amplification",
            tactic="Impact",
            description="Adversaries may perform Network DoS attacks using connection-oriented protocols (TCP SYN)."
        ),
        "ICMP Flood": MitreTechnique(
            id_str="T1498",
            name="Network Denial of Service",
            tactic="Impact",
            description="Adversaries may flood network links with ICMP Echo Requests to exhaust host resources."
        ),
        "ARP Spoof": MitreTechnique(
            id_str="T1557.002",
            name="Adversary-in-the-Middle: ARP Cache Poisoning",
            tactic="Credential Access / Collection",
            description="Adversaries may poison ARP caches to redirect traffic and intercept network communications."
        ),
        "DHCP Starvation": MitreTechnique(
            id_str="T1498.001",
            name="Network Denial of Service: Resource Exhaustion",
            tactic="Impact",
            description="Adversaries may exhaust DHCP addresses pools to prevent authentic devices from joining networks."
        ),
        "SSH Brute Force": MitreTechnique(
            id_str="T1110.001",
            name="Brute Force: Password Guessing",
            tactic="Credential Access",
            description="Adversaries may attempt to brute-force authentication services like SSH to gain initial access."
        ),
        "Reconnaissance": MitreTechnique(
            id_str="T1595",
            name="Active Scanning",
            tactic="Reconnaissance",
            description="Adversaries scan host subnets to gather details on host active ranges and OS variations."
        ),
        "Malware Beacon": MitreTechnique(
            id_str="T1071.001",
            name="Application Layer Protocol: Web Protocols",
            tactic="Command and Control",
            description="Adversaries communicate using standard web protocols (HTTP/HTTPS) to bypass port blocks."
        ),
    }

    @staticmethod
    def map_attack(attack_name: str) -> Optional[MitreTechnique]:
        """Looks up the local catalog for the given attack classification class name."""
        clean_name = str(attack_name).strip()
        # Direct match
        if clean_name in MitreMapper.CATALOG:
            return MitreMapper.CATALOG[clean_name]
            
        # Case insensitive substring search
        for key, tech in MitreMapper.CATALOG.items():
            if clean_name.lower() in key.lower() or key.lower() in clean_name.lower():
                return tech
        return None

    @staticmethod
    def is_internet_available() -> bool:
        """Passive check verifying if official MITRE hyperlinks are reachable."""
        try:
            # Short 1.0 second timeout to avoid blocking threads
            urllib.request.urlopen("https://attack.mitre.org", timeout=1.0)
            return True
        except Exception:
            return False
