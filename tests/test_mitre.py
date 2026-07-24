"""
tests/test_mitre — Unit tests for local offline MITRE ATT&CK Mapping database.
"""

import pytest
from app.ai.mitre.mapper import MitreMapper, MitreTechnique


def test_mitre_direct_mappings() -> None:
    """Verifies that standard classified attacks map to the correct MITRE technique details."""
    tech_syn = MitreMapper.map_attack("SYN Flood")
    assert tech_syn is not None
    assert tech_syn.id == "T1498.001"
    assert tech_syn.tactic == "Impact"
    assert "TCP SYN" in tech_syn.description
    assert "https://attack.mitre.org/techniques/T1498/001" in tech_syn.get_url()

    tech_scan = MitreMapper.map_attack("Port Scan")
    assert tech_scan is not None
    assert tech_scan.id == "T1046"
    assert tech_scan.tactic == "Discovery"

    tech_arp = MitreMapper.map_attack("ARP Spoof")
    assert tech_arp is not None
    assert tech_arp.id == "T1557.002"
    assert tech_arp.tactic == "Credential Access / Collection"


def test_mitre_fuzzy_substring_mapping() -> None:
    """Verifies case-insensitive fuzzy matches map correctly."""
    tech = MitreMapper.map_attack("   syn flood attack   ")
    assert tech is not None
    assert tech.id == "T1498.001"

    tech_unknown = MitreMapper.map_attack("UnseenExploitName")
    assert tech_unknown is None
