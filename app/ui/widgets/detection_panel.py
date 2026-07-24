"""
app.ui.widgets.detection_panel — Rebuilt collapsible side panel with QTabWidget.

Hosts Detections/Timeline/OSI, AI Playbook, Compliance/MITRE, and Firewall controls.
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTabWidget, QTextBrowser, QFrame
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from app.ui.widgets.anomaly_graph import AnomalyGraph
from app.ui.widgets.timeline_widget import TimelineWidget
from app.ui.widgets.osi_visualizer import OSIVisualizer
from app.ui.widgets.remediation_widget import RemediationWidget

from app.network.threat_engine import ThreatModel
from app.ai.ollama.response_parser import RemediationReport

logger = logging.getLogger("DetectionPanel")


class DetectionPanel(QWidget):
    """
    Main Security Console container. Houses tab views for Phase 4 metrics.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self) -> None:
        self.setObjectName("DetectionPanel")
        self.setStyleSheet("background-color: #050B14; border-left: 1px solid #1E2D45;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(0)

        # Tab Widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::panel {
                border-top: 1px solid #1E2D45;
                background-color: #050B14;
            }
            QTabBar::tab {
                background: #090F1C;
                color: #A9B2C3;
                font-family: Consolas;
                font-size: 7.5pt;
                font-weight: bold;
                padding: 6px 10px;
                border-top: 1px solid #1E2D45;
                border-right: 1px solid #1E2D45;
            }
            QTabBar::tab:selected {
                background: #050B14;
                color: #00D2FF;
                border-bottom: 2px solid #00D2FF;
            }
            QTabBar::tab:hover {
                background: #111B30;
                color: #F8FAFC;
            }
        """)

        # ── Tab 1: Detections (Graph + Timeline + OSI Stack) ──────────────────
        tab_det = QWidget()
        det_layout = QVBoxLayout(tab_det)
        det_layout.setContentsMargins(6, 6, 6, 6)
        det_layout.setSpacing(8)

        self.graph = AnomalyGraph(threshold=0.65)
        self.graph.setFixedHeight(120)
        det_layout.addWidget(self.graph)

        self.timeline = TimelineWidget()
        self.timeline.setMinimumHeight(140)
        det_layout.addWidget(self.timeline, 1)

        self.osi = OSIVisualizer()
        self.osi.setFixedHeight(190)
        det_layout.addWidget(self.osi)

        self.tabs.addTab(tab_det, "DETECTIONS")

        # ── Tab 2: AI Remediation Playbook ───────────────────────────────────
        self.remediation = RemediationWidget()
        self.tabs.addTab(self.remediation, "AI PLAYBOOK")

        # ── Tab 3: Compliance & MITRE ────────────────────────────────────────
        tab_comp = QWidget()
        comp_layout = QVBoxLayout(tab_comp)
        comp_layout.setContentsMargins(6, 6, 6, 6)
        comp_layout.setSpacing(6)

        self.comp_browser = QTextBrowser()
        self.comp_browser.setFrameStyle(QFrame.NoFrame)
        self.comp_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #050B14;
                color: #A9B2C3;
                font-family: Consolas, monospace;
                font-size: 8pt;
                border: 1px solid #1E2D45;
                border-radius: 4px;
                padding: 6px;
            }
        """)
        comp_layout.addWidget(self.comp_browser)
        self.tabs.addTab(tab_comp, "AUDIT & MITRE")

        # ── Tab 4: Firewall Center ───────────────────────────────────────────
        tab_fw = QWidget()
        fw_layout = QVBoxLayout(tab_fw)
        fw_layout.setContentsMargins(6, 6, 6, 6)
        fw_layout.setSpacing(6)

        self.fw_browser = QTextBrowser()
        self.fw_browser.setFrameStyle(QFrame.NoFrame)
        self.fw_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #050B14;
                color: #A9B2C3;
                font-family: Consolas, monospace;
                font-size: 8pt;
                border: 1px solid #1E2D45;
                border-radius: 4px;
                padding: 6px;
            }
        """)
        fw_layout.addWidget(self.fw_browser)
        self.tabs.addTab(tab_fw, "FIREWALL")

        layout.addWidget(self.tabs)
        self.clear()

    def update_threat_model(self, model: ThreatModel) -> None:
        """Forward details to graph and OSI visualizer."""
        self.graph.add_score(model.anomaly_score)

        # Highlight OSI layers based on classification
        layer = "Physical"
        explanation = "No anomaly detected."
        level = model.threat_level

        cat = model.attack_category
        if cat == "SYN Flood":
            layer = "Transport"
            explanation = "TCP SYN Flood detected. Anomalous high-rate TCP connection requests targeting port 80."
        elif cat == "Port Scan":
            layer = "Transport"
            explanation = "Network Service Scanning detected. Sequential TCP probes mapping open target host ports."
        elif cat == "ICMP Flood":
            layer = "Network"
            explanation = "Network Denial of Service. Volumetric ICMP ping packets flooding network interfaces."
        elif cat == "ARP Spoof":
            layer = "Data Link"
            explanation = "ARP Cache Poisoning MitM attempt detected. Host spoofing L2 physical MAC addresses."
        elif cat == "DHCP Starvation":
            layer = "Application"
            explanation = "DHCP Pool Resource Exhaustion detected. Requesting address spaces with random client MACs."
        elif cat == "SSH Brute Force":
            layer = "Application"
            explanation = "Credential Access exploit. Persistent SSH login guesses detected on target port 22."
        elif cat == "Reconnaissance":
            layer = "Application"
            explanation = "Active scan discovery probes mapping DNS and local segments."
        elif cat == "Malware Beacon":
            layer = "Application"
            explanation = "Command and Control beaconing. Internal host communicating with external server controllers."

        if cat != "Normal":
            self.osi.highlight_layer(layer, explanation, level)
        else:
            self.osi.reset_stack()

        # Update Tab 3 MITRE details
        self.render_mitre_and_compliance(model)

    def update_remediation(self, report: RemediationReport) -> None:
        self.remediation.update_remediation(report)

    def update_remediation_token(self, token: str) -> None:
        self.remediation.append_token(token)

    def update_remediation_status(self, status: str) -> None:
        self.remediation.update_status(status)

    def update_timeline(self, events: list[dict]) -> None:
        self.timeline.update_events(events)

    def update_compliance(self, results: dict) -> None:
        """Stores compliance checks results and forces rerender of Tab 3."""
        self._last_compliance_results = results
        # We also trigger a redraw from our current threat model context
        # to ensure it correlates with MITRE technique lookups
        self.render_mitre_and_compliance()

    def update_firewall_stats(self, stats: dict) -> None:
        """Render live firewall status and rule list tables in Tab 4."""
        fw_stats = stats.get("firewall", {})
        allowed = fw_stats.get("packets_allowed", 0)
        blocked = fw_stats.get("packets_blocked", 0)
        total = allowed + blocked
        rate = fw_stats.get("block_rate_pct", 0)

        html = f"""
        <div style="font-family: Consolas, monospace; font-size: 8pt;">
            <div style="color: #00D2FF; font-weight: bold; margin-bottom: 6px;">FIREWALL CONTROLS CENTER</div>
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 8px;">
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">GATEWAY FILTER:</td>
                    <td style="color:#22C55E; font-weight:bold; text-align:right;">ACTIVE / MONITORING</td>
                </tr>
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">PACKETS ALLOWED:</td>
                    <td style="color:#E2E8F0; text-align:right;">{allowed}</td>
                </tr>
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">PACKETS BLOCKED:</td>
                    <td style="color:#EF4444; font-weight:bold; text-align:right;">{blocked}</td>
                </tr>
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">BLOCK RATE:</td>
                    <td style="color:#FACC15; font-weight:bold; text-align:right;">{rate}%</td>
                </tr>
            </table>

            <hr style="border: 0; border-top: 1px solid #1E2D45; margin: 6px 0;">

            <div style="color: #E2E8F0; font-weight: bold; margin-bottom: 4px;">ACTIVE SECURITY RULES:</div>
        """

        # Format rules text
        rules_str = stats.get("firewall_rules_table", "No custom rules defined.")
        html += f"<pre style='color:#A9B2C3; font-size: 7.5pt; margin: 0;'>{rules_str}</pre>"

        html += "</div>"
        self.fw_browser.setHtml(html)

    def render_mitre_and_compliance(self, model: Optional[ThreatModel] = None) -> None:
        """Generates dynamic HTML detailing compliance and MITRE attack metrics."""
        m = model or getattr(self, "_last_model", None)
        if m:
            self._last_model = m

        cat = m.attack_category if m else "Normal"

        # MITRE Mapping lookup
        from app.ai.mitre.mapper import MitreMapper
        tech = MitreMapper.map_attack(cat)

        html = '<div style="font-family: Consolas, monospace; font-size: 8pt;">'
        
        # 1. MITRE Section
        html += '<div style="color: #00D2FF; font-weight: bold; margin-bottom: 6px;">MITRE ATT&CK MAPPING</div>'
        if tech:
            # Check online status for hyperlink mapping
            link_text = f"<a href='{tech.get_url()}' style='color:#38BDF8; text-decoration:none;'>{tech.id}</a>"
            html += f"""
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 8px;">
                <tr>
                    <td style="color:#4A6080; font-weight:bold; width:100px;">TECHNIQUE ID:</td>
                    <td style="color:#F8FAFC; text-align:left;">{link_text}</td>
                </tr>
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">NAME:</td>
                    <td style="color:#E2E8F0; text-align:left;">{tech.name}</td>
                </tr>
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">TACTIC:</td>
                    <td style="color:#F97316; font-weight:bold; text-align:left;">{tech.tactic}</td>
                </tr>
            </table>
            <div style="color: #A9B2C3; padding: 4px; background-color: #0F172A; border-radius: 3px; border: 1px solid #1E2D45; margin-bottom: 10px;">
                {tech.description}
            </div>
            """
        else:
            html += '<div style="color: #4A6080; margin-bottom: 10px;">No threat mapping active (Normal traffic baseline).</div>'

        html += '<hr style="border: 0; border-top: 1px solid #1E2D45; margin: 6px 0;">'

        # 2. Compliance Section
        html += '<div style="color: #FACC15; font-weight: bold; margin-bottom: 6px;">COMPLIANCE FRAMEWORKS AUDIT</div>'
        
        results = getattr(self, "_last_compliance_results", None)
        if results:
            for framework, res in results.items():
                color = "#22C55E" # green
                if res["status"] == "FAIL":
                    color = "#EF4444"
                elif res["status"] == "WARNING":
                    color = "#FACC15"

                html += f"""
                <div style="font-weight:bold; color:#E2E8F0; margin-top: 4px;">{framework}: <span style="color:{color};">{res["status"]}</span> (Score: {res["score"]:.0f}%)</div>
                """
                for detail in res.get("details", []):
                    d_color = "#22C55E" if detail["status"] == "PASS" else ("#EF4444" if detail["status"] == "FAIL" else "#FACC15")
                    html += f"""
                    <div style="padding-left: 6px; border-left: 2px solid {d_color}; margin-bottom: 4px; margin-top: 2px;">
                        <span style="color:#F8FAFC; font-weight:bold;">{detail["control"]}</span>: 
                        <span style="color:{d_color}; font-weight:bold;">{detail["status"]}</span><br/>
                        <span style="color:#A9B2C3;">{detail["reason"]}</span>
                    </div>
                    """
        else:
            html += '<div style="color: #4A6080;">Auditing compliance frameworks NIST, ISO, and OWASP in background...</div>'

        html += '</div>'
        self.comp_browser.setHtml(html)

    def clear(self) -> None:
        """Reset all UI widgets to idle status."""
        self.graph.clear()
        self.timeline.clear()
        self.osi.reset_stack()
        self.remediation.clear()
        self._last_compliance_results = None
        self._last_model = None
        
        # Reset Tab 3
        self.comp_browser.setHtml("""
            <div style="font-family: Consolas, monospace; font-size: 8pt; color: #4A6080; text-align: center; margin-top: 20px;">
                Framework checks idle.<br/>
                Activate standard traffic to audit NIST, ISO, and OWASP compliance controls.
            </div>
        """)

        # Reset Tab 4
        self.fw_browser.setHtml("""
            <div style="font-family: Consolas, monospace; font-size: 8pt; color: #4A6080; text-align: center; margin-top: 20px;">
                Firewall details will display here when active.
            </div>
        """)
