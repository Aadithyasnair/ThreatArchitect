"""
app.utils.pdf_generator — PDF incident report exporter powered by ReportLab.

Compiles complete details of network threats, LSTM scores, Random Forest categories,
compliance checklists, MITRE mappings, incident timelines, and AI recommendations.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

class PDFIncidentReportGenerator:
    """
    Generates professional, printable cybersecurity incident reports.
    """

    @staticmethod
    def generate_report(
        output_path: str,
        incident_data: Dict[str, Any],
        timeline_events: List[Dict[str, Any]],
        compliance_results: List[Dict[str, Any]],
        mitre_info: Optional[Dict[str, Any]] = None,
        ai_remediation: Optional[Dict[str, Any]] = None,
        devices_list: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """
        Builds a comprehensive multi-page PDF report.
        """
        # Ensure directories exist
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54
        )

        styles = getSampleStyleSheet()
        
        # Define clean, modern styles
        primary_color = colors.HexColor("#0F172A")    # Faint Slate / Dark Navy
        secondary_color = colors.HexColor("#0284C7")  # Cyan / Ocean Accent
        text_color = colors.HexColor("#334155")       # Dark Gray
        border_color = colors.HexColor("#E2E8F0")     # Light Slate Gray

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=primary_color,
            spaceAfter=15
        )

        section_heading = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=secondary_color,
            spaceBefore=12,
            spaceAfter=6,
            keepWithNext=True
        )

        normal_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=text_color,
            spaceAfter=6
        )

        code_style = ParagraphStyle(
            'ReportCode',
            parent=styles['Code'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0F172A"),
            backColor=colors.HexColor("#F8FAFC"),
            borderColor=colors.HexColor("#E2E8F0"),
            borderWidth=1,
            borderPadding=6,
            spaceAfter=8
        )

        meta_label_style = ParagraphStyle(
            'MetaLabel',
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=11,
            textColor=primary_color
        )

        story = []

        # ── Header / Banner ──────────────────────────────────────────────────
        story.append(Paragraph("ThreatArchitect Security Incident Report", title_style))
        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"Generated on: {gen_time} | Status: AUDITED", normal_style))
        story.append(Spacer(1, 0.15 * inch))

        # ── Executive Summary ────────────────────────────────────────────────
        story.append(Paragraph("1. Executive Summary", section_heading))
        summary_text = (
            f"On {incident_data.get('timestamp', gen_time)}, ThreatArchitect detected a security incident "
            f"classified as <b>{incident_data.get('attack_category', 'Anomaly')}</b> targeting "
            f"<b>{incident_data.get('affected_host', 'N/A')}</b>. "
            f"The network anomaly score spiked to <b>{incident_data.get('anomaly_score', 0.0):.2f}</b>, "
            f"with a final evaluated Threat Score of <b>{incident_data.get('threat_score', 0)}/100</b> (Level: {incident_data.get('threat_level', 'INFO')})."
        )
        story.append(Paragraph(summary_text, normal_style))
        
        # If AI report exists, add threat summary paragraph
        if ai_remediation and ai_remediation.get("threat_summary"):
            story.append(Paragraph(f"<b>AI Summary:</b> {ai_remediation.get('threat_summary')}", normal_style))
        story.append(Spacer(1, 0.1 * inch))

        # ── Incident Overview Table ──────────────────────────────────────────
        story.append(Paragraph("2. Technical Details", section_heading))
        
        overview_data = [
            [Paragraph("Key Metrics", meta_label_style), Paragraph("Values", meta_label_style)],
            [Paragraph("Classifier Verdict", normal_style), Paragraph(incident_data.get('attack_category', 'N/A'), normal_style)],
            [Paragraph("Threat Score / Level", normal_style), Paragraph(f"{incident_data.get('threat_score', 0)} / {incident_data.get('threat_level', 'N/A')}", normal_style)],
            [Paragraph("Anomaly Score (LSTM)", normal_style), Paragraph(f"{incident_data.get('anomaly_score', 0.0):.4f}", normal_style)],
            [Paragraph("Classifier Confidence", normal_style), Paragraph(f"{incident_data.get('classifier_confidence', 0.0):.2%}", normal_style)],
            [Paragraph("Attacker Address", normal_style), Paragraph(incident_data.get('attacker_host', 'N/A'), normal_style)],
            [Paragraph("Affected Host Address", normal_style), Paragraph(incident_data.get('affected_host', 'N/A'), normal_style)],
            [Paragraph("Affected Port / Service", normal_style), Paragraph(incident_data.get('affected_service', 'N/A'), normal_style)],
        ]
        
        t_overview = Table(overview_data, colWidths=[2.2 * inch, 4.3 * inch])
        t_overview.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor("#F1F5F9")),
            ('TEXTCOLOR', (0, 0), (1, 0), primary_color),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, border_color),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_overview)
        story.append(Spacer(1, 0.15 * inch))

        # ── MITRE ATT&CK Mapping ──────────────────────────────────────────────
        if mitre_info:
            story.append(Paragraph("3. MITRE ATT&CK Mapping", section_heading))
            mitre_desc = (
                f"<b>Technique ID:</b> {mitre_info.get('id', 'N/A')}<br/>"
                f"<b>Technique Name:</b> {mitre_info.get('name', 'N/A')}<br/>"
                f"<b>Tactic:</b> {mitre_info.get('tactic', 'N/A')}<br/>"
                f"<b>Description:</b> {mitre_info.get('description', 'N/A')}"
            )
            story.append(Paragraph(mitre_desc, normal_style))
            story.append(Spacer(1, 0.1 * inch))

        # ── Timeline ─────────────────────────────────────────────────────────
        if timeline_events:
            story.append(Paragraph("4. Incident Timeline Events", section_heading))
            timeline_data = [
                [Paragraph("Time", meta_label_style), Paragraph("Event Type", meta_label_style), Paragraph("Description", meta_label_style)]
            ]
            for evt in timeline_events:
                timeline_data.append([
                    Paragraph(evt.get("event_time", ""), normal_style),
                    Paragraph(evt.get("event_type", "INFO"), normal_style),
                    Paragraph(evt.get("message", ""), normal_style),
                ])
            t_timeline = Table(timeline_data, colWidths=[1.2 * inch, 1.3 * inch, 4.0 * inch])
            t_timeline.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t_timeline)
            story.append(Spacer(1, 0.15 * inch))

        # ── Compliance Checklist ─────────────────────────────────────────────
        if compliance_results:
            story.append(Paragraph("5. Compliance Auditor Findings", section_heading))
            compliance_data = [
                [Paragraph("Control ID", meta_label_style), Paragraph("Framework", meta_label_style), Paragraph("Status", meta_label_style), Paragraph("Finding / Suggestion", meta_label_style)]
            ]
            for rule in compliance_results:
                status_color = "#22C55E" # green
                if rule.get("status") == "FAIL":
                    status_color = "#EF4444" # red
                elif rule.get("status") == "WARNING":
                    status_color = "#FACC15" # yellow
                
                status_p = Paragraph(f"<font color='{status_color}'><b>{rule.get('status')}</b></font>", normal_style)
                compliance_data.append([
                    Paragraph(rule.get("control", ""), normal_style),
                    Paragraph(rule.get("framework", ""), normal_style),
                    status_p,
                    Paragraph(f"<b>Reason:</b> {rule.get('reason','')}<br/><b>Fix:</b> {rule.get('improvement','')}", normal_style)
                ])
            
            t_compliance = Table(compliance_data, colWidths=[1.5 * inch, 1.0 * inch, 0.9 * inch, 3.1 * inch])
            t_compliance.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t_compliance)
            story.append(Spacer(1, 0.15 * inch))

        # ── AI Remediation Plan ──────────────────────────────────────────────
        if ai_remediation:
            story.append(Paragraph("6. AI Remediation Actions & Commands", section_heading))
            story.append(Paragraph(f"<b>Reasoning Model:</b> Llama 3.2 (Local)<br/><b>AI Risk Verdict:</b> {ai_remediation.get('risk_level', 'N/A')}", normal_style))
            
            explanation = ai_remediation.get("reasoning", "No detailed reasoning available.")
            story.append(Paragraph(f"<b>Analysis:</b> {explanation}", normal_style))
            story.append(Spacer(1, 0.05 * inch))

            # Actions
            story.append(Paragraph("Recommended Countermeasures:", meta_label_style))
            for action in ai_remediation.get("recommended_actions", []):
                story.append(Paragraph(f"• {action}", normal_style))
            story.append(Spacer(1, 0.05 * inch))

            # Commands
            linux_cmds = ai_remediation.get("linux_commands", [])
            if linux_cmds:
                story.append(Paragraph("Mitigation Commands (Copyable):", meta_label_style))
                story.append(Paragraph("\n".join(linux_cmds), code_style))

            rollback_cmds = ai_remediation.get("rollback_commands", [])
            if rollback_cmds:
                story.append(Paragraph("Rollback/Undo Commands:", meta_label_style))
                story.append(Paragraph("\n".join(rollback_cmds), code_style))

        # ── 7. Network Topology Snapshot ─────────────────────────────────────
        story.append(Paragraph("7. Network Topology Snapshot", section_heading))
        
        # ASCII schema
        ascii_diagram = """
           [ Internet: 198.51.100.1 ]
                     │
         [ Firewall: 10.0.0.1 ] (GATEWAY)
                     │
          [ Switch: 10.0.1.1 ]
         ┌───────────┼───────────┐
  [ Web Server ]  [ DB Server ]  [ Workstation ]
   10.0.1.10       10.0.1.20       10.0.1.100
        """
        story.append(Paragraph("Network Infrastructure Architecture Layout:", meta_label_style))
        story.append(Paragraph(ascii_diagram.strip().replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style))
        story.append(Spacer(1, 0.05 * inch))

        # Devices list table
        if devices_list:
            story.append(Paragraph("Topology Device Registry & Runtime Status:", meta_label_style))
            dev_data = [
                [
                    Paragraph("Hostname", meta_label_style),
                    Paragraph("Category", meta_label_style),
                    Paragraph("IP Address", meta_label_style),
                    Paragraph("MAC Address", meta_label_style),
                    Paragraph("Status", meta_label_style)
                ]
            ]
            for dev in devices_list:
                status_val = dev.get("status", "").upper()
                status_color = "#22C55E"  # green
                if status_val in ("UNDER_ATTACK", "WARNING"):
                    status_color = "#EF4444"
                elif status_val == "BLOCKED":
                    status_color = "#F97316"
                elif status_val == "OFFLINE":
                    status_color = "#64748B"
                
                status_p = Paragraph(f"<font color='{status_color}'><b>{status_val}</b></font>", normal_style)
                dev_data.append([
                    Paragraph(dev.get("hostname", ""), normal_style),
                    Paragraph(dev.get("type", "").upper(), normal_style),
                    Paragraph(dev.get("ip", "N/A"), normal_style),
                    Paragraph(dev.get("mac", "N/A"), normal_style),
                    status_p
                ])

            t_dev = Table(dev_data, colWidths=[1.3 * inch, 1.1 * inch, 1.3 * inch, 1.5 * inch, 1.3 * inch])
            t_dev.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t_dev)

        # Build document
        doc.build(story)
