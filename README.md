# ThreatArchitect

> **Enterprise Network Threat Modeling & Emulation Platform**  
> A desktop application for building, visualizing, and threat-testing enterprise network topologies — powered by Mininet (Linux) with a transparent simulation fallback on Windows. Equipped with Explainable AI threat modeling, compliance audits, and incident reporting.

---

## Overview

ThreatArchitect is a production-quality, research-grade desktop tool that lets security engineers and students:

- **Construct & Render** realistic enterprise network topologies (routers, firewalls, switches, servers, workstations, databases) with a drag-and-drop interactive topology canvas.
- **Emulate** legitimate user traffic and malicious volumetric/payload attacks (SYN Floods, ICMP Floods, ARP Spoofing, DHCP Starvation, SSH Brute Forcing, and Malware Beacons).
- **Detect** real-time anomalies using deep learning (LSTM Autoencoders) and classify attacks using machine learning (Random Forest Classifiers).
- **Remediate** threats with local generative AI (Llama 3.2 through Ollama integration) streaming token-by-token mitigation playbooks.
- **Audit & Map** network threats to compliance frameworks (NIST CSF, ISO 27001, OWASP ASVS) and map attack paths directly to the MITRE ATT&CK Framework.
- **Generate** printable, multi-page PDF incident reports including cover pages, threat parameters, compliance audit scores, chronological event timelines, copyable shell mitigation commands, and visual topology snap charts.

The application is built with **PySide6 (Qt6)** and runs on Windows and Linux. Mininet integration is available on Linux; Windows falls back to a pure-Python simulation engine with identical behavior.

---

## Phased Project Status

All 5 development phases are **100% Complete & Verified**.

| Phase | Milestone | Status |
|-------|-----------|--------|
| **1** | Application Foundation (UI splitting, consoles, themes, event buses) | ✅ Complete |
| **2** | Networking Foundation (Topologies, links, router & switch components) | ✅ Complete |
| **3** | Attack Simulation & Detections (SYN/ICMP flood, Port Scan, Brute-force) | ✅ Complete |
| **4** | ML Anomaly Detection & MITRE ATT&CK Mapping | ✅ Complete |
| **5** | Explainable AI Playbook, Compliance, Settings, & Reliability | ✅ Complete |

---

## Key Phase 4 & Phase 5 Features

### 🧠 Deep Learning Anomaly Detection & ML Classification
- **LSTM Autoencoders**: Evaluates sequential flow metrics dynamically to score packet stream anomalies (triggers alerts for anomalies exceeding the configured threshold).
- **Random Forest Classifier**: Machine learning model running in the background to accurately classify DDoS, ARP spoofing, SSH brute forcing, port scans, and malware beaconing.

### 🤖 Local Generative AI & Streaming Playbooks
- **Local Ollama Integration**: Leverages local Llama 3.2 instances to provide explaining context and generate actionable countermeasures.
- **Token-by-Token Streaming**: Updates recommendations on the UI real-time with status states: *Analyzing Context* $\rightarrow$ *Streaming Response* $\rightarrow$ *Completed*.
- **Command Clipboard Integration**: Remediation actions compile copy-to-clipboard command blocks allowing administrators to copy bash or firewall commands with one click.

### 🛡️ Compliance Audits & MITRE Mapping
- **Compliance Evaluator**: Audits NIST CSF, ISO 27001, and OWASP ASVS standards against topology active configurations and firewall block ratios.
- **MITRE ATT&CK Mapper**: Automatically resolves classified threats to MITRE tactics and techniques (e.g., T1498 for denial of service) displaying clickable documentation links.

### ⚙️ System settings Editor (`Ctrl+S`)
- Interactive dialog permitting hot-reloads of:
  - UI Themes (`dark` and `light`) loaded dynamically.
  - Packet generator speed rates and canvas animation speeds.
  - Threshold triggers for deep learning anomaly bounds.
  - Ollama LLM host ports and model tag overrides.

### 📁 Log Inspector & UI Explorer (`Ctrl+Shift+L`)
- Separate rotating file logs partition runtime data into `application.log`, `networking.log`, `ai.log`, `threat_detection.log`, `compliance.log`, and `errors.log`.
- Log viewer HUD allows keyword searches, log level filtering, truncating, and exporting.

### 💾 Backup & Corruption Recovery
- Automatically duplicates database file to `threat_architect.db.bak` on start.
- Traps database access errors and automatically recovers state from backup or recreates schemas to guarantee application runtime stability.

---

## Project Structure

```
ThreatArchitect/
├── app/
│   ├── ai/
│   │   ├── compliance/      # NIST, ISO, OWASP checks
│   │   ├── lstm/            # PyTorch sequential autoencoders
│   │   ├── mitre/           # ATT&CK technique lookups
│   │   ├── models/          # Offline trained joblib classifiers
│   │   └── ollama/          # Response parsing & streaming client
│   ├── config/              # YAML loaders, cached structures
│   ├── core/                # Result monads, event buses
│   ├── database/            # SQLite models & recovery engine
│   ├── network/             # Simulation manager, workers, & Mininet
│   ├── ui/                  # Qt main frames, panels, widgets, & nodes
│   └── utils/               # PDF generator, rotating loggers
├── docs/                    # Architectural design docs
├── tests/                   # 90 automated PyTest suites
├── requirements.txt
├── setup.bat                # Windows setup script
└── run.bat                  # Application launcher
```

---

## Setup & Execution

### Windows (One-Click)

1. Launch `setup.bat` to create a virtual environment and download dependencies.
2. Launch `run.bat` to start the application.

### Manual Launch

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# or: source .venv/bin/activate  # Linux

pip install -r requirements.txt
python -m app
```

---

## Verification & Testing

Verify system functionalities and test coverage by executing:

```bash
.venv\Scripts\python -m pytest
```

Output details:
```
====================== 90 passed, 808 warnings in 13.36s ======================
```

---

## Terminal Commands & Keyboard Shortcuts

Type these commands directly inside the ThreatArchitect console terminal:

| Command | Action |
|---------|--------|
| `help` | Lists command registry and shortcuts |
| `start network` | Establishes topology and launches traffic generator |
| `stop network` | Suspends packet generator and simulation |
| `emulate normal` | Resumes legitimate DNS/HTTP/HTTPS/SSH traffic loops |
| `emulate dangerous` | Cycles dangerous attack models (SYN Floods, ARP Spoofs) |
| `show topology` | Prints ASCII topology hierarchy tree |
| `show nodes` | Outputs active host IP, MAC, and status directory |
| `show firewall` | Renders active firewall rules and block logs |
| `generate report` | Compiles ReportLab PDF incident report with topology snap |
| `clear` | Clears console terminal text |

### Keyboard Shortcuts

- **`Ctrl+R`**: Start network
- **`Ctrl+C`**: Stop network
- **`Ctrl+E`**: Emulate normal traffic
- **`Ctrl+L`**: Clear terminal
- **`Ctrl+G`**: Toggle right-side threat graph and explainability panel
- **`Ctrl+S`**: Open System Settings Editor dialog
- **`Ctrl+Shift+L`**: Open Partitioned Log Explorer dialog

---

## License

MIT — see [LICENSE](LICENSE) for details.
