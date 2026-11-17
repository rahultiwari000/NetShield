# 🛡️ NetShield — Real-Time Network Intrusion Detection System

NetShield is a Python-based **Network Intrusion Detection System (NIDS)** designed to monitor live network traffic, detect suspicious attack patterns, visualize telemetry, and store security alerts in an interactive dark-themed dashboard.

Built with **Python, Streamlit, Scapy, SQLite, Pandas, and Plotly**.

## 🚀 Live Demo

🌐 **Streamlit App:** https://netshield-i9jjdpfqxfzinpje7qbqtf.streamlit.app/

## ✨ Key Features

* **Real-Time Packet Capture:** Monitors live Wi-Fi or Ethernet traffic using Scapy (with an optional Cloud Demo Simulator when hosted on Streamlit Community Cloud).
* **Multi-Rule Intrusion Detection:**
  * **DDoS / Packet Flood:** Flags abnormally high packet rates from a single source IP.
  * **Port Scan:** Detects a single source probing multiple distinct destination ports.
  * **TCP SYN Flood:** Identifies abnormal bursts of TCP `SYN` packets.
  * **ICMP Flood:** Flags excessive ICMP ping/control packet rates.
* **Configurable Sensitivity & Cooldowns:** Customize rolling time windows, rule thresholds, and alert cooldown timers directly from the UI.
* **Interactive 5-View Dashboard:**
  * **Overview:** Live packet counters, PPS rate, protocol metrics, and recent alerts.
  * **Live Traffic:** Searchable, filterable packet stream with Pause/Resume and a Packet Metadata Inspector.
  * **Threat Detection:** Severity breakdown (`Critical`, `High`, `Medium`, `Low`) and source-IP traffic investigation.
  * **Network Analytics:** Interactive Plotly charts for protocol distribution, traffic over time, top source IPs, and destination ports.
  * **Alert History:** Persistent SQLite alert log (`netshield.db`) with filtering and CSV export.

## 📂 Project Structure

```text
NetShield/
├── app.py                 # Streamlit dashboard & navigation
├── requirements.txt       # Python dependencies
├── packages.txt           # System dependencies for cloud deployment
├── README.md              # Project documentation
├── core/
│   ├── capture.py         # Scapy packet capture & Windows interface discovery
│   ├── analyzer.py        # Rolling traffic metrics & time-series aggregation
│   ├── detector.py        # Rule-based intrusion detection & alert cooldowns
│   ├── database.py        # Thread-safe SQLite alert persistence
│   └── engine.py          # Background packet consumer pipeline
└── tests/
    ├── test_database.py   # SQLite persistence tests
    └── test_detector.py   # Detection rule & cooldown tests
```

## ⚙️ Installation & Local Setup

### 1. Prerequisites

* **Python 3.10+** (Python 3.12 recommended)
* **Npcap (Windows Only):** Download from [npcap.com](https://npcap.com/) and check **"Install Npcap in WinPcap API-compatible Mode"** during installation.

### 2. Create a Virtual Environment & Install Dependencies

Open a terminal inside the `NetShield` folder:

```bash
python -m venv .venv
```

Activate the environment:

* **Windows (PowerShell):** `.\.venv\Scripts\Activate.ps1`
* **Windows (CMD):** `.venv\Scripts\activate`
* **Linux/macOS:** `source .venv/bin/activate`

Install packages:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Run the Application

For live hardware packet capture on Windows, open your terminal as **Administrator** and run:

```bash
streamlit run app.py
```

Open `http://localhost:8501` in your browser, select your active Wi-Fi or Ethernet interface, and click **Start Monitoring**.

## 🔍 Default Detection Rules

| Attack Category | Trigger Condition (Rolling Window) | Default Threshold |
| :--- | :--- | :--- |
| **Detection Window** | Rolling evaluation period | `10 seconds` |
| **DDoS / Packet Flood** | Total packets from one source IP | `> 50 packets` |
| **Port Scan** | Unique destination ports contacted by one source IP | `> 12 ports` |
| **TCP SYN Flood** | TCP `SYN` packets from one source IP | `> 30 SYN packets` |
| **ICMP Flood** | ICMP packets from one source IP | `> 20 ICMP packets` |
| **Alert Cooldown** | Duplicate alert suppression per `(source IP, attack)` | `15 seconds` |

## 🧪 Running Unit Tests & Troubleshooting

Run the standalone test suite:

```bash
python -m unittest discover -s tests
```

**Common Fixes:**

* **No interfaces listed / Permission error:** Ensure Npcap is installed and launch your terminal as **Administrator** (Windows) or with `sudo` (Linux/macOS).
* **`pip` launcher error:** Always use `python -m pip install ...` instead of standalone `pip`.
* **Port 8501 in use:** Run `python -m streamlit run app.py --server.port 8502`.

## ⚠️ Scope & Ethical Use

* NetShield is a **passive Network Intrusion Detection System (NIDS)** intended for academic and educational demonstrations—it does not decrypt encrypted payloads or automatically block traffic.
* Only monitor networks and devices you own or have explicit permission to test.
