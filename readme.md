# 🛡️ SOAR-Lite: Automated Threat Intelligence & Triage Platform

> **Created by:** Rudra Choudhary
> **Target Roles:** SOC Analyst (Tier 1/2), Detection Engineer, Security Automation Engineer

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge\&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-red?style=for-the-badge\&logo=streamlit)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge\&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## 📌 Executive Summary

**SOAR-Lite** is an enterprise-inspired **Security Orchestration, Automation, and Response (SOAR)** platform designed to solve **SOC alert fatigue** and accelerate Incident Response (IR).

In traditional Security Operations Centers (SOCs), analysts may spend significant time manually querying multiple OSINT and threat-intelligence sources for every Indicator of Compromise (IOC).

SOAR-Lite automates this workflow by:

* Querying multiple threat-intelligence sources
* Automatically identifying IOC types
* Validating indicators
* Performing dynamic weighted risk scoring
* Mapping findings to **MITRE ATT&CK**
* Generating PDF, Markdown, and CSV reports
* Dispatching real-time webhook alerts
* Supporting both single and bulk IOC triage

The goal is to reduce repetitive analyst work and provide a centralized interface for initial IOC investigation.

---

## 🎯 Key Features

### 🔎 Multi-Source OSINT Integration

SOAR-Lite integrates multiple threat-intelligence sources:

* **VirusTotal v3**

  * File hashes
  * URLs
  * IP addresses
  * Domains

* **AbuseIPDB v2**

  * IP reputation
  * Abuse confidence
  * Report history

* **Shodan Host API**

  * Open ports
  * Services
  * Host information
  * Vulnerabilities

* **AlienVault OTX**

  * Threat pulses
  * IOC associations
  * Community intelligence

---

### 🧩 Universal IOC Support

SOAR-Lite automatically classifies and validates:

* IPv4 addresses
* Domain names
* URLs
* MD5 hashes
* SHA-1 hashes
* SHA-256 hashes

Example indicators:

```text
185.220.101.1
example.com
https://example.com/payload
24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
```

---

### 📊 Dynamic Risk Scoring Engine

SOAR-Lite calculates a normalized **0–100 risk score** using weighted threat-intelligence results.

The scoring model is:

```text
Final Score = Σ (Raw Scoreᵢ × Normalized Weightᵢ)
```

The scoring engine dynamically adjusts weights when a particular intelligence source is unavailable or irrelevant to the submitted IOC.

For example, AbuseIPDB provides IP reputation information and therefore should not negatively influence the score of a file hash simply because it cannot be queried for that IOC type.

---

### 🚨 Severity Classification

| Severity        | Score Range | Default Action Protocol                                                |
| --------------- | ----------: | ---------------------------------------------------------------------- |
| 🚨 **CRITICAL** |      80–100 | Immediate investigation, containment, and incident-response procedures |
| 🟧 **HIGH**     |       60–79 | Investigate historical activity and consider blocking                  |
| 🟨 **MEDIUM**   |       40–59 | Add to watchlist and increase monitoring                               |
| 🟩 **LOW**      |       20–39 | Log and establish baseline activity                                    |
| ✅ **CLEAN**     |        0–19 | No significant malicious intelligence identified                       |

> **Important:** A `CLEAN` score does not guarantee that an indicator is benign. It means that the queried intelligence sources did not provide sufficient evidence to classify it as malicious.

---

### 🔬 Single & Bulk Triage Modes

#### Single IOC Triage

Analyze an individual IOC directly through the analyst console.

```text
185.220.101.1
```

#### Bulk IOC Triage

Upload `.CSV` or `.TXT` files containing hundreds of indicators.

Example:

```text
185.220.101.1
8.8.8.8
example.com
44d88612fea8a8f36de82e1278abb02f
```

The platform automatically identifies and processes the indicators.

---

### 🧠 MITRE ATT&CK Mapping

SOAR-Lite maps relevant findings to **MITRE ATT&CK tactics and techniques**.

The intended workflow is:

```text
IOC
 │
 ▼
Threat Intelligence
 │
 ▼
Risk Assessment
 │
 ▼
MITRE ATT&CK Context
 │
 ▼
Investigation / Response
```

This provides analysts with additional context during triage instead of treating an IOC as an isolated artifact.

---

### 📄 Automated Incident Reporting

SOAR-Lite generates structured reports in:

* PDF
* Markdown
* CSV

Reports can contain:

```text
IOC
IOC Type
Risk Score
Severity
Threat Intelligence Results
Source Availability
MITRE ATT&CK Mapping
Investigation Recommendations
Timestamp
```

This allows analysts to preserve investigation results and share them with other members of a security team.

---

### 🚨 Real-Time Alert Dispatch

SOAR-Lite can dispatch high-risk findings through webhooks.

The workflow is:

```text
IOC Investigation
       │
       ▼
Risk Scoring
       │
       ├── LOW
       ├── MEDIUM
       │
       └── HIGH / CRITICAL
                 │
                 ▼
          Webhook Notification
                 │
                 ▼
       SOC Incident Channel
```

Supported notification targets can include:

* Discord
* Slack
* Other compatible webhook endpoints

---

### 🖥️ Analyst Console

The Streamlit dashboard provides an enterprise-inspired SOC/SOAR interface featuring:

* Dark-mode interface
* IOC submission
* Bulk upload
* Threat-source results
* Risk score visualization
* Severity indicators
* MITRE ATT&CK information
* Interactive Plotly metrics
* Report generation
* Alert dispatch

The interface is designed around workflows commonly found in modern SIEM, EDR, and SOAR platforms.

---

# 🏗️ System Architecture

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                             ANALYST CONSOLE                              │
│                                                                          │
│             Single IOC Triage  |  Bulk CSV/TXT File Upload              │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         INPUT PARSER & VALIDATOR                         │
│                                                                          │
│             Regex Validation & Automatic IOC Type Detection              │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                       ORCHESTRATION ENGINE (Python)                      │
│                                                                          │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────┐ ┌─────────────┐ │
│  │  VirusTotal v3 │ │ AbuseIPDB v2   │ │ Shodan API   │ │ AlienVault  │ │
│  │  File/URL/IP   │ │ IP Reputation  │ │ Ports/Vulns  │ │ OTX Pulses  │ │
│  └───────┬────────┘ └───────┬────────┘ └──────┬───────┘ └──────┬──────┘ │
│          │                  │                 │                │         │
│          └──────────────────┴────────┬────────┴────────────────┘         │
│                                     ▼                                   │
│                       ┌─────────────────────────┐                        │
│                       │ WEIGHTED RISK SCORING   │                        │
│                       │        ENGINE           │                        │
│                       └────────────┬────────────┘                        │
│                                    │                                     │
│                       ┌────────────▼────────────┐                        │
│                       │ MITRE ATT&CK MAPPING    │                        │
│                       │        ENGINE            │                        │
│                       └────────────┬────────────┘                        │
└────────────────────────────────────┼─────────────────────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
┌──────────────────────┐  ┌──────────────────────┐  ┌────────────────────┐
│   STREAMLIT CONSOLE  │  │   REPORT GENERATOR   │  │   WEBHOOK ALERTS   │
│                      │  │                      │  │                    │
│ Interactive UI       │  │ PDF                  │  │ Discord             │
│ Plotly Metrics       │  │ Markdown             │  │ Slack               │
│ IOC Results          │  │ CSV                  │  │ Real-Time Alerts    │
└──────────────────────┘  └──────────────────────┘  └────────────────────┘
```

---

# 🔄 Investigation Workflow

```text
                    ┌───────────────┐
                    │   IOC Input   │
                    └───────┬───────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ Detect IOC Type   │
                  └─────────┬─────────┘
                            │
                            ▼
               ┌─────────────────────────┐
               │ Query Threat Sources    │
               └────────────┬────────────┘
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
        VirusTotal       AbuseIPDB       Shodan
             │              │              │
             └──────────────┼──────────────┘
                            │
                            ▼
                     AlienVault OTX
                            │
                            ▼
                 ┌────────────────────┐
                 │ Normalize Results  │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Risk Score 0–100   │
                 └─────────┬──────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ MITRE ATT&CK     │
                  │ Mapping           │
                  └─────────┬────────┘
                            │
               ┌────────────┼────────────┐
               ▼            ▼            ▼
          Dashboard       Reports      Alerts
```

---

# 📊 Threat Scoring Methodology

The scoring engine applies normalized weights to active threat-intelligence sources.

When an intelligence source is skipped because it is:

* Not applicable to the IOC type
* Unavailable
* Temporarily inaccessible
* Missing API credentials

its weight is excluded from the denominator and the remaining active sources are normalized.

Conceptually:

```text
Normalized Weightᵢ =
Weightᵢ / Σ Active Weights
```

Then:

```text
Final Score =
Σ (Raw Scoreᵢ × Normalized Weightᵢ)
```

This prevents unavailable or irrelevant sources from artificially reducing the final risk score.

---

# 🚀 Quickstart & Installation

## Prerequisites

Before installing SOAR-Lite, ensure that you have:

* Python **3.11 or higher**
* Git
* Docker *(optional)*

---

## 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/soar-lite.git
cd soar-lite
```

---

## 2. Create Virtual Environment

### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🔐 API Configuration

Copy the environment template:

### macOS / Linux

```bash
cp .env.example .env
```

### Windows

```powershell
copy .env.example .env
```

Then configure your API keys:

```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
ALIENVAULT_API_KEY=your_key_here
DISCORD_WEBHOOK_URL=your_webhook_url_here
```

### Environment Variables

| Variable              | Purpose                           |
| --------------------- | --------------------------------- |
| `VIRUSTOTAL_API_KEY`  | VirusTotal API authentication     |
| `ABUSEIPDB_API_KEY`   | AbuseIPDB API authentication      |
| `SHODAN_API_KEY`      | Shodan API authentication         |
| `ALIENVAULT_API_KEY`  | AlienVault OTX API authentication |
| `DISCORD_WEBHOOK_URL` | Webhook-based alert dispatch      |

> **Security:** Never commit your `.env` file or API keys to Git.

Recommended `.gitignore` entries:

```gitignore
.env
venv/
__pycache__/
*.pyc
```

---

# ▶️ Launch Platform

## Option A — Streamlit Dashboard

Recommended for interactive investigation:

```bash
streamlit run app.py
```

Open the dashboard at:

```text
http://localhost:8501
```

---

## Option B — Command Line Interface

Investigate a single IP:

```bash
python main.py 185.220.101.1
```

Investigate a SHA-256 hash:

```bash
python main.py 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
```

---

# 🐳 Docker Deployment

Build the Docker image:

```bash
docker build -t soar-lite .
```

Run the container:

```bash
docker run -p 8501:8501 --env-file .env soar-lite
```

Access the application at:

```text
http://localhost:8501
```

---

# 🛠️ Tech Stack

| Category                | Technology               |
| ----------------------- | ------------------------ |
| **Core Language**       | Python 3.11+             |
| **Web UI**              | Streamlit                |
| **CLI Interface**       | Rich                     |
| **HTTP/API Client**     | Requests                 |
| **Data Processing**     | Pandas                   |
| **Visualization**       | Plotly Express           |
| **PDF Reporting**       | FPDF2                    |
| **Text Reporting**      | Markdown                 |
| **Threat Intelligence** | VirusTotal v3            |
| **Threat Intelligence** | AbuseIPDB v2             |
| **Host Intelligence**   | Shodan Host API          |
| **Threat Intelligence** | AlienVault OTX           |
| **Notifications**       | Discord / Slack Webhooks |
| **Containerization**    | Docker                   |
| **Security Framework**  | MITRE ATT&CK             |

---

# 📁 Suggested Project Structure

```text
soar-lite/
│
├── app.py
├── main.py
├── requirements.txt
├── Dockerfile
├── .env.example
├── .gitignore
├── README.md
│
├── core/
│   ├── parser.py
│   ├── scoring.py
│   ├── mitre.py
│   └── orchestrator.py
│
├── integrations/
│   ├── virustotal.py
│   ├── abuseipdb.py
│   ├── shodan.py
│   └── otx.py
│
├── reporting/
│   ├── pdf.py
│   ├── markdown.py
│   └── csv.py
│
└── utils/
    └── helpers.py
```

> The structure above is a recommended organization and can be modified according to the actual implementation.

---

# 📊 Example Triage Result

```text
┌──────────────────────────────────────────────┐
│                IOC TRIAGE                    │
├──────────────────────────────────────────────┤
│ IOC:        185.220.101.1                    │
│ Type:       IPv4                             │
│ Score:      87 / 100                         │
│ Severity:   CRITICAL                         │
├──────────────────────────────────────────────┤
│ VirusTotal:     Malicious                     │
│ AbuseIPDB:      High Abuse Confidence         │
│ Shodan:         Multiple Exposed Services     │
│ OTX:            Associated Pulses              │
├──────────────────────────────────────────────┤
│ MITRE ATT&CK:                                 │
│ Relevant tactics / techniques identified      │
└──────────────────────────────────────────────┘
```

---

# 🔭 Future Improvements

Planned or potential extensions include:

* [ ] Elasticsearch integration
* [ ] Splunk integration
* [ ] Microsoft Sentinel integration
* [ ] SIEM alert ingestion
* [ ] Automated case management
* [ ] IOC enrichment caching
* [ ] Redis-based task queues
* [ ] Celery-based asynchronous processing
* [ ] Authentication and RBAC
* [ ] Analyst audit logs
* [ ] Scheduled threat-intelligence feeds
* [ ] YARA rule generation
* [ ] Sigma rule integration
* [ ] STIX/TAXII support
* [ ] Automated response playbooks
* [ ] Kubernetes deployment
* [ ] PostgreSQL investigation database

---

# 🎯 Intended Use Cases

## SOC Operations

Quickly investigate suspicious indicators received from:

* SIEM alerts
* EDR platforms
* Email security systems
* Firewall logs
* IDS/IPS systems

## Threat Intelligence

Enrich IOCs using multiple independent intelligence sources from a single analyst interface.

## Incident Response

Provide an initial assessment of suspicious indicators before deeper investigation and containment.

## Security Automation

Demonstrate how repetitive SOC workflows can be automated using Python, REST APIs, scoring logic, and webhooks.

## Cybersecurity Education

SOAR-Lite can be used as a practical learning project for:

* Threat intelligence
* IOC analysis
* REST APIs
* Security automation
* Risk scoring
* MITRE ATT&CK
* Incident response
* SOC workflows
* Python automation

---

# ⚠️ Limitations

SOAR-Lite depends on external threat-intelligence providers. Results can therefore be affected by:

* API availability
* API rate limits
* Provider outages
* Free-tier limitations
* Incomplete threat intelligence
* False positives
* False negatives
* Stale intelligence

A high score should be treated as an investigation signal rather than definitive proof of compromise.

Similarly, a low score does **not** guarantee that an IOC is benign.

---

# 🔒 Security & Privacy Considerations

SOAR-Lite may submit indicators to third-party threat-intelligence services.

Before using the platform in a production environment, consider:

* Whether submitted indicators contain sensitive information
* Your organization's data-sharing policies
* Third-party API terms
* Regulatory requirements
* Internal incident-response procedures
* Data retention requirements

Do not submit confidential or restricted indicators to external services without appropriate authorization.

---

# 👤 Author

## Rudra Choudhary

**Security Engineer | Cybersecurity & Security Automation**

* GitHub: `Rudra-choudhary`
* LinkedIn: `https://www.linkedin.com/in/rudra-choudhary-b27b41306/`

---

# 📄 License

This project is licensed under the **MIT License**.

---

# ⚠️ Disclaimer

SOAR-Lite is developed for **educational, research, and authorized security-operations purposes**.

Only investigate or test indicators and systems for which you have appropriate authorization.

The platform does not replace professional SOC investigation, incident-response procedures, threat-hunting processes, or organizational security controls.
