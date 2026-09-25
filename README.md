# 🔐 IPsec VPN Analyzer Dashboard

> **An AI-assisted security analysis platform for IPsec VPN traffic, configuration assessment, encrypted traffic classification, and metadata exposure analysis.**

The **IPsec VPN Analyzer Dashboard** is a cybersecurity analysis platform designed to inspect IPsec VPN traffic from packet captures, extract IKE/IPsec configuration details, evaluate cryptographic security, classify encrypted ESP traffic using machine learning, and identify metadata that may still be exposed despite strong encryption.

The platform combines **protocol parsing, rule-based security assessment, machine learning, traffic analysis, and an interactive web dashboard** into a single workflow.

---

## 📌 Overview

IPsec provides strong encryption for network communication, but encryption does not necessarily eliminate all observable information.

An external observer may still be able to learn information from:

* IKE negotiation parameters
* Encryption and authentication algorithms
* Diffie-Hellman groups
* Perfect Forward Secrecy configuration
* Packet sizes
* Packet timing
* Traffic bursts
* Flow duration
* Traffic volume
* Peer communication patterns

This project analyzes those characteristics without decrypting the protected payload.

### Core idea

```text
                    ┌──────────────────────┐
                    │     PCAP Capture      │
                    └──────────┬───────────┘
                               │
                               ▼
                 ┌─────────────────────────┐
                 │   FastAPI Backend        │
                 └────────────┬────────────┘
                              │
              ┌───────────────┼────────────────┐
              │               │                │
              ▼               ▼                ▼
       ┌────────────┐  ┌──────────────┐  ┌───────────────┐
       │ IKE Parser │  │ ESP Feature  │  │ Observer      │
       │            │  │ Extraction   │  │ Analysis      │
       └─────┬──────┘  └──────┬───────┘  └───────┬───────┘
             │                │                  │
             ▼                ▼                  ▼
       ┌────────────┐  ┌──────────────┐  ┌───────────────┐
       │ Security   │  │ Random Forest│  │ Metadata      │
       │ Scoring    │  │ Classifier   │  │ Exposure      │
       └─────┬──────┘  └──────┬───────┘  └───────┬───────┘
             │                │                  │
             └────────────────┼──────────────────┘
                              ▼
                   ┌─────────────────────┐
                   │ React Dashboard     │
                   │                     │
                   │ Scores              │
                   │ Findings            │
                   │ Flows               │
                   │ Reports             │
                   │ Observer Profiles   │
                   │ Topology            │
                   └─────────────────────┘
```

---

# ✨ Key Features

## 1. 🔎 IPsec / IKE Analysis

The platform analyzes IKE negotiation data from packet captures and extracts security-relevant parameters such as:

* IKE version
* Encryption algorithm
* Integrity/authentication algorithm
* Diffie-Hellman group
* Key exchange parameters
* PFS configuration
* Security Association characteristics
* Peer information

The parser uses **TShark/Wireshark packet decoding** rather than attempting to decrypt the VPN payload.

---

## 2. 🛡️ Security Scoring

Each analyzed VPN session receives a rule-based security assessment.

The scoring engine evaluates areas such as:

* Cryptographic strength
* Encryption algorithm
* Key strength
* Diffie-Hellman group
* Perfect Forward Secrecy
* Configuration compliance
* Key-management characteristics
* Security policy violations

The system generates:

```text
Overall Security Score
        │
        ├── Cryptographic Strength
        ├── Compliance
        └── Key Management
```

The platform also generates a **Threat Matrix** containing:

| Finding          | Severity    | Impact                          | Recommendation       |
| ---------------- | ----------- | ------------------------------- | -------------------- |
| Weak encryption  | High        | Reduced confidentiality         | Upgrade cipher       |
| Weak DH group    | High        | Reduced key-exchange security   | Use stronger group   |
| PFS disabled     | Medium/High | Increased key compromise impact | Enable PFS           |
| Policy violation | Variable    | Configuration non-compliance    | Update configuration |

The scoring system is rule-based so that individual findings can be traced back to specific security rules rather than relying on an unexplained score.

---

# 🤖 3. Machine Learning Traffic Classification

The project includes a **Random Forest classifier** for identifying characteristics of encrypted ESP traffic.

The classifier does **not inspect or decrypt packet payloads**.

Instead, it uses traffic-level characteristics such as:

* Average packet size
* Packet-size variance
* Packet-size standard deviation
* Inter-arrival timing
* Burst characteristics
* Throughput
* Packet counts
* Flow duration

The model can classify traffic into categories represented by the training dataset, such as:

```text
ICMP
Web
VoIP
Video
Email
Messaging
```

### ML pipeline

```text
PCAP
  │
  ▼
ESP Flow Extraction
  │
  ▼
Feature Extraction
  │
  ├── Packet Size
  ├── Timing
  ├── Burstiness
  ├── Throughput
  └── Flow Statistics
  │
  ▼
Dataset
  │
  ▼
Random Forest
  │
  ▼
Traffic Classification
  │
  ▼
Prediction + Confidence
```

The system also stores feature importance information so that model outputs can be inspected rather than treated as a completely opaque prediction.

---

# 👁️ 4. Metadata Exposure Analysis

Strong encryption does not necessarily hide traffic patterns.

The **Observer Profile** analyzes what information may remain observable from encrypted traffic.

Current analysis includes:

* Traffic identifiability
* Padding exposure
* Temporal patterns
* Peer stability
* Volume signatures
* Multi-session correlation
* Insufficient-history detection

For example:

```text
VPN Encryption
      │
      │ Strong
      ▼
┌───────────────┐
│ AES / Strong  │
│ DH / PFS      │
└───────┬───────┘
        │
        ▼
Encrypted ESP Traffic
        │
        ├── Packet sizes
        ├── Timing
        ├── Bursts
        └── Volume
              │
              ▼
      Observable Metadata
```

This allows the system to distinguish between **cryptographic security** and **traffic-pattern privacy**.

---

# 📊 5. Interactive Dashboard

The frontend is built using:

* React
* Vite
* Tailwind CSS
* React Router

The dashboard provides multiple views.

### Sessions

View uploaded PCAP sessions and their analysis status.

### Session Details

Displays:

* IKE handshake
* ESP flows
* Security score
* Threat matrix
* Traffic classification
* Observer findings
* Reports

### Tunnels

Multiple sessions can be associated with a logical tunnel using a `tunnel_id`.

This enables analysis across multiple captures rather than treating every PCAP as an isolated event.

### Policies

Upload and inspect custom security policies.

### Reports

Generate:

* Technical reports
* Executive reports

### Global Topology

Visualizes monitored agents, peers, and VPN tunnel relationships.

---

# 🧩 6. Monitoring Agent

The project also includes an optional lightweight monitoring agent.

The agent can:

1. Register with the backend
2. Receive an agent identity/key
3. Capture authorized network traffic
4. Upload captures to the backend
5. Associate sessions with an agent
6. Contribute to the global topology

This enables the architecture to move from:

```text
Manual PCAP Upload
```

toward:

```text
Authorized Endpoint
       │
       ▼
Monitoring Agent
       │
       ▼
PCAP Capture
       │
       ▼
Central Analyzer
       │
       ▼
Dashboard
```

---

# 🏗️ Project Architecture

```text
IPsec-VPN-Analyzer-Dashboard
│
├── backend/
│   │
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes_analysis.py
│   │   │   ├── routes_capture.py
│   │   │   ├── routes_scoring.py
│   │   │   ├── routes_observer.py
│   │   │   ├── routes_reports.py
│   │   │   └── routes_agents.py
│   │   │
│   │   ├── ike/
│   │   │   ├── parser.py
│   │   │   └── schemas.py
│   │   │
│   │   ├── flow/
│   │   │   ├── extractor.py
│   │   │   └── features.py
│   │   │
│   │   ├── ml/
│   │   │   ├── dataset.py
│   │   │   ├── train.py
│   │   │   ├── classifier.py
│   │   │   └── artifacts/
│   │   │
│   │   ├── scoring/
│   │   │   ├── engine.py
│   │   │   ├── rules.py
│   │   │   └── policy.py
│   │   │
│   │   ├── observer/
│   │   │   ├── profile.py
│   │   │   ├── correlate.py
│   │   │   └── render.py
│   │   │
│   │   ├── reports/
│   │   │   ├── technical.py
│   │   │   └── executive.py
│   │   │
│   │   └── main.py
│   │
│   ├── data/
│   │   ├── datasets/
│   │   └── pcaps/
│   │
│   ├── testbed/
│   └── tests/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── api.js
│   │   └── App.jsx
│   │
│   ├── package.json
│   └── vite.config.js
│
├── docs/
├── API-SPEC.md
├── PLAN.md
└── IMPLEMENTED.md
```

---

# ⚙️ Technology Stack

## Backend

| Technology    | Purpose                    |
| ------------- | -------------------------- |
| Python        | Core development           |
| FastAPI       | REST API                   |
| Uvicorn       | ASGI server                |
| SQLAlchemy    | Database ORM               |
| SQLite        | Local application database |
| Scapy         | Packet processing          |
| TShark        | Packet/IKE analysis        |
| Pandas        | Dataset processing         |
| Scikit-learn  | Machine learning           |
| Random Forest | Traffic classification     |
| XGBoost       | ML experimentation         |
| Joblib        | Model persistence          |
| PyYAML        | Security policies          |

## Frontend

| Technology   | Purpose                   |
| ------------ | ------------------------- |
| React        | UI                        |
| Vite         | Development/build tooling |
| Tailwind CSS | Styling                   |
| React Router | Application routing       |

---

# 🚀 Installation

## Requirements

Install the following before running the project:

* Python 3.10+
* Node.js
* npm
* Git
* Wireshark/TShark

For the optional VPN testbed:

* Docker
* Docker Compose
* Linux/Kali environment recommended for the strongSwan testbed

---

# 📥 Clone the Repository

```bash
git clone https://github.com/ScriptSynapse/IPsec-VPN-Analyzer-Dashboard.git
cd IPsec-VPN-Analyzer-Dashboard
```

---

# 🐍 Backend Setup

Navigate to the backend:

```bash
cd backend
```

Create a virtual environment:

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Verify TShark:

```bash
tshark --version
```

Start the API:

```bash
python -m uvicorn app.main:app --reload
```

Backend:

```text
http://localhost:8000
```

Swagger API documentation:

```text
http://localhost:8000/docs
```

Health check:

```text
http://localhost:8000/health
```

---

# ⚛️ Frontend Setup

Open a second terminal.

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Dashboard:

```text
http://localhost:5173
```

The frontend communicates with:

```text
http://localhost:8000
```

The backend URL can also be configured from the dashboard.

---

# 🧪 Running Tests

From the backend directory:

```bash
pytest -q
```

The repository contains tests covering areas including:

* API endpoints
* Health checks
* IKE parsing
* Flow extraction
* ML pipeline
* Scoring engine
* Observer analysis
* Policy validation

---

# 🧠 Training the Traffic Classifier

The ML pipeline requires labeled PCAP data.

After collecting appropriate captures:

```bash
python -m app.ml.dataset
```

Then train the classifier:

```bash
python -m app.ml.train
```

The trained model is stored under:

```text
backend/app/ml/artifacts/
```

The classifier is intentionally designed to fail closed when insufficient training data is available rather than producing misleading predictions.

---

# 📦 Using the Dashboard

## Step 1: Start Backend

```bash
cd backend
python -m uvicorn app.main:app --reload
```

## Step 2: Start Frontend

```bash
cd frontend
npm run dev
```

## Step 3: Open Dashboard

```text
http://localhost:5173
```

## Step 4: Upload a PCAP

Navigate to:

```text
Sessions → Upload
```

Select a valid:

```text
.pcap
.pcapng
```

file.

## Step 5: Analyze

Open the uploaded session and run the analysis.

The backend performs:

```text
PCAP
 ↓
IKE Analysis
 ↓
ESP Flow Extraction
 ↓
Traffic Classification
 ↓
Security Scoring
 ↓
Observer Analysis
 ↓
Report Generation
```

---

# 🔌 API Endpoints

| Method | Endpoint                          | Description             |
| ------ | --------------------------------- | ----------------------- |
| GET    | `/health`                         | Backend/database health |
| POST   | `/sessions/upload`                | Upload PCAP             |
| GET    | `/sessions`                       | List sessions           |
| GET    | `/sessions/{id}`                  | Session details         |
| PATCH  | `/sessions/{id}`                  | Update session metadata |
| POST   | `/sessions/{id}/analyze`          | Analyze session         |
| GET    | `/sessions/{id}/ike`              | IKE findings            |
| GET    | `/sessions/{id}/flows`            | ESP flow findings       |
| GET    | `/sessions/{id}/score`            | Security score          |
| GET    | `/sessions/{id}/report`           | Generate report         |
| GET    | `/sessions/{id}/observer-profile` | Observer analysis       |
| GET    | `/tunnels/{id}/observer-profile`  | Tunnel-level analysis   |
| POST   | `/policy`                         | Upload security policy  |
| GET    | `/policy`                         | List policies           |
| GET    | `/agents`                         | List monitoring agents  |
| POST   | `/agents`                         | Register an agent       |
| GET    | `/topology`                       | Global topology         |

Full API details are available in [`API-SPEC.md`](./API-SPEC.md).

---

# 🔬 Testbed

The repository includes a strongSwan-based IPsec testbed under:

```text
backend/testbed/
```

The testbed is designed to generate controlled VPN traffic using different configurations and traffic profiles.

Example configuration categories include:

```text
3DES
AES-128
AES-256
AES-GCM
Different DH groups
PFS enabled/disabled
IPv4
IPv6 configurations
```

Traffic profiles include categories such as:

```text
ICMP
Web
VoIP
Video
Email
Messaging
```

The testbed can then produce PCAP files that can be analyzed by the dashboard.

> The testbed requires an environment capable of creating IPsec/XFRM tunnels. A standard Windows development environment may not support every part of the testbed directly. The analysis dashboard itself can still be run locally on Windows.

---

# 🔐 Security Design

A central design principle of this project is:

> **The analyzer does not decrypt protected VPN payloads.**

The system focuses on observable information from:

```text
IKE negotiation
+
Encrypted packet metadata
+
Traffic statistics
```

This makes the analyzer suitable for studying how much information can remain observable even when payload confidentiality is preserved.

---

# 📊 Reports

The system supports two report formats.

### Technical Report

Designed for security analysts and technical users.

Contains:

* VPN configuration
* IKE findings
* ESP flow information
* Security scoring
* Threat findings
* Observer profile
* Recommendations

### Executive Report

Designed for non-technical stakeholders.

Provides:

* Overall assessment
* Key risks
* Important findings
* Recommended actions
* High-level security summary

Reports can be returned as structured JSON or Markdown.

---

# 📈 Current Project Status

| Component                  | Status                   |
| -------------------------- | ------------------------ |
| FastAPI backend            | ✅ Implemented            |
| React dashboard            | ✅ Implemented            |
| SQLite database            | ✅ Implemented            |
| PCAP upload                | ✅ Implemented            |
| IKE parser                 | ✅ Implemented            |
| ESP flow extraction        | ✅ Implemented            |
| Security scoring           | ✅ Implemented            |
| Threat matrix              | ✅ Implemented            |
| ML classification pipeline | ✅ Implemented            |
| Observer Profile           | ✅ Implemented            |
| Multi-session correlation  | ✅ Implemented            |
| Technical reports          | ✅ Implemented            |
| Executive reports          | ✅ Implemented            |
| Monitoring agents          | ✅ Implemented            |
| Global topology            | ✅ Implemented            |
| StrongSwan testbed         | ⚠️ Environment-dependent |
| Large-scale ML dataset     | 🔄 Ongoing               |
| Demonstration video        | 🔄 Pending               |

---

# ⚠️ Limitations

The current system has several important limitations.

### Dataset size

The traffic classifier requires a sufficiently diverse labeled dataset. A small dataset should not be interpreted as evidence of broad real-world generalization.

### Traffic classification

Traffic classification is based on observable traffic characteristics rather than payload inspection. Predictions therefore represent statistical inference rather than guaranteed identification.

### Messaging traffic

Messaging traffic profiles used for controlled experiments represent traffic characteristics rather than decrypted or authenticated captures of a specific messaging application.

### Testbed

The strongSwan testbed requires appropriate Linux networking, Docker, and IPsec/XFRM support.

### IPv6

IPv6 configurations are included in the project design but have less experimental coverage than IPv4 configurations.

---

# 🧪 Experimental Workflow

A typical experiment can follow this workflow:

```text
1. Configure IPsec tunnel
          ↓
2. Establish strongSwan VPN
          ↓
3. Generate controlled traffic
          ↓
4. Capture PCAP
          ↓
5. Upload PCAP
          ↓
6. Parse IKE negotiation
          ↓
7. Extract ESP flow features
          ↓
8. Classify traffic
          ↓
9. Calculate security score
          ↓
10. Analyze metadata exposure
          ↓
11. Generate reports
          ↓
12. Compare configurations
```

This workflow allows researchers to compare different VPN configurations and observe how cryptographic configuration and encrypted traffic characteristics affect the resulting analysis.

---

# 🎯 Use Cases

The project can be used for:

* IPsec security assessment
* VPN configuration auditing
* Network security research
* Encrypted traffic analysis research
* Cybersecurity education
* Security operations experimentation
* VPN privacy research
* Machine learning experimentation
* Security policy validation
* Academic research

---

# 🛠️ Future Improvements

Potential future work includes:

* Larger and more diverse real-world datasets
* Additional traffic classes
* Improved ML models
* Explainable AI visualizations
* Temporal drift detection
* More advanced traffic correlation
* Expanded IPv6 testing
* Additional IPsec modes
* Automated security-policy recommendations
* Role-based access control
* Persistent authentication
* PostgreSQL support
* Dockerized production deployment
* Distributed monitoring agents
* Real-time alerting
* SIEM integration

---

# 📚 Documentation

Additional project documentation:

* [`API-SPEC.md`](./API-SPEC.md) - API specification
* [`PLAN.md`](./PLAN.md) - Project implementation plan
* [`IMPLEMENTED.md`](./IMPLEMENTED.md) - Implementation status
* [`FULL-IMPLEMENTATION.md`](./FULL-IMPLEMENTATION.md) - Full implementation review
* [`docs/PROJECT_EXPLAINED.md`](./docs/PROJECT_EXPLAINED.md) - Project explanation
* [`docs/technical_documentation.md`](./docs/technical_documentation.md) - Technical documentation
* [`docs/demo_script.md`](./docs/demo_script.md) - Demonstration workflow

---

# 👨‍💻 Author

**Paulson Fernandes**

B.Tech Computer Science Engineering
Cybersecurity & Digital Forensics

MIT World Peace University
Pune, Maharashtra, India

GitHub: [ScriptSynapse](https://github.com/ScriptSynapse)

---

# 📄 License

This project is licensed under the **MIT License**.

See [`LICENSE`](./LICENSE) for details.

---

## ⭐ Project Summary

**IPsec VPN Analyzer Dashboard** brings together traditional network security analysis and machine learning to answer two different questions:

### 1. How securely is the VPN configured?

The system analyzes the IKE negotiation and evaluates cryptographic and configuration properties.

### 2. What can still be inferred from encrypted traffic?

The system analyzes observable traffic characteristics such as packet sizes, timing, bursts, and volumes without decrypting the payload.

Together, these provide a broader view of VPN security:

```text
          VPN Security
               │
       ┌───────┴────────┐
       │                │
 Cryptographic       Observable
   Security           Metadata
       │                │
       ▼                ▼
   IKE Analysis    ESP Analysis
       │                │
       ▼                ▼
 Security Score    ML + Observer
       │                │
       └───────┬────────┘
               ▼
       Unified Dashboard
```

> **Encryption protects content. This project investigates what the surrounding traffic can still reveal.**
