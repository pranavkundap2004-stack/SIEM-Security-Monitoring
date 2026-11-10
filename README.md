# SIEM Security Monitoring & Threat Detection System

A Python-based Security Information and Event Management (SIEM) prototype designed to collect, analyze, detect, and visualize suspicious security events using the Elastic Stack.

## Project Overview

This project demonstrates a centralized security monitoring solution that processes security events, identifies suspicious login activities, generates alerts, and assigns risk scores to help prioritize potential threats.

The system combines custom Python detection modules with Elasticsearch, Logstash, Kibana, and a SOC monitoring dashboard.

## Architecture

**Event Generation → Logstash → Elasticsearch → Detection Engine → Alert Storage → SOC Dashboard**

### Technology Stack

- **Python 3.11** – Detection logic, event analysis, and risk scoring
- **Elasticsearch 9.5.4** – Security event and alert storage
- **Logstash 9.5.4** – Log ingestion and processing
- **Kibana 9.5.4** – Security monitoring and visualization
- **Docker & Docker Compose** – Containerized service deployment
- **JSON** – Event and alert data representation

## Key Features

### 1. Security Event Processing
- Security-event generation for testing.
- Centralized event ingestion using Logstash.
- Elasticsearch-based event storage and indexing.

### 2. Threat Detection Engine

The Python detection engine implements the following detection capabilities:

| Detection Module | Description |
|---|---|
| Brute Force Detection | Identifies repeated failed login attempts |
| Unknown IP Detection | Identifies activity from unrecognized IP addresses |
| Unusual Login Time | Detects login activity outside expected time patterns |
| Failure-to-Success Correlation | Identifies successful logins following failed attempts |
| Password Spraying Detection | Identifies suspicious password-spraying patterns |
| Multiple IPs per User | Identifies accounts associated with multiple IP addresses |
| IP Activity Analysis | Analyzes IP-based security activity |
| Risk Scoring Engine | Assigns risk scores and severity classifications |

### 3. Alert Management
- Centralized alert storage.
- Detection result correlation.
- Risk-based prioritization.
- Severity classification.
- Deterministic alert identifiers.

### 4. Security Monitoring Dashboard

The project includes a Python-based SOC dashboard and Kibana visualizations to help monitor:

- Security alert counts.
- Detection categories.
- Severity distribution.
- Risk scores.
- Suspicious login activity.

## Project Structure

```text
SIEM-Security-Monitoring/
│
├── config/
│   ├── elasticsearch/
│   └── kibana/
│
├── detection/
│   ├── alert_storage.py
│   ├── brute_force_detector.py
│   ├── failure_success_detector.py
│   ├── ip_activity_analyzer.py
│   ├── multiple_ip_same_user_detector.py
│   ├── password_spraying_detector.py
│   ├── risk_scoring_engine.py
│   ├── unified_detection_engine.py
│   ├── unknown_ip_detector.py
│   └── unusual_time_detector.py
│
├── generator/
│   └── security_event_generator.py
│
├── gui/
│   └── soc_dashboard.py
│
├── logstash/
│   └── pipeline/
│       └── logstash.conf
│
├── screenshots/
│
├── .env.example
├── .gitignore
├── docker-compose.yml
└── README.md
```

## Setup and Installation

### Prerequisites

- Windows, Linux, or macOS
- Docker Desktop or Docker Engine
- Docker Compose
- Python 3.11 or compatible version

### Step 1: Clone the Repository

```bash
git clone https://github.com/pranavkundap2004-stack/SIEM-Security-Monitoring.git

cd SIEM-Security-Monitoring
```

### Step 2: Configure Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Review the environment variables before starting the services.

### Step 3: Start the Elastic Stack

```bash
docker compose up -d
```

### Step 4: Verify Services

```bash
docker compose ps
```

### Step 5: Access the Monitoring Interfaces

- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601

The actual host ports depend on the values configured in `.env`.

## Sample Detection Results

During a recorded test run, the detection engine generated the following results:

| Detection Category | Alerts |
|---|---:|
| Brute Force | 6 |
| Unknown IP | 2 |
| Unusual Login Time | 1 |
| Failed-to-Successful Login | 1 |
| Password Spraying | 0 |
| Multiple IPs for Same User | 5 |
| **Total** | **15** |

These results represent one test execution and are not a benchmark of detection accuracy.

## Screenshots

The `screenshots/` directory contains implementation evidence, including:

- SIEM environment and Docker services.
- Elasticsearch service responses.
- Controlled security-event testing.
- Logstash pipeline ingestion.
- Elasticsearch security events.
- Event-count results.
- Kibana dashboard visualizations.
- Detection and alert results.

## Security Considerations

- Never upload `.env` or credentials.
- Keep private certificates and private keys out of version control.
- Use `.env.example` for placeholder configuration.
- Elasticsearch security is disabled in the included local Docker Compose configuration.
- This project is an educational and portfolio prototype, not a production-hardened deployment.

## Future Improvements

- Expand detection capabilities.
- Improve alert correlation and prioritization.
- Enhance SOC dashboard functionality.
- Integrate additional threat intelligence sources.
- Introduce improved authentication and access controls.
- Expand automated testing and detection validation.

## Author

**Pranav Kundap**

Cybersecurity Enthusiast | SIEM | Security Monitoring | Threat Detection

GitHub: https://github.com/pranavkundap2004-stack

---

*This project was developed as a hands-on cybersecurity learning and implementation project to explore SIEM architecture, security-event analysis, threat detection, and SOC monitoring workflows.*
