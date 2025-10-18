# 🧠 Honeypy Attack Monitoring & Analysis System

## 📌 Project Overview

This project implements a **cloud-based honeypot** that emulates vulnerable **SSH** and **HTTP WordPress-like login interfaces** to attract malicious actors. It captures, analyzes, and reports real-world attack data to study behaviors and techniques used by adversaries.

Deployed on a secure VPS environment, the system automatically logs brute-force attempts, command execution, and HTTP login activity. It enriches the collected data using **IP intelligence APIs** for geolocation, organization (ASN), and VPN detection.

---

## ⚙️ Features

* **SSH & HTTP Honeypots** built using Python and Flask
* **Credential capture** (username/password pairs)
* **IP enrichment** using IPinfo API (ASN, Org, City, Country)
* **VPN detection** integration
* **Audit report generator** for structured text-based summaries
* **Cloud-ready deployment** (Ubuntu VPS, port forwarding supported)
* **Extensible modular codebase** for adding new protocols (FTP, SMTP...)

---

## 🧰 Tech Stack

| Layer              | Technology                                 |
| ------------------ | ------------------------------------------ |
| Backend            | Python (Flask, Paramiko, Requests, Regex)  |
| Data Processing    | Custom log parsers & analyzers             |
| GeoIP Intelligence | IPinfo API (with token authentication)     |
| Logging            | Rotating file handlers for SSH & HTTP logs |
| Environment        | Ubuntu 22.04 LTS (VPS-based deployment)    |

---

## 🧾 Example Audit Report

```bash
===== HONEYPY ATTACK REPORT =====
Generated on: 2025-10-18 20:29:29 UTC

Top Attacker IPs:
196.75.162.63 | Temara, Rabat-Salé-Kénitra, MA (Maroc Telecom) | VPN: No | 3 attempts

Captured Credentials:
196.75.162.63 | admin | 123456 | Morocco
```

---

## 🚀 Setup & Deployment

### 1️⃣ Clone Repository

```bash
git clone https://github.com/<your-username>/honeypy-honeypot.git
cd honeypy-honeypot
```

### 2️⃣ Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Run SSH or HTTP Honeypot

#### SSH Honeypot

```bash
python3 honeypy.py -a 0.0.0.0 -p 2222 --ssh
```

#### HTTP Honeypot (WordPress Simulation)

```bash
python3 honeypy.py -a 0.0.0.0 -p 8080 --http
```

### 5️⃣ Generate Attack Reports

```bash
python3 audit_report.py  # SSH Report
python3 http_audit_report.py  # HTTP Report
```

---

## 🧭 Directory Structure

```
├── honeypy.py                # Main honeypot launcher
├── ssh_honeypot.py           # SSH simulation logic
├── web_honeypot.py           # Flask-based HTTP honeypot
├── audit_report.py           # SSH report generator
├── http_audit_report.py      # HTTP report generator
├── logs/
│   ├── ssh_audits.log
│   ├── http_audits.log
│   └── audit_report.txt
├── templates/
│   └── login.html            # WordPress-style login page
├── requirements.txt
└── README.md
```

---

## 📸 Recommended Image for LinkedIn Post

Use a clean, **cybersecurity-themed image** to grab attention. Examples:

* A dark-themed dashboard with IP map visualization
* A terminal screen with scrolling logs ("attacker connected", etc.)
* A world map glowing with connection lines (representing global attack sources)
* A stylized image with title overlay: *“Cloud Honeypot Attack Report System – by Marwane Boujlida”*

If you want, I can **generate one** for you that matches your honeypot’s theme — dark, technical, and professional.

---

## 🧩 Future Improvements

* Real-time dashboard using Grafana or Kibana
* Add FTP/SMTP honeypots for wider coverage
* Integrate machine learning models for attack pattern classification
* Build an API for live data querying

---

## 🏆 Author

**Marwane Boujlida**
*Engineering Student & Cybersecurity Enthusiast*
🔗 [LinkedIn Profile](https://www.linkedin.com/in/marwane-boujlida-14a816379)
🐙 [GitHub Repository](https://github.com/SVMUVRIx9/honeypy-honeypot)

---

## 🛡️ License

This project is released under the **MIT License**. Free to use, modify, and distribute for educational and research purposes.
