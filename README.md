# 🛡️ LightEDR

![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

LightEDR is a lightweight, high-performance Digital Forensics and Incident Response (DFIR) & Threat Hunting Platform. Designed to quickly collect, analyze, and report on security events across systems.

## 🚀 Features

- **Artifact Collection**: Automatically collect process, network, service, event log, and registry data.
- **YARA Detection**: Scan files and processes using custom YARA rules.
- **Sigma Detection**: Detect anomalous behaviors using Sigma rules on event logs.
- **IOC Correlation**: Correlate artifacts with known Indicators of Compromise (hashes, IPs, domains).
- **MITRE ATT&CK Mapping**: Map alerts to MITRE ATT&CK tactics and techniques.
- **Risk Assessment**: Intelligent risk scoring engine for prioritizing alerts.
- **HTML/PDF Reports**: Generate comprehensive incident reports.
- **Real-time Dashboard**: Monitor endpoints and view alerts as they happen.

## 🏗️ Architecture

```text
[ Endpoint ] <---> [ Collector Engine ]
                          |
                          v
                   [ Analysis Engine ] <--- YARA / Sigma / IOCs
                          |
                          v
                   [ Risk Scorer ]
                          |
                          v
                  [ SQLite Database ]
                          |
                          v
            [ FastAPI Backend / Dashboard ]
```

## ⚡ Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/lightedr.git
   cd lightedr
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database:**
   ```bash
   python setup_db.py
   ```

5. **Run the application:**
   ```bash
   uvicorn app.main:app --reload
   ```

## 📁 Project Structure

```
LightEDR/
├── app/
│   ├── core/         # Core utilities, configuration, and logging
│   ├── database/     # SQLAlchemy models and database setup
│   ├── ...
├── config.yaml       # Application configuration
├── requirements.txt  # Python dependencies
├── setup_db.py       # Database initialization script
└── README.md         # Project documentation
```

## 🛠️ Technologies Used

| Component      | Technology |
| -------------- | ---------- |
| Backend        | FastAPI, Python 3.12 |
| Database       | SQLite, SQLAlchemy 2.0 |
| Validation     | Pydantic v2 |
| Forensics      | psutil, python-evtx, yara-python |
| UI/CLI         | Rich, Jinja2, WeasyPrint |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
