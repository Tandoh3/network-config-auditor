# 🔐 Network Config Auditor

A comprehensive **Streamlit application** for automated security auditing of network configuration files.  
This tool analyzes network device configurations, identifies security vulnerabilities, and generates detailed compliance reports.

---

## 🚀 Features

### 🔍 Security Analysis
- **7-Category Audit** – Comprehensive scanning across:
  - Layer 2 Security  
  - Access Control  
  - AAA (Authentication, Authorization & Accounting)  
  - Logging  
  - Cryptography  
  - Resilience  
  - Configuration Management  
- **Risk Scoring** – Automated High/Medium/Low/No Risk categorization  
- **Vulnerability Detection** – Identifies common misconfigurations and compliance gaps  

### 📊 Visual Analytics
- **Interactive Dashboard** – Real-time visualization of network security posture  
- **Risk Heatmaps** – Category-based vulnerability distribution across devices  
- **Risk Distribution Charts** – Visual representation of device risk levels  

### 🧾 Reporting & Export
- **Detailed Findings** – Comprehensive vulnerability listings with remediation guidance  
- **Professional Reports** – Generate management-ready **PDF** and **Word** documents  
- **Data Export** – Download results in **CSV** format for further analysis  
- **Device Summaries** – Color-coded risk assessment tables  

---

## 📥 Supported Input Formats
- **Text Files**: Individual configuration files (`.txt`)  
- **Archive Files**: ZIP and RAR archives *(currently under maintenance)*  

---

## ⚙️ Quick Start

### 🖥️ Local Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd network-config-auditor

2. **Install Dependencies** 
   ```bash
    pip install -r requirements.txt
   
Run the application

bash
Copy code
streamlit run app.py
💡 Usage
Upload Files – Select one or multiple network configuration files (.txt)

View Analysis – Review findings, risk summaries, and visual analytics

Export Reports – Download CSV data or professional PDF/Word reports

📦 Output Deliverables
Deliverable	Description
Security Findings	Detailed vulnerability analysis per device
Risk Assessment	Device-level risk scoring and categorization
Visual Analytics	Interactive charts and heatmaps
Management Reports	Professional PDF and DOCX reports
Exportable Data	CSV formats for integration with other tools

🔎 Security Categories Audited
Category	Checks Include
Layer 2 Security	DHCP snooping, ARP inspection, port security
Access Control	ACLs, SNMP communities, remote access protocols
Authentication & Authorization	AAA configuration, local credentials
Logging & Monitoring	Syslog, NTP, SNMPv3
Cryptographic Security	SSH, HTTPS, secure protocols
Resilience & Availability	HSRP/VRRP, storm control, spanning tree
Configuration Management	Password encryption, archiving, best practices

☁️ Deployment
Streamlit Cloud
Fork this repository

Visit Streamlit Cloud

Connect your GitHub repository

Set the main file path to app.py

📋 Requirements
Refer to requirements.txt for a complete dependency list:

nginx
Copy code
streamlit
pandas
matplotlib
seaborn
reportlab
python-docx
rarfile
📁 File Structure
bash
Copy code
network-config-auditor/
├── app.py                 # Main application file
├── requirements.txt       # Python dependencies
├── .streamlit/            # Streamlit configuration
│   └── config.toml
└── README.md              # Project documentation
🤝 Contributing
Contributions are welcome!
You can:

Add new security checks

Improve visualization and performance

Extend file format support

Please submit pull requests or open issues.

⚖️ License
This project is licensed under the MIT License — see the LICENSE file for details.

⚠️ Disclaimer
This tool is intended for security auditing and educational purposes only.
Always validate findings in your environment and consult with network security professionals before applying any configuration changes in production systems.

Maintainer: [Your Name / Organization]
Version: 1.0
Last Updated: 2024

yaml
Copy code
