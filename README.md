ThreatLens 🛡️

Network Threat Detection & Investigation Platform

ThreatLens is a Python-based cybersecurity project that analyzes network traffic and detects suspicious activities using predefined security rules.

Features

- PCAP file upload and network traffic analysis
- Detection of unusual destination ports
- Detection of repeated TCP connection attempts
- Possible port scan detection
- Interactive security dashboard
- Network protocol and IP address statistics
- Incident history using SQLite database
- CSV export of alerts

Technologies Used

- Python
- Streamlit
- Scapy
- Pandas
- Plotly
- SQLite

Project Structure

ThreatLens/
├── app.py
├── analyzer.py
├── detector.py
├── database.py
├── generate_sample.py
├── sample_traffic.pcap
├── requirements.txt
└── README.md

Installation

1. Clone the Repository

git clone YOUR_GITHUB_REPOSITORY_URL
cd ThreatLens

2. Create a Virtual Environment

python -m venv .venv

3. Activate the Environment

For Windows Command Prompt:

.venv\Scripts\activate

4. Install Dependencies

pip install -r requirements.txt

5. Run the Application

streamlit run app.py

How It Works

1. Upload a PCAP file containing network traffic.
2. Analyze packet counts, protocols and IP addresses.
3. Identify suspicious traffic using predefined detection rules.
4. Review alerts in the dashboard.
5. Save incidents and export alert information as a CSV file.

Detection Rules

Unusual Destination Port: Flags traffic involving configured ports such as 4444, 5555, 6667 and 31337.

Repeated Connection Attempts: Detects repeated TCP SYN attempts that meet the configured threshold.

Possible Port Scan: Identifies a source IP addressing multiple destination ports on the same destination IP.

Limitations

ThreatLens is an educational cybersecurity prototype using rule-based detection. Alerts indicate potentially suspicious activity and do not independently confirm an attack. Detection capabilities are limited to the implemented rules.

Disclaimer

Use this application only with network traffic you are authorized to analyze.

Author

Shrisha Gujar
BE Information Technology Student