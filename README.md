# NetMon 🛡️

NetMon is a lightweight, real-time command-line network traffic analyzer and security monitor built with Python and Scapy. It is designed for cybersecurity students, network administrators, and junior pentesters to inspect live traffic, track protocol statistics, and detect basic network anomalies like TCP port scans.

## Features 🚀
- **Real-Time Packet Sniffing:** Captures TCP, UDP, ICMP, DNS, HTTP, HTTPS/TLS, and ARP traffic.
- **Traffic Statistics Dashboard:** Live tracking of packet counts per protocol.
- **Security Alerts:** Basic heuristic detection for potential TCP Port Scans.
- **File Logging:** Option to dump captured logs into a text file for post-analysis (`-o`).
- **Interactive TUI:** Clean terminal UI powered by the `rich` library.

## Installation ⚙️

1. Clone the repository:
   ```bash
   git clone https://github.com/rahimlii004-create/netmon
   cd netmon
