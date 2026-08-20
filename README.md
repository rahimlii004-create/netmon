# 🛡️ NetMon

### Real-Time CLI Network Traffic Analyzer & Security Monitor

NetMon is a lightweight, high-performance command-line network traffic analyzer and security monitoring tool built with **Python** and **Scapy**.

It allows cybersecurity students, network administrators, and junior penetration testers to monitor live network traffic, inspect packets, analyze protocol distribution, and detect basic network anomalies directly from the terminal.

---

## ✨ Features

* 🔍 **Real-Time Packet Sniffing**

  * TCP
  * UDP
  * ICMP
  * DNS
  * HTTP
  * HTTPS / TLS
  * ARP

* 🚨 **Basic Anomaly Detection**

  * TCP port scan detection
  * Suspicious traffic/flood patterns
  * Basic connection-rate analysis

* 📊 **Protocol Statistics**

  * Live protocol counters
  * Traffic distribution
  * Percentage-based statistics

* 📝 **Logging & Export**

  * Save captured traffic information
  * Export security alerts
  * Structured log output

* 🎯 **BPF Filtering**

  * Supports standard Berkeley Packet Filter syntax
  * Capture only the traffic you need

* ⚡ **CLI-Based**

  * Lightweight terminal interface
  * No GUI overhead
  * Suitable for Linux security labs and testing environments

---

## 🧰 Technologies

| Technology  | Purpose                      |
| ----------- | ---------------------------- |
| Python 3.8+ | Core programming language    |
| Scapy       | Packet sniffing and analysis |
| Rich        | Terminal UI and formatting   |
| BPF         | Packet filtering             |

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/rahimlii004-create/netmon.git
cd netmon
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ⚠️ Privileges

NetMon uses packet-capture functionality that may require elevated privileges.

On Linux:

```bash
sudo ./venv/bin/python netmon.py
```

On Windows, run the terminal as **Administrator** and make sure the required packet-capture components are installed.

---

## 🚀 Usage

```bash
sudo ./venv/bin/python netmon.py [OPTIONS]
```

### Command-Line Options

| Short | Long          | Description                       |
| ----- | ------------- | --------------------------------- |
| `-i`  | `--interface` | Network interface to monitor      |
| `-f`  | `--filter`    | BPF packet filter                 |
| `-o`  | `--output`    | Save logs to a file               |
| `-v`  | `--verbose`   | Enable detailed packet inspection |
| `-h`  | `--help`      | Display help information          |

---

## 💻 Examples

### Basic network monitoring

```bash
sudo ./venv/bin/python netmon.py -i eth0
```

### Monitor a wireless interface

```bash
sudo ./venv/bin/python netmon.py -i wlan0
```

### Capture HTTP traffic

```bash
sudo ./venv/bin/python netmon.py -i eth0 -f "tcp port 80"
```

### Monitor HTTPS traffic

```bash
sudo ./venv/bin/python netmon.py -i eth0 -f "tcp port 443"
```

### Save monitoring results

```bash
sudo ./venv/bin/python netmon.py -i eth0 -o security_logs.txt
```

### Enable verbose analysis

```bash
sudo ./venv/bin/python netmon.py -i wlan0 -v
```

### Combine filtering, logging and verbose mode

```bash
sudo ./venv/bin/python netmon.py \
    -i eth0 \
    -f "tcp" \
    -o security_logs.txt \
    -v
```

---

## 🔎 BPF Filtering

NetMon supports standard **Berkeley Packet Filter (BPF)** syntax.

Examples:

```text
tcp
```

Capture TCP traffic.

```text
udp
```

Capture UDP traffic.

```text
icmp
```

Capture ICMP traffic.

```text
arp
```

Capture ARP traffic.

```text
tcp port 80
```

Capture HTTP traffic.

```text
tcp port 443
```

Capture HTTPS traffic.

```text
host 192.168.1.10
```

Capture traffic involving a specific host.

You can combine filters using operators such as `and`, `or`, and `not`.

Example:

```text
tcp and port 443
```

---

## 📊 Detection Capabilities

NetMon currently focuses on lightweight heuristic detection rather than full IDS functionality.

### TCP Port Scan Detection

The tool monitors TCP connection patterns and can identify behavior consistent with port scanning, such as:

```text
Single Source
     │
     ├── TCP → Port 21
     ├── TCP → Port 22
     ├── TCP → Port 23
     ├── TCP → Port 80
     ├── TCP → Port 443
     └── TCP → Port 8080
              │
              ▼
       Suspicious Pattern
              │
              ▼
         Security Alert
```

Detection is heuristic and should not be treated as definitive proof of malicious activity.

---

## 📁 Project Structure

```text
netmon/
│
├── netmon.py
├── requirements.txt
├── README.md
├── .gitignore
│
└── logs/
    └── .gitkeep
```

### File Description

| File               | Description                          |
| ------------------ | ------------------------------------ |
| `netmon.py`        | Main application                     |
| `requirements.txt` | Python dependencies                  |
| `.gitignore`       | Ignored files and directories        |
| `README.md`        | Project documentation                |
| `logs/`            | Optional directory for exported logs |

---

## 🧪 Recommended Testing Environment

For safe testing, NetMon should be used in an environment where you have explicit authorization to monitor traffic.

Recommended environments include:

* 🖥️ Local Linux machine
* 🧪 Virtual machines
* 🔬 Isolated cybersecurity labs
* 🌐 Personal test networks
* 🎯 Authorized penetration-testing environments

For example:

```text
┌──────────────────────┐
│      Test Network    │
│                      │
│  ┌──────┐  ┌──────┐  │
│  │ Kali │  │ Lab  │  │
│  │ NetMon│ │ VM   │  │
│  └──────┘  └──────┘  │
│       │        │     │
│       └───┬────┘     │
│           │          │
│        Network       │
└──────────────────────┘
```

---

## ⚠️ Best Practices

### Use a Virtual Environment

Keep project dependencies isolated:

```bash
python3 -m venv venv
source venv/bin/activate
```

### Monitor a Specific Interface

Instead of capturing everything, specify the interface you want:

```bash
sudo ./venv/bin/python netmon.py -i eth0
```

Common interfaces include:

```text
eth0
wlan0
tun0
lo
```

### Manage Log Files

Long-running captures can generate large log files. Monitor disk usage when using:

```bash
-o security_logs.txt
```

---

## 🔐 Legal & Ethical Use

NetMon is intended for **authorized security monitoring, education, and testing**.

Only capture or inspect network traffic on systems and networks that you own or have explicit permission to monitor.

The author is not responsible for misuse of this software.

---

## 🛣️ Roadmap

Potential future improvements:

* [ ] Advanced port-scan detection
* [ ] SYN flood detection
* [ ] UDP flood detection
* [ ] DNS anomaly detection
* [ ] ARP spoofing detection
* [ ] IP reputation integration
* [ ] JSON log export
* [ ] PCAP export
* [ ] Configurable detection thresholds
* [ ] Live Rich dashboard
* [ ] Alert severity levels
* [ ] Modular detection engine
* [ ] Unit and integration tests

---

## 🤝 Contributing

Contributions, bug reports, and feature suggestions are welcome.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test your changes
5. Submit a pull request

Example:

```bash
git checkout -b feature/new-detector
```

---


---

## ⭐ Support

If you find NetMon useful for learning or security research, consider giving the repository a ⭐ on GitHub.
