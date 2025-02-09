# 🚀 Internet Packet Sniffer - Advanced Network Traffic Analyzer 🔍

## 🌐 Overview

**Internet Packet Sniffer** is a high-performance **network traffic analyzer** for **Windows**. Built using **C++**, it captures live network packets, detects **malicious activities**, and integrates **GeoIP location tracking** with **PostgreSQL/PostGIS**. Designed for **cybersecurity professionals**, this tool helps analyze **DDoS attacks, port scans, TLS handshakes, and blocklisted IPs** in real-time.

## 🔥 Features

✅ **Live Packet Capture** - Monitors network packets in real-time using **Npcap**.\
✅ **DDoS & UDP Flood Detection** - Alerts when excessive traffic is detected.\
✅ **Port Scan Detection** - Identifies potential **reconnaissance** activities.\
✅ **Blocklisted IP Alerts** - Flags known malicious IP addresses.\
✅ **TLS/SSL Detection** - Detects encrypted connections.\
✅ **ICMP (Ping) Monitoring** - Identifies ping scans and network probing.\
✅ **GeoIP Lookup** - Determines the **geographical location** of IPs.\
✅ **JSON Logging** - Stores alerts for **post-analysis**.\
✅ **Portable & Lightweight** - Runs efficiently without additional dependencies.

## 🛠 Installation

### Prerequisites

- Windows 10/11 (64-bit)
- [Npcap](https://nmap.org/npcap/) (for packet capturing)
- [PostgreSQL](https://www.postgresql.org/) + [PostGIS](https://postgis.net/) (for GeoIP lookup) *(optional)*
- C++ Compiler (Clang64, MSVC, or MinGW)

### Step 1: Install Dependencies

1. **Install Npcap** (Ensure "WinPcap API-compatible mode" is checked).
2. **Install PostgreSQL & PostGIS** *(if using GeoIP detection)*.
3. Set PostgreSQL password as an environment variable:
   ```sh
   setx PG_PASSWORD "your_database_password"
   ```

### Step 2: Clone and Build

```sh
git clone https://github.com/yourusername/internet-packet-sniffer.git
cd internet-packet-sniffer
mkdir build && cd build
cmake ..
cmake --build .
```

## 🎯 Usage

Run the application with administrator privileges:

```sh
./packet_sniffer.exe
```

Example output:

```sh
[INFO] IP Layer:
Src IP: 192.168.1.10 (United States) -> Dest IP: 192.168.1.1
[ALERT] 🚨 Possible DDoS from: 203.0.113.5 (Packets: 105)
```

## 📜 Alert System

| Alert Type         | Severity    | Description                           |
| ------------------ | ----------- | ------------------------------------- |
| **DDoS Attack**    | 🔴 Critical | High packet rate detected             |
| **UDP Flood**      | 🔴 High     | Unusual UDP packet burst              |
| **Port Scan**      | 🟠 Medium   | Multiple connection attempts detected |
| **Blocklisted IP** | 🔴 Critical | Malicious IP detected                 |
| **TLS Handshake**  | 🟡 Medium   | Encrypted connection detected         |
| **ICMP Ping Scan** | 🟡 Low      | Possible reconnaissance               |

## 📂 Log Files

- `` - Stores security alerts in JSON format.
- **Packet Captures** - Saved in `Packet_Captures/` with timestamps.

## 🛡 Security Considerations

- **Run with admin privileges** to capture all packets.
- **Use a secure PostgreSQL connection** for GeoIP queries.

## 🚀 Future Enhancements

- 📌 **GUI Support** *(for better user experience)*
- 📌 **More Protocol Analysis** *(HTTP, DNS, etc.)*
- 📌 **Machine Learning-based Intrusion Detection**

## 🤝 Contributing

Want to improve this project? Contributions are welcome!

1. **Fork** the repository.
2. **Create a new branch**: `git checkout -b feature-branch`
3. **Commit your changes**: `git commit -m 'Add new feature'`
4. **Push to the branch**: `git push origin feature-branch`
5. **Create a Pull Request**

## 📜 License

This project is licensed under the **MIT License**.

## ❤️ Support & Feedback

⭐ **Star this repo** if you found it useful!\
🐛 **Report issues** via GitHub Issues.\
👥 **Join discussions** in the community.

---

🚀 *Internet Packet Sniffer - Empowering Cybersecurity Enthusiasts!* 🔥

