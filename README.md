# 🚀 Internet Packet Sniffer - Network Traffic Analyzer

## 🌐 Overview
Internet Packet Sniffer is a powerful network traffic analyzer for Windows, built with C++. It captures live network packets, detects malicious activities, and integrates GeoIP tracking using PostgreSQL/PostGIS. This tool is designed for cybersecurity professionals to analyze DDoS attacks, port scans, TLS handshakes, and blocklisted IPs in real-time.

## 🔥 Features
✅ **Live Packet Capture** - Monitors network packets in real-time using Npcap.  
✅ **DDoS & UDP Flood Detection** - Alerts when excessive traffic is detected.  
✅ **Port Scan Detection** - Identifies potential reconnaissance activities.  
✅ **Blocklisted IP Alerts** - Flags known malicious IP addresses.  
✅ **TLS/SSL Detection** - Detects encrypted connections.  
✅ **ICMP (Ping) Monitoring** - Identifies ping scans and network probing.  
✅ **GeoIP Lookup** - Determines the geographical location of IPs.  
✅ **JSON Logging** - Stores alerts for post-analysis.  
✅ **Portable & Lightweight** - Runs efficiently without additional dependencies.  

---
## 🛠 Installation

### **Prerequisites**
- **Windows 10/11 (64-bit)**
- **Npcap** (for packet capturing)
- **PostgreSQL + PostGIS** *(optional, for GeoIP lookup)*
- **C++ Compiler** *(Clang64, MSVC, or MinGW)*

### **Step 1: Install Dependencies**
1. Install **Npcap** (Ensure *"WinPcap API-compatible mode"* is checked).
2. Install **PostgreSQL** and **PostGIS** (if using GeoIP detection).
3. Set PostgreSQL password as an environment variable:
   ```cmd
   setx PG_PASSWORD "your_database_password"
   ```

### **Step 2: Setup the GeoIP Database (Optional but Recommended)**
If you want GeoIP tracking, you need to:

1. **Download** GeoLite2 databases (City, Country, ASN) from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. **Create a PostgreSQL database and tables**:
   ```sql
   CREATE DATABASE geoip;
   \c geoip;
   CREATE EXTENSION postgis;
   
   CREATE TABLE geoip_city (
       network CIDR PRIMARY KEY,
       geoname_id INT,
       registered_country_geoname_id INT,
       represented_country_geoname_id INT,
       is_anonymous_proxy BOOLEAN,
       is_satellite_provider BOOLEAN
   );

   CREATE TABLE geoip_asn (
       network CIDR PRIMARY KEY,
       autonomous_system_number INT,
       autonomous_system_organization TEXT
   );

   CREATE TABLE geoname_location (
       geoname_id INT PRIMARY KEY,
       locale_code TEXT,
       continent_name TEXT,
       country_name TEXT,
       subdivision_name TEXT,
       city_name TEXT,
       metro_code INT,
       time_zone TEXT
   );
   ```
3. **Import GeoIP data** from CSV files into the respective tables.

### **Step 3: Clone and Build**
```cmd
git clone https://github.com/yourusername/internet-packet-sniffer.git
cd internet-packet-sniffer
mkdir build && cd build
cmake ..
cmake --build .
```

---
## 🎯 Usage
Run the application with administrator privileges:
```cmd
./packet_sniffer.exe
```
Example output:
```log
[INFO] IP Layer:
Src IP: 192.168.1.10 (United States) -> Dest IP: 192.168.1.1
[ALERT] 🚨 Possible DDoS from: 203.0.113.5 (Packets: 105)
```

---
## 🌟 Alert System
| Alert Type       | Severity   | Description                           |
|-----------------|-----------|---------------------------------------|
| DDoS Attack     | 🔴 Critical | High packet rate detected             |
| UDP Flood       | 🔴 High     | Unusual UDP packet burst              |
| Port Scan       | 🟠 Medium   | Multiple connection attempts detected |
| Blocklisted IP  | 🔴 Critical | Malicious IP detected                 |
| TLS Handshake   | 🟡 Medium   | Encrypted connection detected         |
| ICMP Ping Scan  | 🟡 Low      | Possible reconnaissance               |

---
## 📂 Log Files
- **Security Alerts** - Stored in JSON format.
- **Packet Captures** - Saved in `Packet_Captures/` with timestamps.

---
## 🛡 Security Considerations
- Run with **admin privileges** to capture all packets.
- Use a **secure PostgreSQL connection** for GeoIP queries.

---
## 🚀 Future Enhancements
- 📌 **GUI Support** (for better user experience)
- 📌 **More Protocol Analysis** (HTTP, DNS, etc.)
- 📌 **Machine Learning-based Intrusion Detection**

---
## 🤝 Contributing
Want to improve this project? Contributions are welcome!
1. Fork the repository.
2. Create a new branch:
   ```cmd
   git checkout -b feature-branch
   ```
3. Commit your changes:
   ```cmd
   git commit -m 'Add new feature'
   ```
4. Push to the branch:
   ```cmd
   git push origin feature-branch
   ```
5. Create a Pull Request.

---
## 🐝 License
This project is licensed under the **MIT License**.

---
## ❤️ Support & Feedback
🌟 **Star this repo** if you found it useful!  
🐛 **Report issues** via GitHub Issues.  
🤝 **Join discussions** in the community.

---
🚀 **Internet Packet Sniffer - Empowering Cybersecurity Enthusiasts!** 🔥

