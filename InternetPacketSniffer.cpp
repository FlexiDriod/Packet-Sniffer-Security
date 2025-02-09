/*
& ==================================================
^   Project - Internet Packet Sniffer Tool
^   Author  - SUdip Howlader (FlexiDroid)
^   Database - PostgreSQL
& ==================================================
*/

#include <pcap.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <windows.h>
#include <memory>
#include <string>
#include <cstdlib> // for getenv
#include <ctime>
#include <csignal>
#include <unordered_set>
#include <map>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <libpq-fe.h> // PostgreSQL C API
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

using json = nlohmann::json;

/*
    &  Global variables
*/

#define RESET "\033[0m"
#define RED "\033[1;31m"
#define YELLOW "\033[1;33m"
#define GREEN "\033[1;32m"
#define BLUE "\033[1;34m"
#define CYAN "\033[1;36m"    // Cyan for Source IP
#define MAGENTA "\033[1;35m" // Magenta for Destination IP

pcap_t *globalHandle = nullptr;
pcap_dumper_t *dumpFile = nullptr;
std::unordered_set<std::string> blocklist;
std::map<std::string, int> connectionCounts;
std::map<std::string, time_t> lastSeen;
const int PORT_SCAN_THRESHOLD = 10;
const int TIME_WINDOW = 10;
const char *password = nullptr;
const int RATE_LIMIT_THRESHOLD = 1000; //^ Maximum packets per second
std::unordered_map<std::string, int> rateLimitCounts;
std::unordered_map<std::string, time_t> rateLimitTime;
std::unordered_map<std::string, int> packetCounts;
std::unordered_map<std::string, time_t> firstPacketTime;
const int PACKET_THRESHOLD = 100; //^ 🚨 Detects DDoS if an IP sends >100 packets in 10 sec
const int TIME_WINDOW_SEC = 10;
std::unordered_map<std::string, int> udpPacketCounts;
std::unordered_map<std::string, time_t> udpFirstPacketTime;
const int UDP_PACKET_THRESHOLD = 150;

void enableANSI()
{
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (hStdout == INVALID_HANDLE_VALUE)
        return;
    if (!GetConsoleMode(hStdout, &dwMode))
        return;
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hStdout, dwMode);
}

// Network packet structures
struct EthernetHeader
{
    u_char dest[6], src[6];
    u_short type;
};

struct IpHeader
{
    u_char versionHeaderLength, tos;
    u_short totalLength, id, offset;
    u_char ttl, protocol;
    u_short checksum;
    struct in_addr src, dest;
};

struct TcpHeader
{
    u_short srcPort, destPort;
    u_int seq, ack;
    u_char offsetRes, flags;
    u_short window, checksum, urgent;
};

struct UdpHeader
{
    u_short srcPort;
    u_short destPort;
    u_short length;
    u_short checksum;
};

struct IcmpHeader
{
    u_char type; // ICMP message type
    u_char code; // ICMP code
    u_short checksum;
    u_short id;
    u_short sequence;
};

// Create directory if it doesn't exist
bool createDirectoryIfNotExists(const std::string &dirPath)
{
    DWORD ftyp = GetFileAttributesA(dirPath.c_str());
    if (ftyp == INVALID_FILE_ATTRIBUTES)
    {
        // Directory doesn't exist, try creating it
        if (CreateDirectoryA(dirPath.c_str(), NULL) != 0)
        {
            std::cout << "[INFO] Directory created: " << dirPath << std::endl;
            return true;
        }
        else
        {
            std::cerr << "[ERROR] Failed to create directory: " << dirPath << std::endl;
            return false;
        }
    }
    std::cout << "[INFO] Directory already exists: " << dirPath << std::endl;
    return true;
}

void logAlertToJson(const json &alert)
{
    std::ofstream file("alerts.json", std::ios::app);
    if (file)
    {
        file << alert.dump(4) << ",\n";
    }
    else
    {
        std::cerr << "[!] Failed to open alerts.json for writing!\n";
    }
}

// Query GeoIP database for country information
std::string queryGeoIP(const std::string &ip)
{
    std::string connStr = "dbname=geoip user=postgres password=" + std::string(password) + " host=localhost";
    PGconn *conn = PQconnectdb(connStr.c_str());

    if (PQstatus(conn) != CONNECTION_OK)
    {
        std::cerr << "[!] PostgreSQL connection failed: " << PQerrorMessage(conn) << "\n";
        PQfinish(conn);
        return "Unknown";
    }

    std::string query = "SELECT g.country_name FROM geoip_country gc "
                        "JOIN geoname_location g ON gc.geoname_id = g.geoname_id "
                        "WHERE gc.network >>= '" +
                        ip + "' LIMIT 1;";

    PGresult *res = PQexec(conn, query.c_str());
    std::string country = (PQntuples(res) > 0) ? PQgetvalue(res, 0, 0) : "Unknown";

    PQclear(res);
    PQfinish(conn);
    return country;
}

bool isRateLimited(const std::string &ip)
{
    time_t currentTime = std::time(nullptr);
    if (rateLimitTime.find(ip) == rateLimitTime.end() || currentTime - rateLimitTime[ip] > 1)
    {
        rateLimitTime[ip] = currentTime;
        rateLimitCounts[ip] = 0;
    }
    rateLimitCounts[ip]++;

    if (rateLimitCounts[ip] > RATE_LIMIT_THRESHOLD)
    {
        std::cout << "[DEBUG] Rate-limiting IP: " << ip << std::endl;
        return true;
    }
    return false;
}

void detectUdpFlood(const std::string &srcIp)
{
    time_t currentTime = std::time(nullptr);

    if (udpFirstPacketTime.find(srcIp) == udpFirstPacketTime.end())
    {
        udpFirstPacketTime[srcIp] = currentTime;
        udpPacketCounts[srcIp] = 1;
    }
    else
    {
        udpPacketCounts[srcIp]++;
        if (currentTime - udpFirstPacketTime[srcIp] <= TIME_WINDOW_SEC)
        {
            if (udpPacketCounts[srcIp] > UDP_PACKET_THRESHOLD)
            {
                json alert = {
                    {"timestamp", std::time(nullptr)},
                    {"alert_type", "Possible UDP Flood"},
                    {"source_ip", srcIp},
                    {"packet_count", udpPacketCounts[srcIp]},
                    {"severity", "High"},
                    {"description", "Excessive UDP packets detected in short time."}};
                logAlertToJson(alert);
                std::cout << RED "[ALERT] 🚨 Possible UDP Flood from: " << srcIp << " (Packets: " << udpPacketCounts[srcIp] << ")" RESET "\n";
            }
        }
        else
        {
            udpFirstPacketTime[srcIp] = currentTime;
            udpPacketCounts[srcIp] = 1;
        }
    }
}

//^ 🚀 Function to detect DDoS
void detectDDoS(const std::string &srcIp)
{
    time_t currentTime = std::time(nullptr);

    if (firstPacketTime.find(srcIp) == firstPacketTime.end())
    {
        firstPacketTime[srcIp] = currentTime;
        packetCounts[srcIp] = 1;
    }
    else
    {
        packetCounts[srcIp]++;
        if (currentTime - firstPacketTime[srcIp] <= TIME_WINDOW_SEC)
        {
            if (packetCounts[srcIp] > PACKET_THRESHOLD)
            {
                json alert = {
                    {"timestamp", std::time(nullptr)},
                    {"alert_type", "Possible DDoS Attack"},
                    {"source_ip", srcIp},
                    {"packet_count", packetCounts[srcIp]},
                    {"severity", "Critical"},
                    {"description", "High number of packets in a short time"}};
                logAlertToJson(alert);
                std::cout << RED "[ALERT] 🚨 Possible DDoS from: " << srcIp
                          << " (Packets: " << packetCounts[srcIp] << ")" RESET "\n";
            }
        }
        else
        {
            firstPacketTime[srcIp] = currentTime;
            packetCounts[srcIp] = 1;
        }
    }
}

//^ Detect TLS handshake
void detectTlsHandshake(const u_char *packet, int ipHeaderLen, int totalPacketLen)
{
    if (totalPacketLen < 14 + ipHeaderLen + sizeof(TcpHeader) + 6)
        return;
    TcpHeader *tcp = (TcpHeader *)(packet + 14 + ipHeaderLen);
    int tcpHeaderLen = (tcp->offsetRes >> 4) * 4;
    const u_char *payload = packet + 14 + ipHeaderLen + tcpHeaderLen;

    if (payload[0] == 0x16 && payload[5] == 0x01)
    { // TLS handshake detection
        json alert = {
            {"timestamp", std::time(nullptr)},
            {"alert_type", "TLS Handshake Detected"},
            {"description", "Possible encrypted traffic detected."},
            {"severity", "Medium"}};
        logAlertToJson(alert);
        std::cout << "[ALERT] TLS Handshake detected!\n";
    }
}

//^ Function to generate timestamped filename
std::string getTimestampedFilename()
{
    // Get current time
    std::time_t now = std::time(nullptr);
    if (now == -1)
    {
        std::cerr << "[ERROR] Unable to retrieve local time." << std::endl;
        return ""; // Return empty string if time retrieval fails
    }

    // Use stringstream with std::put_time
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now), "%Y-%m-%d_%H-%M-%S.pcap");

    std::string filename = ss.str();

    // Debugging: print filename
    std::cout << "[INFO] Generated timestamp filename: " << filename << std::endl;

    // Replace any characters that are invalid in Windows filenames (e.g. \ / : * ? " < > |)
    std::string invalidChars = "\\/:*?\"<>|";
    for (char &c : filename)
    {
        if (invalidChars.find(c) != std::string::npos)
        {
            c = '-'; // Replace invalid characters with '-'
        }
    }

    // Define the base directory path
    std::string baseDir = "D:\\Problem_Solving\\C_plus_plus\\Packet_Captures";

    // Ensure that the directory exists before trying to write the file
    if (!createDirectoryIfNotExists(baseDir))
    {
        std::cerr << "[ERROR] Directory creation failed." << std::endl;
        return ""; // Return empty string if directory creation fails
    }

    // Combine the base directory with the filename
    std::string fullPath = baseDir + "\\" + filename;

    // Debugging: print full path to check for issues
    std::cout << "[INFO] Full file path: " << fullPath << std::endl;

    // Return the full path with the filename
    return fullPath;
}

void processUdpPacket(const u_char *packet, int ipHeaderLen, const std::string &srcIp)
{
    UdpHeader *udp = (UdpHeader *)(packet + 14 + ipHeaderLen);
    detectUdpFlood(srcIp);
}

//* Function to convert MAC address bytes into readable format (XX:XX:XX:XX:XX:XX)
// std::string formatMacAddress(const u_char *mac)
// {
//     std::ostringstream oss;
//     for (int i = 0; i < 6; i++)
//     {
//         oss << std::hex << std::setw(2) << std::setfill('0') << (int)mac[i];
//         if (i < 5)
//             oss << ":"; // Add colon between bytes
//     }
//     return oss.str();
// }

//*  Packet handler function
void packetHandler(u_char *, const struct pcap_pkthdr *header, const u_char *packet)
{
    std::cout << "[DEBUG] Packet captured! Size: " << header->len << " bytes" << std::endl;
    EthernetHeader *eth = (EthernetHeader *)packet;
    if (ntohs(eth->type) != 0x0800)
        return; // Only process IPv4 packets

    // Convert source and destination MAC addresses to readable format
    // std::string srcMac = formatMacAddress(eth->src);
    // std::string destMac = formatMacAddress(eth->dest);

    // std::cout << GREEN "[INFO] Ethernet Frame:" RESET << std::endl;
    // std::cout << "   Source MAC: " << formatMacAddress(eth->src)
    //           << "    ->    Destination MAC: " << formatMacAddress(eth->dest) << std::endl;

    IpHeader *ip = (IpHeader *)(packet + 14);
    char srcIp[INET_ADDRSTRLEN], destIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->src, srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->dest, destIp, INET_ADDRSTRLEN);

    if (isRateLimited(srcIp))
    {
        return;
    }

    std::string country = queryGeoIP(srcIp);
    // std::cout << "Src: " << srcIp << " (" << country << ") -> Dst: " << destIp << "\n";
    std::cout << BLUE "[INFO] IP Layer:" RESET << std::endl;
    std::cout << "Src IP: " << CYAN << srcIp << "(" << country << ")" << RESET << " ->  Dest IP: " << MAGENTA << destIp << RESET << std::endl;

    // printFormattedOutput(srcIp, destIp, srcMac, destMac, country);

    detectDDoS(srcIp); //^ 🚀 Call DDoS Detection function

    //^ 🚨 Blocklisted IP alert
    if (blocklist.find(srcIp) != blocklist.end())
    {
        json alert = {
            {"timestamp", std::time(nullptr)},
            {"alert_type", "Blocklisted IP"},
            {"source_ip", srcIp},
            {"severity", "Critical"}};
        logAlertToJson(alert);
        std::cout << "[ALERT] Blocklisted IP: " << srcIp << "\n";
    }

    //^ 🔵 ICMP Detection (Ping Detection)
    if (ip->protocol == IPPROTO_ICMP)
    {
        IcmpHeader *icmp = (IcmpHeader *)(packet + 14 + ((ip->versionHeaderLength & 0x0F) * 4));

        if (icmp->type == 8)
        { // ICMP Echo Request (Ping)
            json alert = {
                {"timestamp", std::time(nullptr)},
                {"alert_type", "ICMP Echo Request (Ping)"},
                {"source_ip", srcIp},
                {"destination_ip", destIp},
                {"severity", "Low"},
                {"description", "Potential reconnaissance or network scan"}};
            logAlertToJson(alert);
            std::cout << YELLOW "[ALERT] Ping detected from: " << srcIp << RESET "\n";
        }
        else if (icmp->type == 0)
        { // ICMP Echo Reply
            std::cout << BLUE "[INFO] Ping Reply from: " << srcIp << RESET "\n";
        }
    }

    /*
    ^ 🔴 TCP Detection (TLS, Attacks, Port Scans)
    */
    if (ip->protocol == IPPROTO_TCP)
    {
        detectTlsHandshake(packet, (ip->versionHeaderLength & 0x0F) * 4, header->caplen);
    }

    if (ip->protocol == IPPROTO_UDP)
    {
        processUdpPacket(packet, (ip->versionHeaderLength & 0x0F) * 4, srcIp);
    }
}

// Signal handler for cleanup
void signalHandler(int signum)
{
    if (globalHandle)
    {
        pcap_breakloop(globalHandle);
        pcap_close(globalHandle);
    }
    if (dumpFile)
    {
        pcap_dump_close(dumpFile);
    }
    std::cout << "\n[INFO] Capture stopped.\n";
    exit(signum);
}

void checkPostgresPassword()
{
    password = std::getenv("PG_PASSWORD");
    if (!password)
    {
        std::cerr << "[!] PostgreSQL password not set. Exiting.\n";
        exit(EXIT_FAILURE);
    }
}

int main()
{
    try
    {
        std::cout << "[DEBUG] Calling enableANSI()..." << std::endl;
        enableANSI();
        std::cout << "\033[1;32m[DEBUG] ANSI Enabled Successfully!\033[0m" << std::endl;
        checkPostgresPassword();

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs, *device;

        // Find all network devices
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            throw std::runtime_error("Error finding devices: " + std::string(errbuf));
        }

        int i = 0;
        for (device = alldevs; device; device = device->next)
        {
            std::cout << ++i << ". " << (device->description ? device->description : "Unknown device") << "\n";
        }

        int choice;
        std::cout << "Select a device: ";
        std::cin >> choice;

        device = alldevs;
        for (i = 1; i < choice && device; device = device->next, i++)
            ;
        if (!device)
            throw std::runtime_error("Invalid device selection.");

        std::cout << "Using: " << device->name << "\n";

        std::unique_ptr<pcap_t, decltype(&pcap_close)> handle(
            pcap_open_live(device->name, 65536, 1, 1000, errbuf), pcap_close);
        if (!handle)
            throw std::runtime_error("Cannot open device: " + std::string(errbuf));

        globalHandle = handle.get();
        signal(SIGINT, signalHandler);

        std::string filename = getTimestampedFilename();
        if (!filename.empty())
        {
            std::cout << "[INFO] Saving capture to: " << filename << std::endl;
            // Now you can use filename to save your packet capture
        }
        else
        {
            std::cerr << "[ERROR] Failed to generate filename." << std::endl;
        }

        dumpFile = pcap_dump_open(globalHandle, filename.c_str());
        if (dumpFile == nullptr)
        {
            std::cerr << "[ERROR] Failed to open dump file: " << filename << std::endl;
            return 1;
        }

        int res = pcap_loop(handle.get(), 0, packetHandler, (unsigned char *)dumpFile);
        if (res < 0)
        {
            std::cerr << "[ERROR] Error capturing packets: " << pcap_geterr(globalHandle) << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}