#pragma once

#include <pcap.h>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

// Ethernet header
struct EthernetHeader {
    u_char destMac[6];  // Destination MAC address
    u_char srcMac[6];   // Source MAC address
    u_short type;       // Type/Length field
};

// IPv4 header
struct IPv4Header {
    u_char  ver_ihl;    // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;        // Type of service 
    u_short tlen;       // Total length 
    u_short identification; // Identification
    u_short flags_fo;   // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;        // Time to live
    u_char  proto;      // Protocol
    u_short crc;        // Header checksum
    struct in_addr srcAddr; // Source address
    struct in_addr destAddr; // Destination address
};

// TCP header
struct TCPHeader {
    u_short srcPort;    // Source port
    u_short destPort;   // Destination port
    u_int   seqNum;     // Sequence Number
    u_int   ackNum;     // Acknowledgement number
    u_char  dataOffset; // Data offset + Reserved
    u_char  flags;      // Flags
    u_short window;     // Window
    u_short checksum;   // Checksum
    u_short urgPointer; // Urgent pointer
};

// UDP header
struct UDPHeader {
    u_short srcPort;    // Source port
    u_short destPort;   // Destination port
    u_short len;        // Datagram length
    u_short checksum;   // Checksum
};

// Protocol constants
#define ETHERNET_TYPE_IP 0x0800
#define ETHERNET_TYPE_ARP 0x0806
#define ETHERNET_TYPE_IPV6 0x86DD

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

// Helper functions for packet analysis
std::string getMacAddress(const u_char* macAddr);
std::string getIpAddress(const in_addr addr); 