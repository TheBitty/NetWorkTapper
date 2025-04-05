#include <iostream>
#include <pcap.h>
#include <string>
#include <ctime>
#include <iomanip>
#include "include/networkheader.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// Callback function for pcap_loop
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main() {
	// Initialize Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "Failed to initialize Winsock" << std::endl;
		return 1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0, inum;
	pcap_t *adhandle;
	
	// Find all devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
		WSACleanup();
		return 1;
	}
	
	// Print the list of network devices
	std::cout << "Network devices found:" << std::endl;
	for (d = alldevs; d; d = d->next) {
		std::cout << ++i << ". " << d->name;
		if (d->description)
			std::cout << " (" << d->description << ")";
		std::cout << std::endl;
	}
	
	if (i == 0) {
		std::cout << "No interfaces found! Make sure WinPcap/Npcap is installed." << std::endl;
		WSACleanup();
		return 1;
	}
	
	// Ask user which device to use
	std::cout << "Enter the interface number (1-" << i << "): ";
	std::cin >> inum;
	
	if (inum < 1 || inum > i) {
		std::cout << "Interface number out of range." << std::endl;
		pcap_freealldevs(alldevs);
		WSACleanup();
		return 1;
	}
	
	// Jump to the selected adapter
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	
	// Open the device
	adhandle = pcap_open_live(d->name,   // name of the device
							65536,      // portion of the packet to capture
							1,          // promiscuous mode
							1000,       // read timeout
							errbuf);    // error buffer
	
	if (adhandle == NULL) {
		std::cerr << "Unable to open the adapter. " << d->name << " is not supported by WinPcap/Npcap." << std::endl;
		pcap_freealldevs(alldevs);
		WSACleanup();
		return 1;
	}
	
	std::cout << "Listening on " << d->description << "..." << std::endl;
	
	// We don't need the device list anymore
	pcap_freealldevs(alldevs);
	
	// Set a filter to capture only IP traffic
	struct bpf_program fcode;
	char packet_filter[] = "ip";
	
	// Compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		std::cerr << "Unable to compile the packet filter. Check the syntax." << std::endl;
		pcap_close(adhandle);
		WSACleanup();
		return 1;
	}
	
	// Set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		std::cerr << "Error setting the filter." << std::endl;
		pcap_close(adhandle);
		WSACleanup();
		return 1;
	}
	
	std::cout << "Capturing packets... Press Ctrl+C to stop." << std::endl;
	
	// Start capturing packets
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	pcap_close(adhandle);
	WSACleanup();
	return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	
	// Convert the timestamp to readable format
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	std::cout << "Time: " << timestr << "." << header->ts.tv_usec << " Length: " << header->len << std::endl;
	
	// Parse the Ethernet header
	EthernetHeader *eth_header = (EthernetHeader *)pkt_data;
	
	// Print MAC addresses
	std::cout << "   MAC: " << getMacAddress(eth_header->srcMac) << " -> " 
			  << getMacAddress(eth_header->destMac) << std::endl;
	
	// Check if it's an IP packet
	if (ntohs(eth_header->type) == ETHERNET_TYPE_IP) {
		// Parse IP header
		IPv4Header *ip_header = (IPv4Header *)(pkt_data + sizeof(EthernetHeader));
		u_int ip_header_length = (ip_header->ver_ihl & 0x0f) * 4;
		
		std::cout << "   IP: " << getIpAddress(ip_header->srcAddr) << " -> " 
				  << getIpAddress(ip_header->destAddr) << std::endl;
		
		// Parse TCP/UDP header based on protocol
		if (ip_header->proto == IP_PROTO_TCP) {
			TCPHeader *tcp_header = (TCPHeader *)((u_char*)ip_header + ip_header_length);
			std::cout << "   TCP Port: " << ntohs(tcp_header->srcPort) << " -> " 
					  << ntohs(tcp_header->destPort) << std::endl;
		} 
		else if (ip_header->proto == IP_PROTO_UDP) {
			UDPHeader *udp_header = (UDPHeader *)((u_char*)ip_header + ip_header_length);
			std::cout << "   UDP Port: " << ntohs(udp_header->srcPort) << " -> " 
					  << ntohs(udp_header->destPort) << std::endl;
		}
	}
	
	std::cout << "----------------------------------------" << std::endl;
}