/**
 * @file: anti_arpspoof.cpp
 * @author Ricardo Román <https://telegram.me/reroman
 * 
 * Tool to detect ARP spoofing
 */
 
/* 
 * Compilation:
 * 	g++ -o anti_arpspoof anti_arpspoof.cpp -std=c++11
 * or
 * 	make anti_arpspoof CXXFLAGS=-std=c++11	
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.* 
 */

#include <iostream>
#include <iomanip>
#include <map>
#include <set>
#include <string>
#include <sstream>
#include <stdexcept>
#include <atomic>
using namespace std;

#include <cstring>
#include <cerrno>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

#define MAC_ADDR_LEN	6
#define IP_ADDR_LEN		4
#define IP_ONE		htonl( 1 )
#define MAX_TRIES_FOR_RESOLV	5

// ===============================
// Global variables
// ===============================
atomic<bool> active( true ); /// To control the analysis



// ===============================
// Data types
// ===============================

/**
 * Stores a MAC Address
 */
struct HWAddr{
	uint8_t hw[MAC_ADDR_LEN];

	HWAddr( const uint8_t m[] ){
		memcpy( hw, m, MAC_ADDR_LEN );
	}

	bool operator < ( const HWAddr &m ) const {
		return memcmp( hw, m.hw, MAC_ADDR_LEN ) < 0;
	}

	string toString() const {
		ostringstream out;

		out << hex << setfill( '0' ) << setw( 2 );
		for( int i = 0 ; i < MAC_ADDR_LEN ; ){
			out << static_cast<int>( hw[i] );
			if( hw[i] == 0 )
				out << 0;
			if( ++i != MAC_ADDR_LEN )
				out << ':';
		}
		return out.str();
	}

};

struct ARPFrame{
	uint8_t		eth_dst[MAC_ADDR_LEN];
	uint8_t		eth_src[MAC_ADDR_LEN];
	uint16_t	eth_ethertype;
	uint16_t	hw_type;
	uint16_t	protocol;
	uint8_t		hw_len;
	uint8_t		proto_len;
	uint16_t	opcode;
	uint8_t		hw_src[MAC_ADDR_LEN];
	uint32_t	ip_src;
	uint8_t		hw_dst[MAC_ADDR_LEN];
	uint32_t	ip_dst;
} __attribute__((__packed__));

typedef map< HWAddr, struct in_addr> ARPTable;

/** Stores some info about the netdevice */
struct LocalData{
	int ifindex;
	uint32_t ipAddr;
	uint32_t firstHost;
	uint32_t lastHost;
	uint8_t hwAddr[MAC_ADDR_LEN];
};


// ===============================
// Functions
// ===============================

/** Get the local data of the netdevice */
LocalData loadLocalData( const char *ifname ) throw( runtime_error ) 
{
	struct ifreq nic;
	int sock = socket( AF_INET, SOCK_STREAM, 0 );
	LocalData data;

	strncpy( nic.ifr_name, ifname, IFNAMSIZ-1 );
	nic.ifr_name[IFNAMSIZ-1] = '\0';

	// Index
	if( ioctl( sock, SIOCGIFINDEX, &nic ) < 0 ){
		close( sock );
		throw runtime_error( string(ifname) + ": " + string(strerror(errno)) );
	}
	data.ifindex = nic.ifr_ifindex;

	// IP Address
	if( ioctl( sock, SIOCGIFADDR, &nic ) < 0 ){
		close( sock );
		throw runtime_error( "Getting IP Address: " + string(strerror(errno)) );
	}
	memcpy( &data.ipAddr, nic.ifr_addr.sa_data + 2, IP_ADDR_LEN );

	// Hw Address
	if( ioctl( sock, SIOCGIFHWADDR, &nic ) < 0 ){
		close( sock );
		throw runtime_error( "Getting HW Address: " + string(strerror(errno)) );
	}
	memcpy( data.hwAddr, nic.ifr_netmask.sa_data, MAC_ADDR_LEN );

	// Broadcast for last host
	if( ioctl( sock, SIOCGIFBRDADDR, &nic ) < 0 ){
		close( sock );
		throw runtime_error( "Getting Broadcast: " + string(strerror(errno)) );
	}
	memcpy( &data.lastHost, nic.ifr_broadaddr.sa_data + 2, IP_ADDR_LEN );

	// First host from the network IP
	struct in_addr aux = { data.ipAddr };
	data.firstHost = inet_netof( aux );
	data.firstHost = (htonl( data.firstHost ) >> 8) + IP_ONE;

	return data;
}

/** Creates a socket for ARP frames */
int initSocket( int ifindex ) throw( runtime_error )
{
	int sockfd;
	struct sockaddr_ll sll;
	struct timeval timer;

	if( (sockfd = socket( AF_PACKET, SOCK_RAW, htons(ETH_P_ARP) )) < 0 )
		throw runtime_error( "socket: " + string(strerror(errno)) );

	timer.tv_sec = 0;
	timer.tv_usec = 100000;
	if( setsockopt( sockfd, SOL_SOCKET, SO_RCVTIMEO, &timer, sizeof(timer) ) < 0 )
		throw runtime_error( strerror(errno) );

	memset( &sll, 0, sizeof(sll) );
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_protocol = htons( ETH_P_ARP );

	if( bind( sockfd, (struct sockaddr*) &sll, sizeof(sll) ) < 0 )
		throw runtime_error( strerror(errno) );

	return sockfd;
}

/** Adds a permanent entry to the ARP cache of the system */
void addARPEntry(const char *ifname, struct in_addr ip, const HWAddr &hw)
	throw( runtime_error )
{
	struct arpreq arp;
	int sock = socket( AF_INET, SOCK_DGRAM, 0 );

	arp.arp_pa.sa_family = AF_INET;
	memcpy( arp.arp_pa.sa_data + 2, &ip.s_addr, IP_ADDR_LEN );
	arp.arp_ha.sa_family = ARPHRD_ETHER;
	memcpy( arp.arp_ha.sa_data, hw.hw, MAC_ADDR_LEN );
	strncpy( arp.arp_dev, ifname, IFNAMSIZ - 1 );
	arp.arp_dev[IFNAMSIZ - 1] = '\0';
	arp.arp_flags = ATF_COM | ATF_PERM;

	if( ioctl( sock, SIOCSARP, &arp ) == -1 ){
		close( sock );
		throw runtime_error( "Add ARP entry: " + string(strerror(errno)) );
	}
	close( sock );
}

/** Makes a scan for ARP entries */
ARPTable scan( int sfd, const LocalData &ld )
{
	struct in_addr host;
	ARPTable table;
	ARPFrame request, reply;
	int attempts;

	memset( request.eth_dst, 0xff, MAC_ADDR_LEN );
	memcpy( request.eth_src, ld.hwAddr, MAC_ADDR_LEN );
	request.eth_ethertype = htons( ETH_P_ARP );
	request.hw_type = htons( ARPHRD_ETHER );
	request.protocol = htons( ETH_P_IP );
	request.hw_len = MAC_ADDR_LEN;
	request.proto_len = IP_ADDR_LEN;
	request.opcode = htons(ARPOP_REQUEST);
	memcpy( request.hw_src, ld.hwAddr, MAC_ADDR_LEN );
	request.ip_src = ld.ipAddr;
	memset( request.hw_dst, 0, MAC_ADDR_LEN );

	for( host.s_addr = ld.firstHost ; host.s_addr != ld.lastHost ; host.s_addr += IP_ONE ){
		request.ip_dst = host.s_addr;
		attempts = MAX_TRIES_FOR_RESOLV;
		cout << "Resolving " << inet_ntoa( host ) << '\r';
		cout.flush();
		write( sfd, &request, sizeof(request) );
		do{
			if( read( sfd, &reply, sizeof(reply) ) > 0 ){
				if( ntohs(reply.opcode) == ARPOP_REPLY && reply.ip_src == host.s_addr ){
					HWAddr hw( reply.hw_src );
					struct in_addr aux = { reply.ip_src };
					table[hw] = aux;
					attempts = 0;
				}
				else
					attempts--;
			}
			else
				attempts = 0;
		}while( attempts );
	}
	cout << endl;
	return table;
}


/** Analyzes new ARP replies */
void guard( int sfd, const char *ifname, const ARPTable &table )
{
	ARPFrame reply;
	set<uint32_t> ignored;
	string option;
	bool find;

	while( active ){
		if( read( sfd, &reply, sizeof(reply) ) > 0 ){
			if( ntohs(reply.opcode) == ARPOP_REPLY ){
				HWAddr hw( reply.hw_src );
				struct in_addr ip = { reply.ip_src };

				try{
					struct in_addr reg = table.at(hw); // Check our ARP Table

					if( reg.s_addr != ip.s_addr ){ // If the MAC doesn't match with the IP
						if( ignored.find(ip.s_addr) == ignored.end() ){ // ... And it's not ignored
							find = true;
							cout << hw.toString() << " is poisoning " << inet_ntoa(ip) << 
								". Would you like to add a permanent entry to avoid the faking? (Y/N) ";
							getline( cin, option );

							if( option != "N" && option != "n" ){
								find = false;
								for( auto &i : table ){ // Look for the IP Address, if it is.
									if( i.second.s_addr == ip.s_addr ){
										try{
											addARPEntry( ifname, ip, i.first );
											cout << "Entry added" << endl;
											find = true;
										}
										catch( runtime_error &e ){
											cerr << e.what() << endl;
										}
										break;
									}
								}
							}
							if( !find )
								cout << "There's a missing entry. Please run the tool again for a new scan." << endl;
							ignored.insert( ip.s_addr );
						} // End if for ignoring
					} // End if for not matching IP
				}
				catch( out_of_range ){
					cout << "There's a new device. You should try with a new scan." << endl;
				} // The received entry is not in our ARP Table
			} // End if for replies ARP
		} // End if for reading
	} // End while
}

/** Kill signal handler */
void sigKill(int){
	active = false;
}

int main( int argc, char **argv )
{
	if( argc != 2 ){
		cerr << "Uso:\n\t" << *argv << " interface_name" << endl;
		return 1;
	}

	int sockfd;
	LocalData data;
	ARPTable arpTable;

	try{
		data = loadLocalData( argv[1] );
		sockfd = initSocket( data.ifindex );
	}
	catch( runtime_error &e ){
		cerr << e.what() << endl;
		return 1;
	}


	arpTable = scan( sockfd, data );
	
	cout << arpTable.size() << " entries found. "
		"If you think there's missing devices, please run the tool again.\n\n"
		"\tHW Address\t\t\tIP Address\n";
	for( auto &i : arpTable )
		cout << '\t' << i.first.toString() << "\t\t" << inet_ntoa(i.second) << endl; 

	cout << "\nAnalyzing ARP replies. Press CTRL-C to exit\n\n";
	signal( SIGINT, sigKill );
	guard( sockfd, argv[1], arpTable );

	cout << "\rClosing socket..." << endl;
	close( sockfd );
	return 0;
}
