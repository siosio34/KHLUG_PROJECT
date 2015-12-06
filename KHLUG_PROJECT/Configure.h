#pragma once
#define HAVE_REMOTE

#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_REVARP 0X8035
#define ETHERTYPE_IPv6 0X86dd

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20

#define TCP_PRO 6
#define UDP_PRO 17  

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

#define GET_GATEMAC_MODE 0
#define GET_VICTIMEMAC_MODE 1

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "windivert.lib")

#include <stdio.h>
#include <stdlib.h>

#include <WinSock2.h>
#include <iphlpapi.h>
#include <Windows.h>
#include <conio.h>


#include <iostream>
#include <string>
#include <vector>
#include <thread> // c++ 11 쓰레드를 쓰기 위해 추가한 헤더.


// 오픈 소스인 pcap 라이브러리와 windivert 라이브러리 인클루드 
// winpcap과 windivert의 차이는 오는 패킷이나 가는 패킷을 가로 챌수 있는지 아님 보기만 하는지 차이
// windiver 함수를 사용할려면 관리자 모드로 켜야되고 이상하게 디버깅을 시도하면 패킷 자체가 안열림 ( 아마 드라이버 서명 문제인듯 )

#include <pcap.h>
#include <windivert.h>

using namespace std;



typedef struct etc_header {
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];     //destination Mac
	u_int8_t  ether_shost[ETHER_ADDR_LEN];     //source  Mac
	u_int16_t ether_type;
}ETC_HEADER;

typedef struct arp_header
{
	u_short hard_type; //
	u_short Pro_type; // 
	u_char hard_length;
	u_char pro_length;
	u_short op_code;

	u_char source_Macaddr[6];  //sender hard address
	u_char source_ipaddr[4]; // sender sourse ip

	u_char Des_Macaddr[6]; // target Hard address
	u_char Des_ipaddr[4]; // target source IP


}ARP_HEADER;

typedef struct infection {
	ETC_HEADER etc;
	ARP_HEADER arp;
} infection;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service
	u_short tlen;           // Total length
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	u_char  saddr[4];      // Source address
	u_char  daddr[4];      // Destination address
	u_int   op_pad;         // Option + Padding
}IPHEADER;


// TCP Header
typedef struct tcp_header {
	unsigned short sourceport;			// source port
	unsigned short destport;				// destination port
	unsigned long seqno;				// sequenz number
	unsigned long ackno;				// acknowledge number
	unsigned char th_x2 : 4;
	unsigned char hlen:4;					// Header length
	unsigned char flag;					// flags
	unsigned short window;				// window
	unsigned short chksum;				// checksum
	unsigned short urgptr;				// urgend pointer
	unsigned int op_pad;

}TCPHEADER, *PTCPHEADER;

/* UDP header*/
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}UDPHEADER;

typedef struct Basic_ip_mac_addr
{
	vector<u_char> attacker_ip; // 어택커 ip
	vector<u_char> attacker_mac; // 어택커맥
	vector<u_char> gate_ip; // 게이트웨어 ip
	vector<u_char> gate_mac; // 게이트웨어 mac
	vector<u_char> victim_ip; // 희생자 ip
	vector<u_char> victim_mac; // victim mac

}; Basic_ip_mac_addr
//TCP PAYLOAD 길이 ip header의 총길이 - ip헤더크기 - tcp 헤더크기
//UDP DATAGRAM 길이 호스트 바이 오더로 바뀬 udp_header.len에서  udp 헤더크기를 빼주어야한다.
