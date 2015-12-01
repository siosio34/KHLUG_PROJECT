#pragma once
#define HAVE_REMOTE
#define ETHER_ADDR_LEN 6

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "windivert.lib")

#include <stdio.h>
#include <stdlib.h>

#include <WinSock2.h>
#include <iphlpapi.h>
#include <Windows.h>
#include <conio.h>
#include <netiodef.h>


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
}etc_header;

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
}ip_header;


// TCP Header
typedef struct tcp_header {
	unsigned short sourceport;			// source port
	unsigned short destport;				// destination port
	unsigned long seqno;				// sequenz number
	unsigned long ackno;				// acknowledge number

	unsigned char hlen;					// Header length

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
}udp_header;