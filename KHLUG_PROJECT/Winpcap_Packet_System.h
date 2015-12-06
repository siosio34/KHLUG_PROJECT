#pragma once
#include "Configure.h"



class Winpcap_Packet_System
{
private:
	 pcap_t *adhandle; // 현재 사용할 핸들
	 Basic_ip_mac_addr Basic_addr;
	
	
public:
	
	void Print_Hex(void *Data, u_int len);
	static void pcap_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
	
	int open_device(pcap_t *_adhandle, int _flag);
	int Input_Victim_ip(); // 희생자 IP 는 알고 있어야 한다.
	PIP_ADAPTER_ADDRESSES Find_Addapter(string _device_name); // 어댑터 이름 찾기
	vector<u_char> Send_ARP_For_Macaddr(pcap_t* handle, int flag); // Arp 해킷을 보내서 맥주소를 따옴.

	
	 void Send_Arp_Infection_Packet();
	 void Send_Arp_Relay_Packet();



	void _RunPacketCapture();
	void _RunArpSpoofing();

};