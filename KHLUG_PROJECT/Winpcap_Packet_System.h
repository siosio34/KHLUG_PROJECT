#pragma once
#include "Configure.h"

class Winpcap_Packet_System
{
private:
	pcap_t *adhandle; // 현재 사용할 핸들
	Basic_ip_mac_addr Basic_addr;
	
public:
	int open_device(pcap_t *_adhandle,int _flag);
	void Print_Hex(void *Data, u_int len);
	static void pcap_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
	int Input_Victim_ip();

	PIP_ADAPTER_ADDRESSES Find_Addapter(string _device_name); // 어댑터 이름 찾
	vector<u_char> Send_ARP_For_Macaddr(pcap_t* handle, int flag);

	void _RunPacketCapture();
	void _RunArpSpoofing();

};