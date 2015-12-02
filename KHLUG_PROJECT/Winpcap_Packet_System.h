#pragma once
#include "Configure.h"

class Winpcap_Packet_System
{
private:
	pcap_t *adhandle; // 현재 사용할 핸들
public:
	int open_device(pcap_t *_adhandle);
	void Print_Hex(void *Data, u_int len);
	static void pcap_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
	void _RunPacketCapture();
};