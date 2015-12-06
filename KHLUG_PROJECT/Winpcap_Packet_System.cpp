#include "Winpcap_Packet_System.h"


void Winpcap_Packet_System::Print_Hex(void *Data, u_int len)
{

	int iLin;
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
	// DEVICE lIST 검색
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

	 // 이 아래는 ARP_SPOOfing 전용이다.

	if (_flag == 1)
	{
		// 게이트 웨이 정보를 들고온다.
		PIP_ADAPTER_ADDRESSES Adapter_addr;
		PIP_ADAPTER_GATEWAY_ADDRESS Gate_addr;

		Adapter_addr = Find_Addapter(d->name); // 어댑터
		Gate_addr = Adapter_addr->FirstGatewayAddress; // 게이트 웨이


		// 공격자의 Mac 주소 획득 
		if (Adapter_addr->PhysicalAddressLength != 0)
		{
			for (int i = 0; i < (int)Adapter_addr->PhysicalAddressLength; i++)
			{
				Basic_addr.attacker_mac.push_back(Adapter_addr->PhysicalAddress[i]); // 공격자의 맥 설정.
			}
		}

		while (Adapter_addr->FirstUnicastAddress != NULL)
		{
			sockaddr_in *sa_in = (sockaddr_in *)Adapter_addr->FirstUnicastAddress->Address.lpSockaddr;
			
			if (sa_in->sin_family == AF_INET)
			{
				for (int i = 0; i < 4; i++)
				{
					Basic_addr.attacker_ip.push_back(Adapter_addr->FirstUnicastAddress->Address.lpSockaddr->sa_data[i + 2]); // 공격자의 IP 설정
					Basic_addr.gate_ip.push_back(Gate_addr->Address.lpSockaddr->sa_data[i + 2]); // 게이트 IP 설정
				}
				break;
			}

			Adapter_addr->FirstUnicastAddress = Adapter_addr->FirstUnicastAddress->Next;
		}


		// 희생자 IP 설정
		Input_Victim_ip();


		// 1. 희생자 IP -> 입력
		// 2. 공격자의 MAC  및 3. IP 는 어댑터만 알면 찾을 수 있다.
		// 4. 게이트워어 IP 도 어댑터로 찾을 수 있다.
		// 5. 게이트웨어 MAC 과 6. 희생자 MAC 은 ARP 헤더를 사용해서 알아낸다.

		Basic_addr.gate_mac = Send_ARP_For_Macaddr(adhandle, GET_GATEMAC_MODE);
		Basic_addr.victim_mac = Send_ARP_For_Macaddr(adhandle, GET_VICTIMEMAC_MODE);

		// 구해온 게이트 웨이 정보로 ARP SPOOFING 에 필요한 자료를 수집한다.
	}
	cout << " 으엑 " << endl;
	pcap_freealldevs(alldevs);



	return 1;
}

void Winpcap_Packet_System::pcap_handler(u_char * param, const pcap_pkthdr * header, const u_char * pkt_data)
{
	etc_header *eth;
	ip_header *ih;
	tcp_header *th;
	udp_header *uh;
	char data_buffer[2048];
	u_int ip_len;
	u_int th_len;
	u_int uh_len;
	u_short sport, dport;
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
	// 다른것도 있는데 귀찮다 나중에 하자.

	printf("\n\n");

	//TCP와 UDP 일때 정보를 추가해주면된다. ICMP 도 있지만 나중에 구현하도록하자.
	if (ih->proto == TCP_PRO)
	{
		th = (tcp_header *)((u_char*)ih + ip_len); // tcp나 udp 나 둘다 ip 헤더 끝나고 시작되기때문에 이렇게 해도 무관하다.
		th_len = th->hlen << 2; // TCP 헤더만의 크기계산 , 옵션 포함 더길다
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
		//uh = (udp_header *)((u_char*)ih + ip_len); // ip 헤더값은 고정이 아니기 때문에 이렇게 해줘야한다.
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
	infection *infec;
	string temp_mac;
	string temp_split = ".";
	string token;
	size_t pos = 0;

	int i = 0;
	int num;

	cout << "공격할 대상의 IP Address : ";
	cin >> temp_mac;
	
	//Victim_ip 등록하기.
	while ((pos = temp_mac.find(temp_split)) != string::npos)
	{
		token = temp_mac.substr(0, pos);
		num = atoi(token.c_str());
		Basic_addr.victim_ip.push_back(num);
		temp_mac.erase(0, pos + 1);
	}

	num = atoi(temp_mac.c_str());
	Basic_addr.victim_ip.push_back(num);

	//Victim_Mac 등록하기

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

			if (k.compare(_device_name) == 0) // 어댑터들 중에서 내가 연결한 어댑터와 같을때
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
				printf("\tError: %s", lpMsgBuf);
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
	
	// temp ethernet 헤더 설정
	for (int i = 0; i < 6; i++)
	{
		infec->etc.ether_dhost[i] = 0xFF;
		infec->etc.ether_shost[i] = Basic_addr.attacker_mac[i];
		infec->arp.source_Macaddr[i] = Basic_addr.attacker_mac[i];
		infec->arp.Des_Macaddr[i] = 0;
		
	}
	infec->etc.ether_type = htons(ETHERTYPE_ARP);

   // tep arp 헤더 설정
	infec->arp.hard_type = htons(0x1);
	infec->arp.Pro_type = htons(0x0800);
	infec->arp.hard_length = 6;
	infec->arp.pro_length = 4;
	infec->arp.op_code = htons(0x01);

	vector<u_char> get_mac;

	// mac 설정은 끝냈으니 아이피 설정을 하면된다.

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
			fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(_handle));
		}

		Recieve_arp = (infection *)(pkt_data); // 받아오는 패킷

		for (int i = 0; i < 4; i++)
		{
			if (Recieve_arp->arp.source_ipaddr[i] == infec->arp.Des_ipaddr[i]) //공격자의 타겟 아이피 == 알고자하는 소스 아이피
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
				get_mac.push_back(pkt_data[i + 6]);
			}
			break;
		}
	}


	return get_mac;
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
		Basic_addr;

		
		// Victim 정보획득
		// 상대방 ip만 알아도 모든 정보를 불러올 수 있도록 자동화해야 한다.
		// 1. GateWay IP 와 GateWay Mac 을 알아야 된다.
		// 2. 공격자 자신의 Mac과 공격자 자신의 ip 를 알아야 한다.
		// 3. 상대방 IP 주소를 알면 상대방 MAC 주소도 알수 있다.


		// -> open_device 에서 처리를해줌

		// Arp Infection 패킷을 만들어야 한다.(source 나 , destination 공유기)
		// 1. 감염 패킷은 ARP HEADER와 ETERNET 헤더를 합친것이다.
		// 2. 감염 성공시 arp -a 명령어를 통해 확인할 수 있다. (인터넷도 끊긴다 )
		// 3. 정보 획득으로 얻은 정보를 통해 나 자신(공격자)로 부터 희생자로부터 infection 패킷을 전송한다.

		// ->

		// Arp Relay 패킷을 만들어야 한다. ( source 공유기 destination 희생자 )
		// 1. ARP_INFECTION 만 진행하면 나 자신도 희생자에 의해서 감염되기 때문에
		//    게이트웨이와의 통신을 못해서 상대방 포함 나 자신도 감염되어 인터넷 연결이 안된다.
		// 2. 인터넷 연결이 안되게 되면 ARP_Spoofing을 통해서 얻는 이득이 아무것도 없기 때문에
		//	  나 자신과 통신하는게 아닌 공유기와 통신하는척 속여야 한다.



	}

}
	
