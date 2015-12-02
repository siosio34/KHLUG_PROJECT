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


int Winpcap_Packet_System::open_device(pcap_t *_adhandle)
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


void Winpcap_Packet_System::_RunPacketCapture()
{
	if (open_device(adhandle) == -1)
	{
		return;
	}

	else
	{
		pcap_loop(adhandle, 0, pcap_handler, NULL);

	}
}
	
