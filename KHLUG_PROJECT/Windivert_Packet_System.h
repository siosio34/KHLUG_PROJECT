#include "Configure.h"


class Windivert_Packet_System
{
private:
	HANDLE handle;
	float input_time; // UDP 패킷을 잡아둘 시간
	vector<SENDSAVEPACKET> Saved_UDP_Packet; // 패킷
	mutex mtx_lock; // mutex 동기화 객체
public:
	void Windivert_Open_UDP(); 
	void ReceiveUdp_Packet(); // UDP 를 저장해서보관
	void SendUdp_Packet(); // UDP 를 보내겠습니다.
	
};