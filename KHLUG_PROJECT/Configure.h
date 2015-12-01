#pragma once

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "windivert.lib")
#pragma comment(lib, "wpcap.lib")

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