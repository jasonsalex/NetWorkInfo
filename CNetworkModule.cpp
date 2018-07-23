#include <CNetworkModule.h>
#include <iostream>

using namespace std;

bool CNetworkModule::CheckNetworkIsOnline()
{
	CoInitialize(NULL);
	//  通过NLA接口获取网络状态
	IUnknown *pUnknown = NULL;
	BOOL   bOnline = TRUE;//是否在线  

	HRESULT Result = CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, IID_IUnknown, (void **)&pUnknown);
	
	if (SUCCEEDED(Result))
	{
		INetworkListManager *pNetworkListManager = NULL;

		if (pUnknown) Result = pUnknown->QueryInterface(IID_INetworkListManager, (void **)&pNetworkListManager);
		
		if (SUCCEEDED(Result))
		{
			VARIANT_BOOL IsConnect = VARIANT_FALSE;
			
			if (pNetworkListManager)
				Result = pNetworkListManager->get_IsConnectedToInternet(&IsConnect);
			
			if (SUCCEEDED(Result))
			{
				bOnline = (IsConnect == VARIANT_TRUE) ? true : false;
			}
		}

		if (pNetworkListManager)
			pNetworkListManager->Release();
	}

	if (pUnknown)
		pUnknown->Release();
	
	CoUninitialize();
	
	return bOnline;
}

PMIB_IPFORWARDTABLE CNetworkModule::MyGetIpForwardTable(BOOL bOrder)
{
	PMIB_IPFORWARDTABLE pIpRouteTab = NULL;
	DWORD dwActualSize = 0;

	// 查询所需缓冲区的大小
	if (::GetIpForwardTable(pIpRouteTab, &dwActualSize, bOrder) == ERROR_INSUFFICIENT_BUFFER)
	{
		// 为MIB_IPFORWARDTABLE结构申请内存
		pIpRouteTab = (PMIB_IPFORWARDTABLE)::GlobalAlloc(GPTR, dwActualSize);
		// 获取路由表
		if (::GetIpForwardTable(pIpRouteTab, &dwActualSize, bOrder) == NO_ERROR)
			return pIpRouteTab;
		::GlobalFree(pIpRouteTab);
	}
	return NULL;
}

void CNetworkModule::MyFreeIpForwardTable(PMIB_IPFORWARDTABLE pIpRouteTab)
{
	if (pIpRouteTab != NULL)
		::GlobalFree(pIpRouteTab);
}

USHORT CNetworkModule::Checksum(USHORT * pBuf, int iSize)
{
	unsigned long cksum = 0;
	while (iSize > 1)
	{
		cksum += *pBuf++;
		iSize -= sizeof(USHORT);
	}
	if (iSize)//如果 iSize 为正，即为奇数个字节
	{
		cksum += *(UCHAR *)pBuf; //则在末尾补上一个字节，使之有偶数个字节
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);

}

BOOL CNetworkModule::DecodeIcmpResponse(char * pBuf, int iPacketSize, DECODE_RESULT & DecodeResult, BYTE ICMP_ECHO_REPLY, BYTE ICMP_TIMEOUT)
{
	//检查数据报大小的合法性
	IP_HEADER* pIpHdr = (IP_HEADER*)pBuf;
	int iIpHdrLen = pIpHdr->hdr_len * 4;    //ip报头的长度是以4字节为单位的

											//若数据包大小 小于 IP报头 + ICMP报头，则数据报大小不合法
	if (iPacketSize < (int)(iIpHdrLen + sizeof(ICMP_HEADER)))
		return FALSE;

	//根据ICMP报文类型提取ID字段和序列号字段
	ICMP_HEADER *pIcmpHdr = (ICMP_HEADER *)(pBuf + iIpHdrLen);//ICMP报头 = 接收到的缓冲数据 + IP报头
	USHORT usID, usSquNo;

	if (pIcmpHdr->type == ICMP_ECHO_REPLY)    //ICMP回显应答报文
	{
		usID = pIcmpHdr->id;        //报文ID
		usSquNo = pIcmpHdr->seq;    //报文序列号
	}
	else if (pIcmpHdr->type == ICMP_TIMEOUT)//ICMP超时差错报文
	{
		char * pInnerIpHdr = pBuf + iIpHdrLen + sizeof(ICMP_HEADER); //载荷中的IP头
		int iInnerIPHdrLen = ((IP_HEADER *)pInnerIpHdr)->hdr_len * 4; //载荷中的IP头长
		ICMP_HEADER * pInnerIcmpHdr = (ICMP_HEADER *)(pInnerIpHdr + iInnerIPHdrLen);//载荷中的ICMP头

		usID = pInnerIcmpHdr->id;        //报文ID
		usSquNo = pInnerIcmpHdr->seq;    //序列号
	}
	else
	{
		return false;
	}

	//检查ID和序列号以确定收到期待数据报
	if (usID != (USHORT)GetCurrentProcessId() || usSquNo != DecodeResult.usSeqNo)
	{
		return false;
	}
	//记录IP地址并计算往返时间
	DecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;
	DecodeResult.dwRoundTripTime = GetTickCount() - DecodeResult.dwRoundTripTime;

	//处理正确收到的ICMP数据报
	if (pIcmpHdr->type == ICMP_ECHO_REPLY || pIcmpHdr->type == ICMP_TIMEOUT)
	{
		//输出往返时间信息
		if (DecodeResult.dwRoundTripTime)
			cout << "      " << DecodeResult.dwRoundTripTime << "ms" << flush;
		else
			cout << "      " << "<1ms" << flush;
	}
	return true;
}

std::list<std::string> CNetworkModule::GetDNSAddress()
{
	FIXED_INFO * FixedInfo;
	ULONG ulOutBufLen;
	DWORD dwRetVal;
	IP_ADDR_STRING * pIPAddr;

	FixedInfo = (FIXED_INFO *)GlobalAlloc(GPTR, sizeof(FIXED_INFO));

	ulOutBufLen = sizeof(FIXED_INFO);

	std::list<std::string> dnsList;

	if (ERROR_BUFFER_OVERFLOW == GetNetworkParams(FixedInfo, &ulOutBufLen))
	{
		GlobalFree(FixedInfo);

		FixedInfo = (FIXED_INFO *)GlobalAlloc(GPTR, ulOutBufLen);
	}

	if (dwRetVal = GetNetworkParams(FixedInfo, &ulOutBufLen) == ERROR_SUCCESS)
	{
		dnsList.push_back(FixedInfo->DnsServerList.IpAddress.String);

		pIPAddr = FixedInfo->DnsServerList.Next;

		while(pIPAddr)
		{
			dnsList.push_back(pIPAddr->IpAddress.String);
			pIPAddr = pIPAddr->Next;
		}
	}

	return dnsList;
}

std::list<TraceIpInfo> CNetworkModule::GetTraceIpInfo(const std::string ip)
{
	//初始化Windows sockets网络环境
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);

	//得到IP地址
	u_long ulDestIP = inet_addr(ip.c_str());

	std::list<TraceIpInfo> traceInfoList;

	//转换不成功时按域名解析
	if (ulDestIP == INADDR_NONE)
	{
		hostent * pHostent = gethostbyname(ip.c_str());
		if (pHostent)
		{
			ulDestIP = (*(in_addr*)pHostent->h_addr).s_addr;
		}
		else
		{
			cout << "输入的IP地址或域名无效!" << endl;
			WSACleanup();
			return traceInfoList;
		}
	}
	cout << "Tracing roote to " << ip << " with a maximum of 30 hops.\n" << endl;

	//填充目的端socket地址
	sockaddr_in destSockAddr;
	ZeroMemory(&destSockAddr, sizeof(sockaddr_in));
	destSockAddr.sin_family = AF_INET;
	destSockAddr.sin_addr.s_addr = ulDestIP;

	//创建原始套接字
	SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);

	//超时时间
	int iTimeout = 3000;

	//设置接收超时时间
	setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char *)&iTimeout, sizeof(iTimeout));

	//设置发送超时时间
	setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char *)&iTimeout, sizeof(iTimeout));

	//构造ICMP回显请求消息，并以TTL递增的顺序发送报文
	//ICMP类型字段
	const BYTE ICMP_ECHO_REQUEST = 8;    //请求回显
	const BYTE ICMP_ECHO_REPLY = 0;    //回显应答
	const BYTE ICMP_TIMEOUT = 11;   //传输超时

									//其他常量定义
	const int DEF_ICMP_DATA_SIZE = 32;    //ICMP报文默认数据字段长度
	const int MAX_ICMP_PACKET_SIZE = 1024;  //ICMP报文最大长度（包括报头）
	const DWORD DEF_ICMP_TIMEOUT = 3000;  //回显应答超时时间
	const int DEF_MAX_HOP = 30;    //最大跳站数

								   //填充ICMP报文中每次发送时不变的字段
	char IcmpSendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE];//发送缓冲区
	memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));               //初始化发送缓冲区
	char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];                      //接收缓冲区
	memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));               //初始化接收缓冲区

	ICMP_HEADER * pIcmpHeader = (ICMP_HEADER*)IcmpSendBuf;
	pIcmpHeader->type = ICMP_ECHO_REQUEST; //类型为请求回显
	pIcmpHeader->code = 0;                //代码字段为0
	pIcmpHeader->id = (USHORT)GetCurrentProcessId();    //ID字段为当前进程号
	memset(IcmpSendBuf + sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE);//数据字段

	USHORT usSeqNo = 0;            //ICMP报文序列号
	int iTTL = 1;            //TTL初始值为1
	BOOL bReachDestHost = FALSE;        //循环退出标志
	int iMaxHot = DEF_MAX_HOP;  //循环的最大次数
	DECODE_RESULT DecodeResult;    //传递给报文解码函数的结构化参数
	while (!bReachDestHost && iMaxHot--)
	{
		//设置IP报头的TTL字段
		setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char *)&iTTL, sizeof(iTTL));
		cout << iTTL << flush;    //输出当前序号,flush表示将缓冲区的内容马上送进cout,把输出缓冲区刷新

								  //填充ICMP报文中每次发送变化的字段
		((ICMP_HEADER *)IcmpSendBuf)->cksum = 0;                   //校验和先置为0
		((ICMP_HEADER *)IcmpSendBuf)->seq = htons(usSeqNo++);    //填充序列号
		((ICMP_HEADER *)IcmpSendBuf)->cksum =
			Checksum((USHORT *)IcmpSendBuf, sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE); //计算校验和

																					   //记录序列号和当前时间
		DecodeResult.usSeqNo = ((ICMP_HEADER*)IcmpSendBuf)->seq;    //当前序号
		DecodeResult.dwRoundTripTime = GetTickCount();                          //当前时间
																	//发送TCP回显请求信息
		sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0, (sockaddr*)&destSockAddr, sizeof(destSockAddr));

		//接收ICMP差错报文并进行解析处理
		sockaddr_in from;           //对端socket地址
		int iFromLen = sizeof(from);//地址结构大小
		int iReadDataLen;           //接收数据长度
		while (1)
		{
			//接收数据
			iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr*)&from, &iFromLen);
			if (iReadDataLen != SOCKET_ERROR)//有数据到达
			{
				//对数据包进行解码
				if (DecodeIcmpResponse(IcmpRecvBuf, iReadDataLen, DecodeResult, ICMP_ECHO_REPLY, ICMP_TIMEOUT))
				{
					//到达目的地，退出循环
					if (DecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr)
						bReachDestHost = true;
					//输出IP地址cout
					cout << '\t' << inet_ntoa(DecodeResult.dwIPaddr) << endl;
					traceInfoList.push_back({ inet_ntoa(DecodeResult.dwIPaddr), (int)DecodeResult.dwRoundTripTime });

					break;
				}
			}
			else if (WSAGetLastError() == WSAETIMEDOUT)    //接收超时，输出*号
			{
				cout << "         *" << '\t' << "Request timed out." << endl;
				break;
			}
			else
			{
				break;
			}
		}
		iTTL++;    //递增TTL值
	}
	
	return traceInfoList;
}

std::list<IpForwardTable> CNetworkModule::GetIpForwardTable()
{
	PMIB_IPFORWARDTABLE pIpRouteTable = MyGetIpForwardTable(TRUE);
	std::list<IpForwardTable> routeList;

	if (pIpRouteTable != NULL)
	{
		DWORD i, dwCurrIndex;
		struct in_addr inadDest;
		struct in_addr inadMask;
		struct in_addr inadGateway;
		PMIB_IPADDRTABLE pIpAddrTable = NULL;

		char szDestIp[128];
		char szMaskIp[128];
		char szGatewayIp[128];
		
		for (i = 0; i < pIpRouteTable->dwNumEntries; i++)
		{
			dwCurrIndex = pIpRouteTable->table[i].dwForwardIfIndex;

			// 目的地址
			inadDest.s_addr = pIpRouteTable->table[i].dwForwardDest;
			// 子网掩码
			inadMask.s_addr = pIpRouteTable->table[i].dwForwardMask;
			// 网关地址
			inadGateway.s_addr = pIpRouteTable->table[i].dwForwardNextHop;

			routeList.push_back({
				inet_ntoa(inadDest),
				inet_ntoa(inadMask),
				inet_ntoa(inadGateway),
				(int)pIpRouteTable->table[i].dwForwardIfIndex,
				(int)pIpRouteTable->table[i].dwForwardMetric1
				});
		}

		MyFreeIpForwardTable(pIpRouteTable);
	}

	return routeList;
}
