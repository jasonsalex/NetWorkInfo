#include <CNetworkModule.h>
#include <iostream>

using namespace std;

bool CNetworkModule::CheckNetworkIsOnline()
{
	CoInitialize(NULL);
	//  ͨ��NLA�ӿڻ�ȡ����״̬
	IUnknown *pUnknown = NULL;
	BOOL   bOnline = TRUE;//�Ƿ�����  

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

	// ��ѯ���軺�����Ĵ�С
	if (::GetIpForwardTable(pIpRouteTab, &dwActualSize, bOrder) == ERROR_INSUFFICIENT_BUFFER)
	{
		// ΪMIB_IPFORWARDTABLE�ṹ�����ڴ�
		pIpRouteTab = (PMIB_IPFORWARDTABLE)::GlobalAlloc(GPTR, dwActualSize);
		// ��ȡ·�ɱ�
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
	if (iSize)//��� iSize Ϊ������Ϊ�������ֽ�
	{
		cksum += *(UCHAR *)pBuf; //����ĩβ����һ���ֽڣ�ʹ֮��ż�����ֽ�
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);

}

BOOL CNetworkModule::DecodeIcmpResponse(char * pBuf, int iPacketSize, DECODE_RESULT & DecodeResult, BYTE ICMP_ECHO_REPLY, BYTE ICMP_TIMEOUT)
{
	//������ݱ���С�ĺϷ���
	IP_HEADER* pIpHdr = (IP_HEADER*)pBuf;
	int iIpHdrLen = pIpHdr->hdr_len * 4;    //ip��ͷ�ĳ�������4�ֽ�Ϊ��λ��

											//�����ݰ���С С�� IP��ͷ + ICMP��ͷ�������ݱ���С���Ϸ�
	if (iPacketSize < (int)(iIpHdrLen + sizeof(ICMP_HEADER)))
		return FALSE;

	//����ICMP����������ȡID�ֶκ����к��ֶ�
	ICMP_HEADER *pIcmpHdr = (ICMP_HEADER *)(pBuf + iIpHdrLen);//ICMP��ͷ = ���յ��Ļ������� + IP��ͷ
	USHORT usID, usSquNo;

	if (pIcmpHdr->type == ICMP_ECHO_REPLY)    //ICMP����Ӧ����
	{
		usID = pIcmpHdr->id;        //����ID
		usSquNo = pIcmpHdr->seq;    //�������к�
	}
	else if (pIcmpHdr->type == ICMP_TIMEOUT)//ICMP��ʱ�����
	{
		char * pInnerIpHdr = pBuf + iIpHdrLen + sizeof(ICMP_HEADER); //�غ��е�IPͷ
		int iInnerIPHdrLen = ((IP_HEADER *)pInnerIpHdr)->hdr_len * 4; //�غ��е�IPͷ��
		ICMP_HEADER * pInnerIcmpHdr = (ICMP_HEADER *)(pInnerIpHdr + iInnerIPHdrLen);//�غ��е�ICMPͷ

		usID = pInnerIcmpHdr->id;        //����ID
		usSquNo = pInnerIcmpHdr->seq;    //���к�
	}
	else
	{
		return false;
	}

	//���ID�����к���ȷ���յ��ڴ����ݱ�
	if (usID != (USHORT)GetCurrentProcessId() || usSquNo != DecodeResult.usSeqNo)
	{
		return false;
	}
	//��¼IP��ַ����������ʱ��
	DecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;
	DecodeResult.dwRoundTripTime = GetTickCount() - DecodeResult.dwRoundTripTime;

	//������ȷ�յ���ICMP���ݱ�
	if (pIcmpHdr->type == ICMP_ECHO_REPLY || pIcmpHdr->type == ICMP_TIMEOUT)
	{
		//�������ʱ����Ϣ
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
	//��ʼ��Windows sockets���绷��
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);

	//�õ�IP��ַ
	u_long ulDestIP = inet_addr(ip.c_str());

	std::list<TraceIpInfo> traceInfoList;

	//ת�����ɹ�ʱ����������
	if (ulDestIP == INADDR_NONE)
	{
		hostent * pHostent = gethostbyname(ip.c_str());
		if (pHostent)
		{
			ulDestIP = (*(in_addr*)pHostent->h_addr).s_addr;
		}
		else
		{
			cout << "�����IP��ַ��������Ч!" << endl;
			WSACleanup();
			return traceInfoList;
		}
	}
	cout << "Tracing roote to " << ip << " with a maximum of 30 hops.\n" << endl;

	//���Ŀ�Ķ�socket��ַ
	sockaddr_in destSockAddr;
	ZeroMemory(&destSockAddr, sizeof(sockaddr_in));
	destSockAddr.sin_family = AF_INET;
	destSockAddr.sin_addr.s_addr = ulDestIP;

	//����ԭʼ�׽���
	SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);

	//��ʱʱ��
	int iTimeout = 3000;

	//���ý��ճ�ʱʱ��
	setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char *)&iTimeout, sizeof(iTimeout));

	//���÷��ͳ�ʱʱ��
	setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char *)&iTimeout, sizeof(iTimeout));

	//����ICMP����������Ϣ������TTL������˳���ͱ���
	//ICMP�����ֶ�
	const BYTE ICMP_ECHO_REQUEST = 8;    //�������
	const BYTE ICMP_ECHO_REPLY = 0;    //����Ӧ��
	const BYTE ICMP_TIMEOUT = 11;   //���䳬ʱ

									//������������
	const int DEF_ICMP_DATA_SIZE = 32;    //ICMP����Ĭ�������ֶγ���
	const int MAX_ICMP_PACKET_SIZE = 1024;  //ICMP������󳤶ȣ�������ͷ��
	const DWORD DEF_ICMP_TIMEOUT = 3000;  //����Ӧ��ʱʱ��
	const int DEF_MAX_HOP = 30;    //�����վ��

								   //���ICMP������ÿ�η���ʱ������ֶ�
	char IcmpSendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE];//���ͻ�����
	memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));               //��ʼ�����ͻ�����
	char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];                      //���ջ�����
	memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));               //��ʼ�����ջ�����

	ICMP_HEADER * pIcmpHeader = (ICMP_HEADER*)IcmpSendBuf;
	pIcmpHeader->type = ICMP_ECHO_REQUEST; //����Ϊ�������
	pIcmpHeader->code = 0;                //�����ֶ�Ϊ0
	pIcmpHeader->id = (USHORT)GetCurrentProcessId();    //ID�ֶ�Ϊ��ǰ���̺�
	memset(IcmpSendBuf + sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE);//�����ֶ�

	USHORT usSeqNo = 0;            //ICMP�������к�
	int iTTL = 1;            //TTL��ʼֵΪ1
	BOOL bReachDestHost = FALSE;        //ѭ���˳���־
	int iMaxHot = DEF_MAX_HOP;  //ѭ����������
	DECODE_RESULT DecodeResult;    //���ݸ����Ľ��뺯���Ľṹ������
	while (!bReachDestHost && iMaxHot--)
	{
		//����IP��ͷ��TTL�ֶ�
		setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char *)&iTTL, sizeof(iTTL));
		cout << iTTL << flush;    //�����ǰ���,flush��ʾ�������������������ͽ�cout,�����������ˢ��

								  //���ICMP������ÿ�η��ͱ仯���ֶ�
		((ICMP_HEADER *)IcmpSendBuf)->cksum = 0;                   //У�������Ϊ0
		((ICMP_HEADER *)IcmpSendBuf)->seq = htons(usSeqNo++);    //������к�
		((ICMP_HEADER *)IcmpSendBuf)->cksum =
			Checksum((USHORT *)IcmpSendBuf, sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE); //����У���

																					   //��¼���кź͵�ǰʱ��
		DecodeResult.usSeqNo = ((ICMP_HEADER*)IcmpSendBuf)->seq;    //��ǰ���
		DecodeResult.dwRoundTripTime = GetTickCount();                          //��ǰʱ��
																	//����TCP����������Ϣ
		sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0, (sockaddr*)&destSockAddr, sizeof(destSockAddr));

		//����ICMP����Ĳ����н�������
		sockaddr_in from;           //�Զ�socket��ַ
		int iFromLen = sizeof(from);//��ַ�ṹ��С
		int iReadDataLen;           //�������ݳ���
		while (1)
		{
			//��������
			iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr*)&from, &iFromLen);
			if (iReadDataLen != SOCKET_ERROR)//�����ݵ���
			{
				//�����ݰ����н���
				if (DecodeIcmpResponse(IcmpRecvBuf, iReadDataLen, DecodeResult, ICMP_ECHO_REPLY, ICMP_TIMEOUT))
				{
					//����Ŀ�ĵأ��˳�ѭ��
					if (DecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr)
						bReachDestHost = true;
					//���IP��ַcout
					cout << '\t' << inet_ntoa(DecodeResult.dwIPaddr) << endl;
					traceInfoList.push_back({ inet_ntoa(DecodeResult.dwIPaddr), (int)DecodeResult.dwRoundTripTime });

					break;
				}
			}
			else if (WSAGetLastError() == WSAETIMEDOUT)    //���ճ�ʱ�����*��
			{
				cout << "         *" << '\t' << "Request timed out." << endl;
				break;
			}
			else
			{
				break;
			}
		}
		iTTL++;    //����TTLֵ
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

			// Ŀ�ĵ�ַ
			inadDest.s_addr = pIpRouteTable->table[i].dwForwardDest;
			// ��������
			inadMask.s_addr = pIpRouteTable->table[i].dwForwardMask;
			// ���ص�ַ
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
