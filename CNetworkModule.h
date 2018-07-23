#pragma once
#include "CNetworkModule.h"
#include <string>
#include <list>
#include <Netlistmgr.h>
#include <cstdio>
#include <WINSOCK2.h>
#include <Iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "wininet.lib")

//IP��ͷ
typedef struct IP_HEADER
{
	unsigned char hdr_len : 4;       //4λͷ������
	unsigned char version : 4;       //4λ�汾��
	unsigned char tos;             //8λ��������
	unsigned short total_len;      //16λ�ܳ���
	unsigned short identifier;     //16λ��ʶ��
	unsigned short frag_and_flags; //3λ��־��13λƬƫ��
	unsigned char ttl;             //8λ����ʱ��
	unsigned char protocol;        //8λ�ϲ�Э���
	unsigned short checksum;       //16λУ���
	unsigned long sourceIP;        //32λԴIP��ַ
	unsigned long destIP;          //32λĿ��IP��ַ
} IP_HEADER;

//ICMP��ͷ
typedef struct ICMP_HEADER
{
	BYTE type;    //8λ�����ֶ�
	BYTE code;    //8λ�����ֶ�
	USHORT cksum; //16λУ���
	USHORT id;    //16λ��ʶ��
	USHORT seq;   //16λ���к�
} ICMP_HEADER;

//���Ľ���ṹ
typedef struct DECODE_RESULT
{
	USHORT usSeqNo;        //���к�
	DWORD dwRoundTripTime; //����ʱ��
	in_addr dwIPaddr;      //���ر��ĵ�IP��ַ
}DECODE_RESULT;

struct IpForwardTable
{
	std::string destIp; //�����ַ
	std::string maskIp; //���������ַ
	std::string gatewayIp; //���ص�ַ
	int forwardIndex;   //�˿ں�
	int forwardMetric;  //·������
};

struct TraceIpInfo
{
	std::string ip;//ip��ַ
	int ping; //��ʱ
};


class CNetworkModule
{
public:
	static bool CheckNetworkIsOnline(); //�Ƿ��Ѿ�����
	static std::list<IpForwardTable> GetIpForwardTable();   //��ȡ��ǰ��·����Ϣ�б�
	static std::list<std::string> GetDNSAddress();  //��ȡdns�б�
	static std::list<TraceIpInfo> GetTraceIpInfo(const std::string ip); //��ip��ַ����·�ɸ���

private:
	static PMIB_IPFORWARDTABLE MyGetIpForwardTable(BOOL bOrder);
	static void MyFreeIpForwardTable(PMIB_IPFORWARDTABLE pIpRouteTab);
	static USHORT Checksum(USHORT *pBuf, int iSize);
	static BOOL DecodeIcmpResponse(char * pBuf, int iPacketSize, DECODE_RESULT &DecodeResult,
		BYTE ICMP_ECHO_REPLY, BYTE  ICMP_TIMEOUT);
};

