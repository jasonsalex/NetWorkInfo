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

//IP报头
typedef struct IP_HEADER
{
	unsigned char hdr_len : 4;       //4位头部长度
	unsigned char version : 4;       //4位版本号
	unsigned char tos;             //8位服务类型
	unsigned short total_len;      //16位总长度
	unsigned short identifier;     //16位标识符
	unsigned short frag_and_flags; //3位标志加13位片偏移
	unsigned char ttl;             //8位生存时间
	unsigned char protocol;        //8位上层协议号
	unsigned short checksum;       //16位校验和
	unsigned long sourceIP;        //32位源IP地址
	unsigned long destIP;          //32位目的IP地址
} IP_HEADER;

//ICMP报头
typedef struct ICMP_HEADER
{
	BYTE type;    //8位类型字段
	BYTE code;    //8位代码字段
	USHORT cksum; //16位校验和
	USHORT id;    //16位标识符
	USHORT seq;   //16位序列号
} ICMP_HEADER;

//报文解码结构
typedef struct DECODE_RESULT
{
	USHORT usSeqNo;        //序列号
	DWORD dwRoundTripTime; //往返时间
	in_addr dwIPaddr;      //返回报文的IP地址
}DECODE_RESULT;

struct IpForwardTable
{
	std::string destIp; //网络地址
	std::string maskIp; //子网掩码地址
	std::string gatewayIp; //网关地址
	int forwardIndex;   //端口号
	int forwardMetric;  //路由跳数
};

struct TraceIpInfo
{
	std::string ip;//ip地址
	int ping; //延时
};


class CNetworkModule
{
public:
	static bool CheckNetworkIsOnline(); //是否已经联网
	static std::list<IpForwardTable> GetIpForwardTable();   //获取当前的路由信息列表
	static std::list<std::string> GetDNSAddress();  //获取dns列表
	static std::list<TraceIpInfo> GetTraceIpInfo(const std::string ip); //对ip地址进行路由跟踪

private:
	static PMIB_IPFORWARDTABLE MyGetIpForwardTable(BOOL bOrder);
	static void MyFreeIpForwardTable(PMIB_IPFORWARDTABLE pIpRouteTab);
	static USHORT Checksum(USHORT *pBuf, int iSize);
	static BOOL DecodeIcmpResponse(char * pBuf, int iPacketSize, DECODE_RESULT &DecodeResult,
		BYTE ICMP_ECHO_REPLY, BYTE  ICMP_TIMEOUT);
};

