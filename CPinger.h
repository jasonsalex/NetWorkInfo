#pragma once
#include <WINSOCK2.h>
#include <Iphlpapi.h>
#include <string>

#pragma comment(lib, "wininet.lib")

#pragma pack(push)
#pragma pack(1)

struct IpHead {
	unsigned int    uiHeadLen : 4;            ///<ͷ������
	unsigned int    uiVersion : 4;            ///<�汾
	unsigned char   ucTos;                  ///<��������,type of service
	unsigned short  usTotalLen;             ///<�ܳ���
	unsigned short  usIpId;                 ///<��ʶ
	unsigned short  usFlags;                ///<3λ��־+13λƬƫ��
	unsigned char   ucTtl;                  ///<TTL,time to live
	unsigned char   ucProtocol;             ///<Э��
	unsigned short  usCheckSum;             ///<�ײ���У���
	unsigned int    uiSrcIP;                ///<Դip
	unsigned int    uiDstIP;                ///<Ŀ��ip
};

struct IcmpHead {
	unsigned char   ucType;                 ///<����
	unsigned char   ucCode;                 ///<����
	unsigned short  ususIcmpChkSum;         ///<У���
	unsigned short  usIcmpId;               ///<id
	unsigned char   usSeq;                  ///<���
	unsigned long   ulTimeStamp;            ///<ʱ���
};

#pragma pack(pop)


#define DEF_PACKET_SIZE     32
#define ECHO_REQUEST        8
#define ECHO_REPLY          0
#define ICMP_ECHOREPLY      0
#define ICMP_MIN            sizeof(IcmpHead)
#define ICMP_ECHO           8

class Pinger
{
public:
	Pinger();
	virtual ~Pinger();

	/**
	* @brief ping          pingָ��ip��ַ
	* @param dstIP         Ŀ��ip�����ܰ����ո�ȷǷ��ַ�
	* @param packNum       һ��ping����
	* @param sndTime       ���ͳ�ʱʱ�䣬��λ����
	* @param rcvTime       ���ճ�ʱʱ�䣬��λ����
	* @return              �ɹ�pingͨ�İ���������0��ʾpingͨ
	*/
	int ping(const char* dstIP, const int& packNum, const int &sndTime, const int &rcvTime);

	/**
	* @brief getTips       ��ȡ��ʾ��Ϣ
	* @return              ��ʾ��Ϣ
	*/
	std::string getTips() const { return m_strTips_; }

protected:

	/**
	* @brief checkSum      ����У���
	* @param buf           �����㻺����
	* @param wordCnt       �ָ���
	* @return              У���
	*/
	unsigned short checkSum(const WORD *buf, const int &wordCnt);

	/**
	* @brief decodeIcmpHead        ����icmpͷ
	* @param rcvBuf                ͷ��������
	* @param bread                 �ֽ���
	* @param from                  ��Դip��ַ
	* @return                      0��ʾ������������������EnErrCode
	*/
	int decodeIcmpHead(char *rcvBuf, unsigned int bread, sockaddr_in *from);

	/**
	* @brief fillImcpData          ���icmp����
	* @param icmpData              ������
	* @param byteCnt               ����������
	*/
	void fillIcmpData(char *icmpData, int byteCnt);

	std::string  m_strTips_;                ///<��ʾ��Ϣ

private:
	enum EnErrCode {
		EnOK,
		EnNullPtr,
		EnBadData,
		EnInvalidIp,
		EnSockErr,
	};

	unsigned int m_uiId__;                  ///<��ǰ����id����

	static unsigned int m_uiCnt__;          ///<�ܶ��󴴽�������
};