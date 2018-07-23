## 检测windows网络环境状态和路由节点追踪
* CNetworkModule获取路由表，获取dns列表，追踪路由节点状态
* CPinger网络信号检测

```
#include<CNetworkModule.h>
#include<CPinger.h>

void NetworkInternetTest()
{
	Pinger pinger;
	/*************当前是否已接入网络***********/
	printf("network internet state:%d \n", CNetworkModule::CheckNetworkIsOnline());
	
	/***************获取路由表和网络信号测试***************************************/
	printf("Active Routes:\n\n");
	printf("  Network Address          Netmask  Gateway Address        Interface  Metric	ping\n");

	auto routeList = CNetworkModule::GetIpForwardTable(); //获取路由表信息列表


	for (auto info : routeList)
	{
		printf("  %15s %16s %16s %16d %7d ",
			info.destIp.c_str(),
			info.maskIp.c_str(),
			info.gatewayIp.c_str(),
			info.forwardIndex,   
			info.forwardMetric);

		int ping = pinger.ping(info.gatewayIp.c_str(), 1, 200, 200); //测试网关地址的网络状况
		printf("%5d \n", ping);
	}

	/*****DNS地址获取和网络信号测试******/
	printf("\n\n active dns list \n");
	printf(" dns addr	ping \n");

	auto dnsList = CNetworkModule::GetDNSAddress(); //获取dns地址列表
	
	for (auto info : dnsList)
	{
		printf("%8s ", info.c_str());
		int ping = pinger.ping(info.c_str(), 1, 200, 200); //测试DNS地址的网络状况

		printf("%7d \n", ping);
	}

	//与服务器进行网络信号测试
	{
		printf("\n\nping server \n");
		int ping = pinger.ping("www.hfjy.com", 5, 200, 200); //测试DNS地址的网络状况
		printf("ping:%d \n", ping);
	}

	/*******************追踪IP地址的路由网络状态*********************/
	printf("\n\n trace ip info\n");
	printf("address		ping\n");
	auto traceList = CNetworkModule::GetTraceIpInfo("www.baidu.com");
	
	for (auto info : traceList)
	{
		printf("%7s %5d\n", info.ip.c_str(), info.ping);
	}
}
```