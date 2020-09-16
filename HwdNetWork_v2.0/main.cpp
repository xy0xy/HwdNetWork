#include "CHwdNetWork.hpp"
#include <iostream>

#pragma  warning(disable:4996)


using namespace std;



int main()
{

	//http://test.huweidun.cn/en.php?s=0f06bd6a57e775b3772176cea65f2af4
	/*
	
	TKKn7kH2qv1g0qEw6GMqHYwQm
TKZqBHycHJooINJFGiELfdHim
TKO1YkIfS6OiJy9zOp059ziJe
TKcvDFz4xmsG44Ju0n5Hbej0a
TKYJz82yL0DYi7Lk2MzpVwVUi
TK2P1MdadBlGdnKpHraEEjov0
TKW7IeeSPnBuLPQwABI8LwNtd
TKR2268AsUKe0ZrgiG1sqFa2Q
TK0WyCAVoJKnn8x2VDZKuIZ8C
TKLYv4uGmdy3qvlHSizdMJ1WP
	
	
	*/
	NETWORK::CHwdNetWork net
	(
		XorStr("Z6hDeN6k4RwWhsxAXRraa78O2nxp2sm8")/*通讯密钥*/,
		XorStr("eab84b7b-764f-47a2-9571-f5df21c1845b")/*软件sid*/,
		XorStr(" ")/*购买授权后获得*/,
		XorStr("943e508419c4cd486ab894d3f7dbee50")/*购买授权后获得*/,
		XorStr("[data]123[key]abc")/*客户端sign规则*/,
		XorStr("[data]cba[key]321")/*服务端sign规则*/,
		80/*服务器端口*/,
		XorStr("test.huweidun.cn")/*服务器地址*/,
		XorStr("an.php?s=0f06bd6a57e775b3772176cea65f2af4")/*请求页*/
	);

	if (net.Init())
	{
		cout << "初始化成功"<<endl;
	}
	else
	{
		cout << "初始化失败" << endl;
		cout << net.GetLastErroMsg() << endl;
	}



	std::cout << "公告:" << net.GetNotice() << std::endl;
	std::cout << "软件名字:" << net.GetName() << std::endl;
	std::cout << "软件版本:" << net.GetVersion() << std::endl;
	std::cout << "客服qq:" << net.GetQq() << std::endl;
	std::cout << "软件下载地址:" << net.GetDownloadurl() << std::endl;




	if (net.UserLogin("TKKn7kH2qv1g0qEw6GMqHYwQm","TKKn7kH2qv1g0qEw6GMqHYwQm"))
	{
		cout << "登录成功" << endl;
	}
	else
	{
		cout << "登录失败" << endl;
		cout << net.GetLastErroMsg() << endl;
	}


	cout << "发出扣时请求" << endl;


	if (net.DeductTime("10"))
	{
		cout << "扣时成功" << endl;
	}
	else
	{
		cout << "扣时失败" << endl;
		cout << net.GetLastErroMsg() << endl;
	}

	if (net.BindMac("TKKn7kH2qv1g0qEw6GMqHYwQm"))
	{
		cout << "绑定机器成功" << endl;
	}
	else
	{
		cout << "绑定机器失败" << endl;
		cout << net.GetLastErroMsg() << endl;
	}








	return 0;
}

