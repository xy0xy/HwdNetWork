#include "CHwdNetWork.h"
#include "XorString.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/err.h>

//验证对象
NETWORK::CHwdNetWork* net = nullptr;

int main()
{


    /*在此处填写软件位相关的信息！！！！！！！！！！！*/
	net = new NETWORK::CHwdNetWork(
		xorstr("oudHA6NQ2YYC9b3D36xxXGoR3RkM5T7s").crypt_get()/*通讯密钥*/,
		xorstr("c398ebb5-114c-4258-bb5e-d97bff7a370b").crypt_get()/*软件sid*/,
		xorstr("ab310ac13de1e8c6c582b420bb014d05").crypt_get()/*ModuleMd5购买授权后获得*/,
		xorstr("e46f708329ce3f6c4d8cb1f7579f3d64").crypt_get()/*webkey*购买授权后获得*/,
		xorstr("[data]123[key]abc").crypt_get()/*客户端sign规则*/,
		xorstr("[data]cba[key]321").crypt_get()/*服务端sign规则*/,
		80/*服务器端口*/,
		xorstr("").crypt_get()/*服务器地址如：127.0.0.1*/,
		xorstr("en.php?s=8d703e0cf4c7f1434c4540a1f2066cc3").crypt_get()/*请求页*/);

    static size_t 请求次 = 0;
    static bool isOk = false;
    while (!(isOk = net->Init()) && 请求次 < 3) { 请求次++; };
    if (!isOk)
    {
        std::string 提示 = std::string(xorstr("网络初始化失败！请检查网络环境：").crypt_get()) + net->GetLastErroMsg();
        MessageBoxA(NULL, 提示.c_str(), xorstr("错误！").crypt_get(), MB_OK);
        return 0 ;
    }

    std::cout << "公告:" << net->GetNotice() << std::endl;
    std::cout << "软件名字:" << net->GetName() << std::endl;
    std::cout << "软件版本:" << net->GetVersion() << std::endl;
    std::cout << "客服qq:" << net->GetQq() << std::endl;
    std::cout << "软件下载地址:" << net->GetDownloadurl() << std::endl;

    if (net->UserLogin("HZUWCFF6n39MEBQK", "HZUWCFF6n39MEBQK"))
    {
        std::cout << "登录成功" << std::endl;
        std::cout << "余额"<<net->GetPoint() << std::endl;
    }
    else
    {
        std::cout << "登录失败" << std::endl;
        std::cout << "原因：" << net->GetLastErroMsg() << std::endl;
    }
    if (net->DeductPoint("1", NETWORK::DEDUCTPOINTMODE::ONEDAY_ONCE))
    {
        std::cout << "扣点成功" << std::endl;
        std::cout << "余额：" << net->GetPoint() << std::endl;
    }
    else
    {
        std::cout << "扣点失败" << std::endl;
        std::cout << "原因：" << net->GetLastErroMsg() << std::endl;
    }



    system("pause");
	return 0;
}


