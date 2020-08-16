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
	net = new NETWORK::CHwdNetWork(
		xorstr("YwqprshWcNdPksUUVnbaoox7boE73P6N").crypt_get()/*通讯密钥*/,
		xorstr("773c1e72-4d4a-4ef0-b970-bb4772c5a7b2").crypt_get()/*软件sid*/,
		xorstr("ab310ac13de1e8c6c582b420bb014d05").crypt_get()/*ModuleMd5购买授权后获得*/,
		xorstr("e46f708329ce3f6c4d8cb1f7579f3d64").crypt_get()/*webkey*购买授权后获得*/,
		xorstr("[data]123123[key]asdfg").crypt_get()/*客户端sign规则*/,
		xorstr("[data]asdfg[key]123123").crypt_get()/*客户端sign规则*/,
		80/*服务器端口*/,
		xorstr("").crypt_get()/*服务器地址如：127.0.0.1*/,
		xorstr("en.php?s=3f454239fd1a5385f1955449ba5a3b6f").crypt_get()/*请求页*/);

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

    system("pause");
	return 0;
}


