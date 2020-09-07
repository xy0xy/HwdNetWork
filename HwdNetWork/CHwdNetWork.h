/**************************************************************************

更新日期：2020年9月7日
说明：目前接口大部分完成，动态获取进程本身md5的部分还没完成
注意：
请将C++语言标准设置为std:C++17!!!!!!!!!!
请一定要设置为静态编译，
如果想实现动态dll编译的话（也就是多线程dll/MD  多线程调试dll/MDd）的话
请自己到githuub找 CJsonObject这个库，和 openssl的 库
自己完成替换然后把下面的 libcrypto.lib系列的预编译宏删掉

作者：Lains
联系方式：
lainswork@qq.com

本类库说明：
它是一个用来进行护卫盾网络验证对接用途的例子，你也可以直接使用它进行对接
护卫盾网络验证官网：http://www.huweidun.cn/

说明：



**************************************************************************/


#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <objbase.h>
#include <map>
#include <cmath>
#include"XorString.h"

#include <WinInet.h>
#pragma comment(lib, "WinInet.lib")


//使用CJsonObject库进行json字串格式化和使用，详情github搜索CJsonObject
#include "CJsonObject.hpp"

//md5生成类
#include "md5.h"

//Base64编解码类
#include "Base64.h"

//url编解码类
#include "url_encoder.h"

//使用开源库openssl的des加密类
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/err.h>

//机器码头文件
#include "HardWare.h"


//预编译宏，分别对应debug 32 、debug 64 、Release 32、 Release64
#ifdef _DEBUG  
#ifndef _WIN64  
#pragma comment(lib, "libcrypto_Debug_32.lib")
#else  
#pragma comment(lib, "libcrypto_Debug_64.lib")
#endif  
#else  
#ifndef _WIN64  
#pragma comment(lib, "libcrypto_Release_32.lib")
#else  
#pragma comment(lib, "libcrypto_Release_64.lib")

#endif  
#endif




#define GUID_LEN 64
#define OUT
#define IN

namespace NETWORK 
{
	struct Info
	{
		//键
		std::string Key;
		//值
		std::string Value;
	};

	//网页请求类别
	enum LAINSPATTERN
	{
		GET = 0,
		POST = 1
	};
	//扣点方式
	enum DEDUCTPOINTMODE
	{
		//一天一个ip或者机器码只扣一次
		ONEDAY_ONCE,
		//每次登录都会扣点（ps：貌似没啥用）
		EVERYTIME_ONCE,
	};

	class CHwdNetWork
	{

	public:
		//最后的错误信息，当接口返回为false时LastErroMsg将保存错误原因
		std::string GetLastErroMsg() 
		{
			return aes_256_cbc_decode(LastErroMsg, this->本地字串加密key);
		}
		//公告
		std::string GetNotice()
		{
			return aes_256_cbc_decode(notice, this->本地字串加密key);
		}
		//软件名字
		std::string GetName()
		{
			return aes_256_cbc_decode(name, this->本地字串加密key);
		}
		//版本号
		std::string GetVersion()
		{
			return aes_256_cbc_decode(version, this->本地字串加密key);
		}
		//客服QQ
		std::string GetQq()
		{
			return aes_256_cbc_decode(qq, this->本地字串加密key);
		}
		//软件下载网址
		std::string GetDownloadurl()
		{
			return aes_256_cbc_decode(downloadurl, this->本地字串加密key);
		}
		//软件更新网址
		std::string GetUpdateurl()
		{
			return aes_256_cbc_decode(updateurl, this->本地字串加密key);
		}
		//用户绑定资料,例如游戏号等
		std::string Getbind()
		{
			return aes_256_cbc_decode(bind, this->本地字串加密key);
		}
		//到期时间
		std::string GetEndtime()
		{
			return aes_256_cbc_decode(endtime, this->本地字串加密key);
		}
		//到期时间戳
		time_t GetEndTime_time_t()
		{
			return 到期时间戳;
		}
		//当前网络时间
		time_t GetInternetTime_time_t()
		{
			return 当前网络时间戳;
		}
		//点数余额
		std::string GetPoint()
		{
			return aes_256_cbc_decode(point, this->本地字串加密key);
		}
		//点数余额
		size_t GetPoint_size_t()
		{
			return 点数余额;
		}
		//用户自定义常量
		std::string GetPara()
		{
			return aes_256_cbc_decode(para, this->本地字串加密key);
		}
		//软件自定义常量
		std::string GetSoftpara()
		{
			return aes_256_cbc_decode(softpara, this->本地字串加密key);
		}
		//用户名
		std::string GetUser()
		{
			return aes_256_cbc_decode(user, this->本地字串加密key);
		}
		//密码
		std::string GetPass()
		{
			return aes_256_cbc_decode(pass, this->本地字串加密key);
		}
		//账户余额
		std::string GetBalance()
		{
			return aes_256_cbc_decode(balance, this->本地字串加密key);
		}


	private:
		//最后的错误信息，当接口返回为false时LastErroMsg将保存错误原因
		std::string LastErroMsg;
		//公告
		std::string notice;
		//软件名字
		std::string name;
		//版本号
		std::string version;
		//客服QQ
		std::string qq;
		//软件下载网址
		std::string downloadurl;
		//软件更新网址
		std::string updateurl;
		//用户绑定资料,例如游戏号等
		std::string bind;
		//到期时间
		std::string endtime;
		//到期时间戳
		time_t 到期时间戳;
		//当前网络时间
		time_t 当前网络时间戳;
		//点数余额
		std::string point;
		//点数余额
		size_t 点数余额;
		//用户自定义常量
		std::string para;
		//软件自定义常量
		std::string softpara;
		//用户名
		std::string user;
		//密码
		std::string pass;
		//账户余额
		std::string balance;
	public:
		CHwdNetWork(
			IN std::string _Key/*通讯密钥*/,
			IN std::string _Sid/*软件sid*/,
			IN std::string _ModuleMd5/*购买授权后获得*/,
			IN std::string _WebKey/*购买授权后获得*/,
			IN std::string _SignRuleClient/*客户端sign规则*/,
			IN std::string _SignRuleServer/*客户端sign规则*/,
			IN WORD _Port/*服务器端口*/,
			IN std::string _Domain/*服务器地址*/,
			IN std::string _PageAddr/*请求页*/)
		{
			//固定参数赋值
			Key = _Key;
			Sid = _Sid;
			Md5_3 = _ModuleMd5;
			WebKey = _WebKey;
			SignRuleClient = _SignRuleClient;
			SignRuleServer = _SignRuleServer;
			Domain = _Domain;
			PageAddr = _PageAddr;
			Port = _Port;

			//当前程序MD5值,如果开启校验MD5,则此值必填,可于程序运行时动态读取自身MD5值.

			//将exe的基质和大小传进去，获取自身程序md5 缺少功能
			Md5_2 = "";
			/*std::cout << "程序md5：" << Md5_2 <<std::endl;
			std::cout << std::endl;
			*/
			/*std::cout << "获取机器码"  << std::endl;
			std::cout << std::endl; system("pause");*/


			//机器码
			Mac_code = MD5(HardWare().strAllMacInfo).toString();

			/*std::cout << "机器码特征码：" << Mac_code << std::endl;
			std::cout << std::endl; system("pause");*/


			ClientId = generate();
			/*std::cout << "开始分解密钥" << std::endl;
			std::cout << std::endl; system("pause");*/
			//分解密钥
			客户端密钥 = Key.substr(0, 8);
			std::string 客iv向量 = Key.substr(24, 8);
			for (size_t i = 0; i < 8; i++)
			{
				客户端IV向量[i] = 客iv向量[i];
			}

			服务端密钥 = Key.substr(8, 8);
			std::string 服iv向量 = Key.substr(16, 8);
			for (size_t i = 0; i < 8; i++)
			{
				服务端IV向量[i] = 服iv向量[i];
			}
			//生成一个AES密钥，用来对本地保存的数据（文本数据）进行加密，防止在od或者debug中被搜索到
			//密钥需要设定为32位
			auto rand_str = _GetRandStr(32);
			char* rand_Key = rand_str.get();
			本地字串加密key = std::string(rand_Key);
			/*std::cout << "构造函数结束" << std::endl;
			std::cout << std::endl; system("pause");*/
		}
		~CHwdNetWork()
		{

		}

		//初始化验证
		bool Init()
		{
			Info info;
			info.Key = xorstr("action").crypt_get();
			info.Value = xorstr("init").crypt_get();
			std::vector<Info> test;
			test.push_back(info);

			neb::CJsonObject retJson;
			if (HttpRequest(test, retJson))
			{
				std::string codestr;
				retJson.Get(xorstr("code").crypt_get(), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(xorstr("result").crypt_get(), result);

					result.Get(xorstr("notice").crypt_get(), this->notice);
					result.Get(xorstr("name").crypt_get(), this->name);
					result.Get(xorstr("version").crypt_get(), this->version);
					result.Get(xorstr("qq").crypt_get(), this->qq);
					result.Get(xorstr("downloadurl").crypt_get(), this->downloadurl);
					result.Get(xorstr("updateurl").crypt_get(), this->updateurl);

					this->notice = aes_256_cbc_encode(notice, 本地字串加密key);
					this->name = aes_256_cbc_encode(name, 本地字串加密key);
					this->version = aes_256_cbc_encode(version, 本地字串加密key);
					this->qq = aes_256_cbc_encode(qq, 本地字串加密key);
					this->downloadurl = aes_256_cbc_encode(downloadurl, 本地字串加密key);
					this->updateurl = aes_256_cbc_encode(updateurl, 本地字串加密key);

					return true;
				}
				else
				{
					LastErroMsg = aes_256_cbc_encode(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = aes_256_cbc_encode(xorstr("请求失败！").crypt_get(), 本地字串加密key);
				return false;
			}

		}
		//用户登录
		bool UserLogin(IN std::string username/*用户名*/, IN std::string password/*密码*/)
		{
			//action=login&user=用户名&pwd=密码&code=验证码
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = xorstr("action").crypt_get();
			api.Value = xorstr("login").crypt_get();
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = xorstr("user").crypt_get();
			Var1.Value = username;
			PostMsgInfo.push_back(Var1);
			Info Var2;
			Var2.Key = xorstr("pwd").crypt_get();
			Var2.Value = password;
			PostMsgInfo.push_back(Var2);


			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(xorstr("code").crypt_get(), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(xorstr("result").crypt_get(), result);

					result.Get(xorstr("bind").crypt_get(), bind);
					result.Get(xorstr("endtime").crypt_get(), endtime);
					到期时间戳 = StringToDatetime(endtime);
					result.Get(xorstr("para").crypt_get(), para);
					result.Get(xorstr("point").crypt_get(), point);
					点数余额 = atoi(point.c_str());
					result.Get(xorstr("softpara").crypt_get(), softpara);
					result.Get(xorstr("user").crypt_get(), user);

					this->bind = aes_256_cbc_encode(this->bind, 本地字串加密key);
					this->endtime = aes_256_cbc_encode(this->endtime, 本地字串加密key);
					this->para = aes_256_cbc_encode(this->para, 本地字串加密key);
					this->point = aes_256_cbc_encode(this->point, 本地字串加密key);
					this->softpara = aes_256_cbc_encode(this->softpara, 本地字串加密key);
					this->user = aes_256_cbc_encode(this->user, 本地字串加密key);
					pass = password;
					this->pass = aes_256_cbc_encode(password, 本地字串加密key);
					return true;
				}
				else
				{
					LastErroMsg = aes_256_cbc_encode(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = aes_256_cbc_encode(xorstr("请求失败！").crypt_get(), 本地字串加密key);
				return false;
			}
			return false;
		}
		//心跳包
		bool HeartBeat()
		{
			//action=heartbeat&user=用户名
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = xorstr("action").crypt_get();
			api.Value = xorstr("heartbeat").crypt_get();
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = xorstr("user").crypt_get();
			Var1.Value = this->GetUser();
			PostMsgInfo.push_back(Var1);



			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(xorstr("code").crypt_get(), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(xorstr("result").crypt_get(), result);

					result.Get(xorstr("bind").crypt_get(), bind);
					result.Get(xorstr("endtime").crypt_get(), endtime);
					到期时间戳 = StringToDatetime(endtime);
					result.Get(xorstr("para").crypt_get(), para);
					result.Get(xorstr("point").crypt_get(), point);
					点数余额 = atoi(point.c_str());
					result.Get(xorstr("softpara").crypt_get(), softpara);

					bind = aes_256_cbc_encode(bind, 本地字串加密key);
					endtime = aes_256_cbc_encode(endtime, 本地字串加密key);
					para = aes_256_cbc_encode(para, 本地字串加密key);
					point = aes_256_cbc_encode(point, 本地字串加密key);
					softpara = aes_256_cbc_encode(softpara, 本地字串加密key);


					return true;
				}
				else
				{

					LastErroMsg = aes_256_cbc_encode(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = aes_256_cbc_encode(xorstr("请求失败！").crypt_get(), 本地字串加密key);
				return false;
			}
			return false;
		}
		//绑定用户信息
		bool BindStr(IN std::string str/*绑定内容*/)
		{
			//action=bindstr&user=用户名&pwd=密码&str=绑定内容
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = xorstr("action").crypt_get();
			api.Value = xorstr("bindstr").crypt_get();
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = xorstr("user").crypt_get();
			Var1.Value = this->GetUser();
			PostMsgInfo.push_back(Var1);
			Info Var2;
			Var2.Key = xorstr("pwd").crypt_get();
			Var2.Value = this->GetPass();
			PostMsgInfo.push_back(Var2);
			Info Var3;
			Var3.Key = xorstr("str").crypt_get();
			Var3.Value = str;
			PostMsgInfo.push_back(Var3);


			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(xorstr("code").crypt_get(), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					return true;
				}
				else
				{
					LastErroMsg = aes_256_cbc_encode(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = aes_256_cbc_encode(xorstr("请求失败！").crypt_get(), 本地字串加密key);
				return false;
			}
			return false;
		}
		//绑定机器码
		bool BindMac(IN std::string username/*用户名*/)
		{
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = xorstr("action").crypt_get();
			api.Value = xorstr("bind").crypt_get();
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = xorstr("user").crypt_get();
			Var1.Value = username;
			PostMsgInfo.push_back(Var1);


			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(xorstr("code").crypt_get(), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					return true;
				}
				else
				{
					LastErroMsg = aes_256_cbc_encode(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = aes_256_cbc_encode(xorstr("请求失败！").crypt_get(), 本地字串加密key);
				return false;
			}
			return false;
		}
		//充值
		bool RechArge(IN std::string username/*用户名*/, IN std::string cdkey/*充值卡*/)
		{
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = xorstr("action").crypt_get();
			api.Value = xorstr("recharge").crypt_get();
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = xorstr("user").crypt_get();
			Var1.Value = username;
			PostMsgInfo.push_back(Var1);
			Info Var2;
			Var2.Key = xorstr("card").crypt_get();
			Var2.Value = cdkey;
			PostMsgInfo.push_back(Var2);


			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(xorstr("code").crypt_get(), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(xorstr("result").crypt_get(), result);

					result.Get(xorstr("balance").crypt_get(), balance);
					result.Get(xorstr("endtime").crypt_get(), endtime);
					到期时间戳 = StringToDatetime(endtime);
					result.Get(xorstr("point").crypt_get(), point);
					点数余额 = atoi(point.c_str());

					balance = aes_256_cbc_encode(balance, 本地字串加密key);
					endtime = aes_256_cbc_encode(endtime, 本地字串加密key);
					point = aes_256_cbc_encode(point, 本地字串加密key);

					return true;
				}
				else
				{
					LastErroMsg = aes_256_cbc_encode(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = aes_256_cbc_encode(xorstr("请求失败！").crypt_get(), 本地字串加密key);
				return false;
			}
			return false;
		}
		//扣点
		bool DeductPoint(IN std::string number/*扣除点数*/, IN DEDUCTPOINTMODE mode/*扣点方式*/)
		{
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = xorstr("action").crypt_get();
			api.Value = xorstr("deductpoint").crypt_get();
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = xorstr("user").crypt_get();
			Var1.Value = this->GetUser();
			PostMsgInfo.push_back(Var1);
			Info Var2;
			Var2.Key = xorstr("num").crypt_get();
			Var2.Value = number;
			PostMsgInfo.push_back(Var2);

			Info Var3;
			if (mode == DEDUCTPOINTMODE::ONEDAY_ONCE)
			{

				Var3.Key = xorstr("filter").crypt_get();
				Var3.Value = xorstr("1").crypt_get();
				PostMsgInfo.push_back(Var3);
				Info Var4;
				Var4.Key = xorstr("msg").crypt_get();
				time_t today = time(NULL);
				Var4.Value = Mac_code + DatetimeToString(today, true, false, false, false);
				PostMsgInfo.push_back(Var4);
			}
			else
			{
				Var3.Key = xorstr("filter").crypt_get();
				Var3.Value = xorstr("0").crypt_get();
				PostMsgInfo.push_back(Var3);
			}

			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(xorstr("code").crypt_get(), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(xorstr("result").crypt_get(), result);
					result.Get(xorstr("point").crypt_get(), point);
					点数余额 = atoi(point.c_str());
					point = aes_256_cbc_encode(point, 本地字串加密key);

					return true;
				}
				else
				{

					LastErroMsg = aes_256_cbc_encode(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = aes_256_cbc_encode(xorstr("请求失败！").crypt_get(), 本地字串加密key);
				return false;
			}
			return false;
		}
		//扣时
		bool DeductTime(IN std::string number/*扣除分钟*/)
		{
			//action=deducttime&user=扣时账号&num=扣除分钟&msg=扣时备注&filter=0
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = xorstr("action").crypt_get();
			api.Value = xorstr("deducttime").crypt_get();
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = xorstr("user").crypt_get();
			Var1.Value = this->GetUser();
			PostMsgInfo.push_back(Var1);
			Info Var3;
			Var3.Key = xorstr("num").crypt_get();
			Var3.Value = number;
			PostMsgInfo.push_back(Var3);
			Info Var4;
			Var4.Key = xorstr("msg").crypt_get();
			Var4.Value = xorstr("扣点日期:").crypt_get() + DatetimeToString(time(NULL), true, true, true, false);
			PostMsgInfo.push_back(Var4);
			Info Var5;
			Var5.Key = xorstr("filter").crypt_get();
			Var5.Value = xorstr("0").crypt_get();
			PostMsgInfo.push_back(Var5);

			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(xorstr("code").crypt_get(), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(xorstr("result").crypt_get(), result);

					result.Get(xorstr("endtime").crypt_get(), endtime);
					到期时间戳 = StringToDatetime(endtime);
					endtime = aes_256_cbc_encode(endtime, 本地字串加密key);
					return true;
				}
				else
				{
					LastErroMsg = aes_256_cbc_encode(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = aes_256_cbc_encode(xorstr("请求失败！").crypt_get(), 本地字串加密key);
				return false;
			}
			return false;
		}
		//登出
		bool LogOut()
		{
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = xorstr("action").crypt_get();
			api.Value = xorstr("logout").crypt_get();
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = xorstr("user").crypt_get();
			Var1.Value = this->GetUser();
			PostMsgInfo.push_back(Var1);

			//测试
			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(xorstr("code").crypt_get(), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					return true;
				}
				else
				{
					LastErroMsg = aes_256_cbc_encode(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = aes_256_cbc_encode(xorstr("请求失败！").crypt_get(), 本地字串加密key);
				return false;
			}
			return false;
		}

	private:
		std::string 客户端密钥;
		char 客户端IV向量[8] = { 0 };
		std::string 服务端密钥;
		char 服务端IV向量[8] = { 0 };
		std::string 本地字串加密key;
	private:
		//通讯密钥
		std::string Key;
		//软件sid
		std::string Sid;
		//时间戳
		std::string Time;
		//临时封包token(sid+key+t 拼接后取MD5值)
		std::string Md5_1;
		//当前程序MD5值,如果开启校验MD5,则此值必填,可于程序运行时动态读取自身MD5值.
		std::string Md5_2;
		//moduleMd5,购买授权后获得
		std::string Md5_3;
		//机器码
		std::string Mac_code;
		//客户端id，用于识别客户端，防止同时多个登录
		std::string ClientId;
		//通用秘钥(webKey),购买授权后获得.
		std::string WebKey;

		//客户端sign拼接规则
		std::string SignRuleClient;
		//服务端sign拼接规则
		std::string SignRuleServer;
		//服务器地址
		std::string Domain;
		//请求页
		std::string PageAddr;
		//服务器端口
		WORD Port;





	private:
		//发送请求并返回数据
		BOOL HttpRequest(std::vector<NETWORK::Info>& Variable, neb::CJsonObject& RetJson_)
		{
			/*组包发送*/
			std::string uuid = this->generate();
			int Time = time(NULL);
			std::string timeStr = std::to_string(Time);
			neb::CJsonObject json;
			//固定参数
			json.Add(xorstr("sid").crypt_get(), this->Sid);
			json.Add(xorstr("uuid").crypt_get(), uuid);
			json.Add(xorstr("t").crypt_get(), Time);
			json.Add(xorstr("m1").crypt_get(), MD5(this->Sid + this->Key + timeStr).toString());
			json.Add(xorstr("m2").crypt_get(), this->Md5_2);
			json.Add(xorstr("m3").crypt_get(), this->Md5_3);
			json.Add(xorstr("mcode").crypt_get(), this->Mac_code);
			json.Add(xorstr("clientid").crypt_get(), this->ClientId);
			json.Add(xorstr("webkey").crypt_get(), this->WebKey);
			//可变参数
			for (size_t i = 0; i < Variable.size(); i++)
			{
				json.Add(Variable[i].Key, Variable[i].Value);
			}
			/*std::cout << "发送明文：" << json.ToString() << std::endl;
			std::cout << std::endl;*/
			//机器码
			//转为UTF8编码
			std::string UTF8_Str = this->string_To_UTF8(json.ToString());
			//进行DES加密
			std::string DES加密 = this->des_cbc_encrypt(UTF8_Str, this->客户端密钥);
			//进行base64编码
			std::string base编码 = base64_encode((unsigned char const*)DES加密.c_str(), DES加密.length());

			//进行sign拼接
			std::string sign拼接 = this->SignRuleClient;
			sign拼接 = this->replace_all(sign拼接, xorstr("[data]").crypt_get(), base编码);
			sign拼接 = this->replace_all(sign拼接, xorstr("[key]").crypt_get(), this->Key);
			std::string sign值 = MD5(sign拼接).toString();

			//进行url编码，防止传输过程中丢失特殊字符
			UrlEncoder url;
			std::string url编码 = url.Encode(base编码, false);

			//进行封包 
			std::string 数据 = xorstr("data=").crypt_get() + url编码 + xorstr("&sign=").crypt_get() + sign值;
			/*std::cout << "发送密文：" << 数据 << std::endl;
			std::cout << std::endl;*/
			//发送封包
			std::string 返回数据 = this->GetWeb(this->Domain, this->Port, this->PageAddr, NETWORK::LAINSPATTERN::POST, 数据);
			/*std::cout << "返回密文：" << 返回数据 << std::endl;
			std::cout <<  std::endl;*/

			/*解包验证*/

			//取得密文与sign
			neb::CJsonObject RetJson(返回数据);
			std::string RetData;
			std::string RetSign;
			RetJson.Get(xorstr("data").crypt_get(), RetData);
			RetJson.Get(xorstr("sign").crypt_get(), RetSign);
			//url解码
			UrlEncoder RetUrl;
			std::string url解码;
			RetUrl.Decode(RetData, &url解码);
			//进行sign拼接
			std::string Retsign拼接 = this->SignRuleServer;
			Retsign拼接 = this->replace_all(Retsign拼接, xorstr("[data]").crypt_get(), url解码);
			Retsign拼接 = this->replace_all(Retsign拼接, xorstr("[key]").crypt_get(), this->Key);
			std::string Retsign值 = MD5(Retsign拼接).toString();

			//校验封包合法性   1对比sign值是否正确、2对比封包uuid是否正确、3对比封包时间是否相差太长、

			//对比sign值
			if (Retsign值 != RetSign)
			{
				return false;
			}
			//解密数据
			std::string base解码 = base64_decode(url解码);
			//DES解密
			std::string 返回解密数据 = this->UTF8_To_string(this->des_cbc_decrypt(base解码, this->服务端密钥));
			//json明文
			/*std::cout << std::endl;
			std::cout << std::endl;
			std::cout << "返回的json明文：" << 返回解密数据 << std::endl;
			std::cout << std::endl;
			std::cout << std::endl;*/
			//std::string retstring = UnEscapeUTF8((char*)返回解密数据.c_str());

			//这里进行了两次UTF8转换和两次json转换，是为了解决乱码bug，玄学。
			RetJson_ = (this->UTF8_To_string(neb::CJsonObject(返回解密数据).ToString()));


			std::string uuid_new;
			RetJson_.Get(xorstr("uuid").crypt_get(), uuid_new);
			int time_new = 0;
			RetJson_.Get(xorstr("t").crypt_get(), time_new);
			this->当前网络时间戳 = time_new;
			if (!(uuid_new == uuid && abs(time_new - time(NULL)) < 10))
			{
				return false;
			}

			return true;
		}

		//替换字串
		std::string& replace_all(std::string& str, const   std::string& old_value, const   std::string& new_value)
		{
			while (true) {
				std::string::size_type   pos(0);
				if ((pos = str.find(old_value)) != std::string::npos)
					str.replace(pos, old_value.length(), new_value);
				else   break;
			}
			return   str;
		}
		//字串转换
		std::string UTF8_To_string(const std::string& str)
		{
			int nwLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
			wchar_t* pwBuf = new wchar_t[nwLen + 1];    //一定要加1，不然会出现尾巴 
			memset(pwBuf, 0, nwLen * 2 + 2);
			MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), pwBuf, nwLen);
			int nLen = WideCharToMultiByte(CP_ACP, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
			char* pBuf = new char[nLen + 1];
			memset(pBuf, 0, nLen + 1);
			WideCharToMultiByte(CP_ACP, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);

			std::string strRet = pBuf;

			delete[]pBuf;
			delete[]pwBuf;
			pBuf = NULL;
			pwBuf = NULL;

			return strRet;
		}
		std::string UTF8_To_string(char* szCode)
		{
			string strRet = "";
			for (int i = 0; i < 4; i++)
			{
				if (szCode[i] >= '0' && szCode[i] <= '9')	continue;
				if (szCode[i] >= 'A' && szCode[i] <= 'F')	continue;
				if (szCode[i] >= 'a' && szCode[i] <= 'f')	continue;
				return strRet;
			}

			char unicode_hex[5] = { 0 };
			memcpy(unicode_hex, szCode, 4);
			unsigned int iCode = 0;
			sscanf_s(unicode_hex, "%04x", &iCode);
			wchar_t wchChar[4] = { 0 };
			wchChar[0] = iCode;

			char szAnsi[8] = { 0 };
			WideCharToMultiByte(CP_ACP, NULL, wchChar, 1, szAnsi, sizeof(szAnsi), NULL, NULL);
			strRet = string(szAnsi);

			return strRet;

		}
		//字串转换
		std::string string_To_UTF8(const std::string& str)
		{
			int nwLen = ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
			wchar_t* pwBuf = new wchar_t[nwLen + 1];    //一定要加1，不然会出现尾巴 
			ZeroMemory(pwBuf, nwLen * 2 + 2);
			::MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), pwBuf, nwLen);
			int nLen = ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
			char* pBuf = new char[nLen + 1];
			ZeroMemory(pBuf, nLen + 1);
			::WideCharToMultiByte(CP_UTF8, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);

			std::string strRet(pBuf);

			delete[]pwBuf;
			delete[]pBuf;
			pwBuf = NULL;
			pBuf = NULL;

			return strRet;
		}
		//发送http请求
		std::string GetWeb(std::string Domain, WORD Port, std::string PageAddr, DWORD Pattern, std::string PostBuff)
		{
			HINTERNET hInternet, hConnect, hRequest;
			DWORD len = 0;
			std::string WebRet;
			char useragent[] = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)";
			std::string headers = "Accept: */*\n\rAccept-Language: zh-cn\n\rContent-Type: application/x-www-form-urlencoded\n\r";
			headers = headers + "Referer: " + Domain + PageAddr;
			std::string sPattern;
			if (Pattern == 1)
				sPattern = "POST";
			else
				sPattern = "GET";
			hInternet = InternetOpenA(useragent, 1, NULL, NULL, NULL);
			if (hInternet)
			{
				hConnect = InternetConnectA(hInternet, Domain.c_str(), Port, NULL, NULL, 3, NULL, NULL);
				if (hConnect)
				{
					hRequest = HttpOpenRequestA(hConnect, sPattern.c_str(), PageAddr.c_str(), "HTTP/1.1", NULL, NULL, (INTERNET_FLAG_RELOAD && INTERNET_COOKIE_THIRD_PARTY && INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS), 0);
					if (hRequest)
					{
						HttpSendRequestA(hRequest, headers.c_str(), headers.length(), (LPVOID)(PostBuff.c_str()), PostBuff.length());
						char* Temp = new char[4096];
						while (true)
						{
							memset(Temp, 0, 4096);
							InternetReadFile(hRequest, Temp, 4096, &len);
							WebRet = WebRet + Temp;
							if (len == 0)
							{
								delete[] Temp;
								break;
							}
						}
						InternetCloseHandle(hRequest);
					}
					InternetCloseHandle(hConnect);
				}
				InternetCloseHandle(hInternet);
			}
			return WebRet;
		}
		//des cbc模式加密填充模式nopadding
		std::string des_cbc_encrypt(const std::string& Text, const std::string& key)
		{
			std::string strCipherText;
			DES_cblock keyEncrypt, ivec;
			memset(keyEncrypt, 0, 8);
			if (key.length() <= 8)
				memcpy(keyEncrypt, key.c_str(), key.length());
			else
				memcpy(keyEncrypt, key.c_str(), 8);
			DES_key_schedule keySchedule;  //密钥表
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);   //设置密钥，且不检测密钥奇偶性  
			memcpy(ivec, 客户端IV向量, sizeof(客户端IV向量));
			// 循环加密，每8字节一次    
			const_DES_cblock inputText;
			unsigned char outputText[9];
			std::vector<unsigned char> vecCiphertext;
			unsigned char tmp[8];
			string clearText = Text;

			while (clearText.length() % 8 != 0)
			{
				clearText += ' ';
			}
			char sp[100] = { '\0' };
			memset(sp, ' ', 99);
			clearText += sp;
			for (int i = 0; i < clearText.length() / 8; i++)
			{
				memcpy(inputText, clearText.c_str() + i * 8, 8);
				DES_ncbc_encrypt(inputText, outputText, 8, &keySchedule, &ivec, DES_ENCRYPT);  //加密
				memcpy(tmp, outputText, 8);

				for (int j = 0; j < 8; j++)
					vecCiphertext.push_back(tmp[j]);

				//重置ivec
				memcpy(ivec, outputText, 8);
			}

			strCipherText.clear();
			strCipherText.assign(vecCiphertext.begin(), vecCiphertext.end());
			return strCipherText;
		}
		//解密 cbc 
		std::string des_cbc_decrypt(const std::string& cipherText, const std::string& key)
		{
			//static unsigned char cbc_iv[8] = { 'w', '6', 'n', 'E', 'w', 'U', '3', 't' };//vPVaKkC3  w6nEwU3t
			//初始化IV向量 
			std::string clearText;
			DES_cblock keyEncrypt, ivec;
			memset(keyEncrypt, 0, 8);

			if (key.length() <= 8)
				memcpy(keyEncrypt, key.c_str(), key.length());
			else
				memcpy(keyEncrypt, key.c_str(), 8);

			DES_key_schedule keySchedule;  //密钥表
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);   //设置密钥，且不检测密钥奇偶性  

			memcpy(ivec, 服务端IV向量, sizeof(服务端IV向量));

			// 循环解密，每8字节一次    
			const_DES_cblock inputText;
			DES_cblock outputText;
			std::vector<unsigned char> vecCleartext;
			unsigned char tmp[8];

			for (int i = 0; i < cipherText.length() / 8; i++)
			{
				memcpy(inputText, cipherText.c_str() + i * 8, 8);
				DES_ncbc_encrypt(inputText, outputText, 8, &keySchedule, &ivec, DES_DECRYPT);  //解密
				memcpy(tmp, outputText, 8);

				for (int j = 0; j < 8; j++)
					vecCleartext.push_back(tmp[j]);

				//重置ivec
				//memcpy(ivec, outputText, 8);  //解密过程不需要用前一块的结果作为下一块的IV
			}

			if (clearText.length() % 8 != 0)
			{
				int tmp1 = clearText.length() / 8 * 8;
				int tmp2 = clearText.length() - tmp1;
				memset(inputText, ' ', tmp2);
				memcpy(inputText, cipherText.c_str() + tmp1, tmp2);
				DES_ncbc_encrypt(inputText, outputText, tmp2, &keySchedule, &ivec, DES_DECRYPT);  //解密
				memcpy(tmp, outputText, tmp2);
				for (int j = 0; j < 8; j++)
					vecCleartext.push_back(tmp[j]);
			}

			clearText.clear();
			clearText.assign(vecCleartext.begin(), vecCleartext.end());
			return clearText;
		}
		//AES加密
		std::string aes_256_cbc_encode(const std::string& data, const std::string& password)
		{
			// 这里默认将iv全置为字符0
			unsigned char iv[AES_BLOCK_SIZE] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0' };

			AES_KEY aes_key;
			if (AES_set_encrypt_key((const unsigned char*)password.c_str(), password.length() * 8, &aes_key) < 0)
			{
				//assert(false);
				return "";
			}
			std::string strRet;
			std::string data_bak = data;
			unsigned int data_length = data_bak.length();

			// ZeroPadding
			int padding = 0;
			if (data_bak.length() % (AES_BLOCK_SIZE) > 0)
			{
				padding = AES_BLOCK_SIZE - data_bak.length() % (AES_BLOCK_SIZE);
			}
			// 在一些软件实现中，即使是16的倍数也进行了16长度的补齐
			/*else
			{
				padding = AES_BLOCK_SIZE;
			}*/

			data_length += padding;
			while (padding > 0)
			{
				data_bak += '\0';
				padding--;
			}

			for (unsigned int i = 0; i < data_length / (AES_BLOCK_SIZE); i++)
			{
				std::string str16 = data_bak.substr(i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
				unsigned char out[AES_BLOCK_SIZE];
				::memset(out, 0, AES_BLOCK_SIZE);
				AES_cbc_encrypt((const unsigned char*)str16.c_str(), out, AES_BLOCK_SIZE, &aes_key, iv, AES_ENCRYPT);
				strRet += std::string((const char*)out, AES_BLOCK_SIZE);
			}

			return base64_encode((unsigned char const*)strRet.c_str(), strRet.length());
		}
		//AES解密
		std::string aes_256_cbc_decode(const std::string& strData,const std::string& password)
		{
			std::string str_decode_base64 = base64_decode(strData);
			// 这里默认将iv全置为字符0
			unsigned char iv[AES_BLOCK_SIZE] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0' };

			AES_KEY aes_key;
			if (AES_set_decrypt_key((const unsigned char*)password.c_str(), password.length() * 8, &aes_key) < 0)
			{
				//assert(false);
				return "";
			}
			std::string strRet;
			for (unsigned int i = 0; i < str_decode_base64.length() / AES_BLOCK_SIZE; i++)
			{
				std::string str16 = str_decode_base64.substr(i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
				unsigned char out[AES_BLOCK_SIZE];
				::memset(out, 0, AES_BLOCK_SIZE);
				AES_cbc_encrypt((const unsigned char*)str16.c_str(), out, AES_BLOCK_SIZE, &aes_key, iv, AES_DECRYPT);
				strRet += std::string((const char*)out, AES_BLOCK_SIZE);
			}
			return strRet;
		}
		//Guid(全球唯一识别码)生成方法
		std::string generate()
		{
			char buf[GUID_LEN] = { 0 };
			GUID guid;

			if (CoCreateGuid(&guid))
			{
				return std::move(std::string(""));
			}

			sprintf(buf,
				"%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X",
				guid.Data1, guid.Data2, guid.Data3,
				guid.Data4[0], guid.Data4[1], guid.Data4[2],
				guid.Data4[3], guid.Data4[4], guid.Data4[5],
				guid.Data4[6], guid.Data4[7]);

			return std::move(std::string(buf));
		}
		//获取随机字符串
		std::unique_ptr<char[]> _GetRandStr(IN int SIZE_CHAR)
		{

			//char* result = applyBuffer(SIZE_CHAR + 1);

			static const char CCH[] = "_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";

			std::unique_ptr<char[]> result(new char[SIZE_CHAR + 1]());

			int cchLen = sizeof(CCH);

			srand((unsigned)time(NULL));

			for (int i = 0; i < SIZE_CHAR; ++i)
			{

				//int x = rand() % (sizeof(CCH) - 1); //这个方法不好, 因为许多随机数发生器的低位比特并不随机,
				//RAND MAX 在ANSI 里#define 在<stdlib.h>
				//RAND MAX 是个常数, 它告诉你C 库函数rand() 的固定范围。
				//不可以设RAND MAX 为其它的值, 也没有办法要求rand() 返回其它范围的值。

				int x = rand() / (RAND_MAX / (cchLen - 1));
				result[i] = CCH[x];
			}

			return result;
		}

		//格式化输出时间戳，后面的参数是精确度
		std::string DatetimeToString(time_t time, bool day_, bool hour_, bool minute_, bool second_)
		{
			tm* tm_ = localtime(&time);                // 将time_t格式转换为tm结构体
			int year, month, day, hour, minute, second;// 定义时间的各个int临时变量。
			year = tm_->tm_year + 1900;                // 临时变量，年，由于tm结构体存储的是从1900年开始的时间，所以临时变量int为tm_year加上1900。
			month = tm_->tm_mon + 1;                   // 临时变量，月，由于tm结构体的月份存储范围为0-11，所以临时变量int为tm_mon加上1。
			day = tm_->tm_mday;                        // 临时变量，日。
			hour = tm_->tm_hour;                       // 临时变量，时。
			minute = tm_->tm_min;                      // 临时变量，分。
			second = tm_->tm_sec;                      // 临时变量，秒。
			char yearStr[5], monthStr[3], dayStr[3], hourStr[3], minuteStr[3], secondStr[3];// 定义时间的各个char*变量。
			sprintf(yearStr, "%d", year);              // 年。
			sprintf(monthStr, "%d", month);            // 月。
			sprintf(dayStr, "%d", day);                // 日。
			sprintf(hourStr, "%d", hour);              // 时。
			sprintf(minuteStr, "%d", minute);          // 分。
			if (minuteStr[1] == '\0')                  // 如果分为一位，如5，则需要转换字符串为两位，如05。
			{
				minuteStr[2] = '\0';
				minuteStr[1] = minuteStr[0];
				minuteStr[0] = '0';
			}
			sprintf(secondStr, "%d", second);          // 秒。
			if (secondStr[1] == '\0')                  // 如果秒为一位，如5，则需要转换字符串为两位，如05。
			{
				secondStr[2] = '\0';
				secondStr[1] = secondStr[0];
				secondStr[0] = '0';
			}

			if (day_)
			{
				return(std::string(yearStr) + "年" + std::string(monthStr) + "月" + std::string(dayStr) + "日");
			}
			else if (hour_)
			{
				return(std::string(yearStr) + "年" + std::string(monthStr) + "月" + std::string(dayStr) + "日" + std::string(hourStr) + "时");
			}
			else if (minute_)
			{
				return(std::string(yearStr) + "年" + std::string(monthStr) + "月" + std::string(dayStr) + "日" + std::string(hourStr) + "时" + std::string(minuteStr) + "分");
			}
			else if (second_)
			{
				return(std::string(yearStr) + "年" + std::string(monthStr) + "月" + std::string(dayStr) + "日" + std::string(hourStr) + "时" + std::string(minuteStr) + "分" + std::string(secondStr) + "秒");
			}
			else
			{
				return(std::string(yearStr) + "年" + std::string(monthStr) + "月" + std::string(dayStr) + "日" + std::string(hourStr) + "时" + std::string(minuteStr) + "分" + std::string(secondStr) + "秒");
			}

		}
		time_t StringToDatetime(std::string str)
		{
			char* cha = (char*)str.data();             // 将string转换成char*。
			tm tm_;                                    // 定义tm结构体。
			int year, month, day, hour, minute, second;// 定义时间的各个int临时变量。
			sscanf(cha, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second);// 将string存储的日期时间，转换为int临时变量。
			tm_.tm_year = year - 1900;                 // 年，由于tm结构体存储的是从1900年开始的时间，所以tm_year为int临时变量减去1900。
			tm_.tm_mon = month - 1;                    // 月，由于tm结构体的月份存储范围为0-11，所以tm_mon为int临时变量减去1。
			tm_.tm_mday = day;                         // 日。
			tm_.tm_hour = hour;                        // 时。
			tm_.tm_min = minute;                       // 分。
			tm_.tm_sec = second;                       // 秒。
			tm_.tm_isdst = 0;                          // 非夏令时。
			time_t t_ = mktime(&tm_);                  // 将tm结构体转换成time_t格式。
			return t_;                                 // 返回值。
		}


		private:

			static std::map<size_t, std::string> ErroMap;
			std::string GetMessageWithErroCode(size_t code)
			{
				std::map<size_t, std::string>::iterator iter;
				iter = ErroMap.find(code);
				if (iter != ErroMap.end())
				{
					return iter->second;
				}
				else
				{
					return "错误代码不明";
				}
			}



	};

	std::map<size_t, std::string> CHwdNetWork::ErroMap =
	{
		{ 201 , xorstr("软件不存在").crypt_get()},
		{ 202 , xorstr("通信秘钥校验失败").crypt_get()},
		{ 203 , xorstr("软件MD5校验失败").crypt_get()},
		{ 206 , xorstr("账号或密码错误").crypt_get()},
		{ 207 , xorstr("充值卡不存在").crypt_get()},
		{ 209 , xorstr("当前机器码与绑定机器不符").crypt_get()},
		{ 210 , xorstr("您的账户已过期,请充值后登录").crypt_get()},
		{ 211 , xorstr("您的账户点数为0,请充值后登录").crypt_get()},
		{ 212 , xorstr("软件维护").crypt_get()},
		{ 213 , xorstr("通行证被封停,禁止登录").crypt_get()},
		{ 214 , xorstr("您的账户已过期,无法转绑,使用本机充值后将自动绑定至本机").crypt_get()},
		{ 215 , xorstr("您的剩余时间不足以支付转绑扣除时间,请充值.使用本机充值后将自动绑定至本机").crypt_get()},
		{ 216 , xorstr("转绑失败,未知原因,请联系客服处理").crypt_get()},
		{ 217 , xorstr("您的账户点数为0,无法转绑,使用本机充值后将自动绑定至本机").crypt_get()},
		{ 218 , xorstr("您的剩余点数不足以支付转绑扣除点数,请充值.使用本机充值后将自动绑定至本机").crypt_get()},
		{ 219 , xorstr("充值账号不存在").crypt_get()},
		{ 220 , xorstr("充值卡不存在").crypt_get()},
		{ 221 , xorstr("充值卡类目不存在,请联系客服").crypt_get()},
		{ 222 , xorstr("您的充值卡与当前账号类型不符,请到期后再充值").crypt_get()},
		{ 223 , xorstr("您的充值卡与当前账号类型不符,请将点数用完后再充值").crypt_get()},
		{ 224 , xorstr("扣点账户不存在").crypt_get()},
		{ 225 , xorstr("点数不足,扣点失败").crypt_get()},
		{ 226 , xorstr("扣点失败,未知原因,请联系客服").crypt_get()},
		{ 227 , xorstr("账户被封停,禁止登录").crypt_get()},
		{ 228 , xorstr("通行证已删除,即将下线").crypt_get()},
		{ 229 , xorstr("通行证已被封停,即将下线").crypt_get()},
		{ 230 , xorstr("软件账户已被删除,即将下线").crypt_get()},
		{ 231 , xorstr("软件账户已被封停,即将下线").crypt_get()},
		{ 232 , xorstr("您的点数为0,即将下线").crypt_get()},
		{ 233 , xorstr("您的账户已到期,即将下线").crypt_get()},
		{ 234 , xorstr("您的账户已离线,即将关闭.").crypt_get()},
		{ 235 , xorstr("请登录后绑定").crypt_get()},
		{ 236 , xorstr("用户资料绑定失败,未知原因").crypt_get()},
		{ 237 , xorstr("扣时账户不存在").crypt_get()},
		{ 238 , xorstr("时间不足,扣时失败").crypt_get()},
		{ 239 , xorstr("扣时失败,未知原因,请联系客服").crypt_get()},
		{ 240 , xorstr("您的账号已满额在线,请稍后重试,如异常退出,请等待三分钟后重新登录").crypt_get()},
		{ 241 , xorstr("禁止转绑").crypt_get()},
		{ 242 , xorstr("推荐人不存在").crypt_get()},
		{ 243 , xorstr("用户名为3-12位,支持中文").crypt_get()},
		{ 244 , xorstr("密码为6-16位").crypt_get()},
		{ 245 , xorstr("用户名已存在,请更换!").crypt_get()},
		{ 246 , xorstr("邮箱已被使用,请更换!").crypt_get()},
		{ 247 , xorstr("注册失败,未知原因.").crypt_get()},
		{ 248 , xorstr("用户不存在或已被封停").crypt_get()},
		{ 249 , xorstr("邮件发送失败,请联系客服处理.").crypt_get()},
		{ 250 , xorstr("邮件验证码错误").crypt_get()},
		{ 251 , xorstr("密码修改失败,请联系客服处理").crypt_get()},
		{ 252 , xorstr("绑定失败,欲绑定的软件用户不存在").crypt_get()},
		{ 253 , xorstr("账户未登录,或自定义PHP函数不存在").crypt_get()},
		{ 500 , xorstr("软件ID错误").crypt_get()},
		{ 601 , xorstr("电脑时间与服务器相差太久,通信失败").crypt_get()},
		{ 602 , xorstr("请勿重复提交").crypt_get()},
	};

}