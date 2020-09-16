


#pragma once
//http库，这个库必须放在最前面，否则会跟windows.h冲突 
#include "http/httplib.h"

//AES加密算法
#include "aes/aes.hpp"

//加密静态字串
#include"tool/XorStr.hpp"

//md5生成类
#include "tool/md5.hpp"

//url编解码类
#include "tool/UrlEncoder.hpp"

//机器码头文件
#include "tool/HardWare.hpp"

//json解析
#include "json/CJsonObject.hpp"

//字符串转换
#include "tool/EncodingConversion.hpp"


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
			return decode_str(LastErroMsg, this->本地字串加密key);
		}
		//公告
		std::string GetNotice()
		{
			return decode_str(notice, this->本地字串加密key);
		}
		//软件名字
		std::string GetName()
		{
			return decode_str(name, this->本地字串加密key);
		}
		//版本号
		std::string GetVersion()
		{
			return decode_str(version, this->本地字串加密key);
		}
		//客服QQ
		std::string GetQq()
		{
			return decode_str(qq, this->本地字串加密key);
		}
		//软件下载网址
		std::string GetDownloadurl()
		{
			return decode_str(downloadurl, this->本地字串加密key);
		}
		//软件更新网址
		std::string GetUpdateurl()
		{
			return decode_str(updateurl, this->本地字串加密key);
		}
		//用户绑定资料,例如游戏号等
		std::string Getbind()
		{
			return decode_str(bind, this->本地字串加密key);
		}
		//到期时间
		std::string GetEndtime()
		{
			return decode_str(endtime, this->本地字串加密key);
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
			return decode_str(point, this->本地字串加密key);
		}
		//点数余额
		size_t GetPoint_size_t()
		{
			return 点数余额;
		}
		//用户自定义常量
		std::string GetPara()
		{
			return decode_str(para, this->本地字串加密key);
		}
		//软件自定义常量
		std::string GetSoftpara()
		{
			return decode_str(softpara, this->本地字串加密key);
		}
		//用户名
		std::string GetUser()
		{
			return decode_str(user, this->本地字串加密key);
		}
		//密码
		std::string GetPass()
		{
			return decode_str(pass, this->本地字串加密key);
		}
		//账户余额
		std::string GetBalance()
		{
			return decode_str(balance, this->本地字串加密key);
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
			IN std::string _SignRuleServer/*服务端sign规则*/,
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
			info.Key = XorStr("action") ;
			info.Value = XorStr("init") ;
			std::vector<Info> test;
			test.push_back(info);

			neb::CJsonObject retJson;
			if (HttpRequest(test, retJson))
			{
				std::string codestr;
				retJson.Get(XorStr("code"), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(XorStr("result") , result);

					result.Get(XorStr("notice") , this->notice);
					result.Get(XorStr("name") , this->name);
					result.Get(XorStr("version") , this->version);
					result.Get(XorStr("qq") , this->qq);
					result.Get(XorStr("downloadurl") , this->downloadurl);
					result.Get(XorStr("updateurl") , this->updateurl);


					this->notice = replace_all(this->notice, "<p>", " ");
					this->notice = replace_all(this->notice, "</p>", " ");
					this->notice = STR_EC::UTF8ToGBK(this->notice);
					this->notice = encode_str(notice, 本地字串加密key);
					this->name = encode_str(name, 本地字串加密key);
					this->version = encode_str(version, 本地字串加密key);
					this->qq = encode_str(qq, 本地字串加密key);
					this->downloadurl = encode_str(downloadurl, 本地字串加密key);
					this->updateurl = encode_str(updateurl, 本地字串加密key);

					return true;
				}
				else
				{
					LastErroMsg = encode_str(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = encode_str(XorStr("请求失败！") , 本地字串加密key);
				return false;
			}

		}



		//用户登录
		bool UserLogin(IN std::string username/*用户名*/, IN std::string password/*密码*/)
		{
			//action=login&user=用户名&pwd=密码&code=验证码
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = XorStr("action") ;
			api.Value = XorStr("login") ;
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = XorStr("user") ;
			Var1.Value = username;
			PostMsgInfo.push_back(Var1);
			Info Var2;
			Var2.Key = XorStr("pwd") ;
			Var2.Value = password;
			PostMsgInfo.push_back(Var2);

			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(XorStr("code"), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(XorStr("result") , result);
					result.Get(XorStr("bind") , bind);
					result.Get(XorStr("endtime") , endtime);
					到期时间戳 = StringToDatetime(endtime);
					result.Get(XorStr("para") , para);
					result.Get(XorStr("point") , point);
					点数余额 = atoi(point.c_str());
					result.Get(XorStr("softpara") , softpara);
					result.Get(XorStr("user") , user);
					
					this->bind = encode_str(this->bind, 本地字串加密key);
					this->endtime = encode_str(this->endtime, 本地字串加密key);
					this->para = encode_str(this->para, 本地字串加密key);
					this->point = encode_str(this->point, 本地字串加密key);
					this->softpara = encode_str(this->softpara, 本地字串加密key);
					this->user = encode_str(this->user, 本地字串加密key);
					pass = password;
					this->pass = encode_str(password, 本地字串加密key);
					return true;
				}
				else
				{
					LastErroMsg = encode_str(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = encode_str(XorStr("请求失败！") , 本地字串加密key);
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
			api.Key = XorStr("action") ;
			api.Value = XorStr("heartbeat") ;
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = XorStr("user") ;
			Var1.Value = this->GetUser();
			PostMsgInfo.push_back(Var1);


			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(XorStr("code"), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(XorStr("result") , result);

					result.Get(XorStr("bind") , bind);
					result.Get(XorStr("endtime") , endtime);
					到期时间戳 = StringToDatetime(endtime);
					result.Get(XorStr("para") , para);
					result.Get(XorStr("point") , point);
					点数余额 = atoi(point.c_str());
					result.Get(XorStr("softpara") , softpara);

					bind = encode_str(bind, 本地字串加密key);
					endtime = encode_str(endtime, 本地字串加密key);
					para = encode_str(para, 本地字串加密key);
					point = encode_str(point, 本地字串加密key);
					softpara = encode_str(softpara, 本地字串加密key);


					return true;
				}
				else
				{

					LastErroMsg = encode_str(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = encode_str(XorStr("请求失败！") , 本地字串加密key);
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
			api.Key = XorStr("action") ;
			api.Value = XorStr("bindstr") ;
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = XorStr("user") ;
			Var1.Value = this->GetUser();
			PostMsgInfo.push_back(Var1);
			Info Var2;
			Var2.Key = XorStr("pwd") ;
			Var2.Value = this->GetPass();
			PostMsgInfo.push_back(Var2);
			Info Var3;
			Var3.Key = XorStr("str") ;
			Var3.Value = str;
			PostMsgInfo.push_back(Var3);


			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(XorStr("code"), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					return true;
				}
				else
				{
					LastErroMsg = encode_str(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = encode_str(XorStr("请求失败！") , 本地字串加密key);
				return false;
			}
			return false;
		}
		//绑定机器码
		bool BindMac(IN std::string username/*用户名*/)
		{
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = XorStr("action") ;
			api.Value = XorStr("bind") ;
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = XorStr("user") ;
			Var1.Value = username;
			PostMsgInfo.push_back(Var1);


			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(XorStr("code"), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					return true;
				}
				else
				{
					LastErroMsg = encode_str(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = encode_str(XorStr("请求失败！") , 本地字串加密key);
				return false;
			}
			return false;
		}
		//充值
		bool RechArge(IN std::string username/*用户名*/, IN std::string cdkey/*充值卡*/)
		{
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = XorStr("action") ;
			api.Value = XorStr("recharge") ;
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = XorStr("user") ;
			Var1.Value = username;
			PostMsgInfo.push_back(Var1);
			Info Var2;
			Var2.Key = XorStr("card") ;
			Var2.Value = cdkey;
			PostMsgInfo.push_back(Var2);


			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(XorStr("code"), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(XorStr("result") , result);

					result.Get(XorStr("balance") , balance);
					result.Get(XorStr("endtime") , endtime);
					到期时间戳 = StringToDatetime(endtime);
					result.Get(XorStr("point") , point);
					点数余额 = atoi(point.c_str());

					balance = encode_str(balance, 本地字串加密key);
					endtime = encode_str(endtime, 本地字串加密key);
					point = encode_str(point, 本地字串加密key);

					balance = encode_str(balance, 本地字串加密key);
					endtime = encode_str(endtime, 本地字串加密key);
					point = encode_str(point, 本地字串加密key);

					return true;
				}
				else
				{
					LastErroMsg = encode_str(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = encode_str(XorStr("请求失败！") , 本地字串加密key);
				return false;
			}
			return false;
		}
		//扣点
		bool DeductPoint(IN std::string number/*扣除点数*/, IN DEDUCTPOINTMODE mode/*扣点方式*/)
		{
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = XorStr("action") ;
			api.Value = XorStr("deductpoint") ;
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = XorStr("user") ;
			Var1.Value = this->GetUser();
			PostMsgInfo.push_back(Var1);
			Info Var2;
			Var2.Key = XorStr("num") ;
			Var2.Value = number;
			PostMsgInfo.push_back(Var2);

			Info Var3;
			if (mode == DEDUCTPOINTMODE::ONEDAY_ONCE)
			{

				Var3.Key = XorStr("filter") ;
				Var3.Value = XorStr("1") ;
				PostMsgInfo.push_back(Var3);
				Info Var4;
				Var4.Key = XorStr("msg") ;
				time_t today = time(NULL);
				Var4.Value = Mac_code + (DatetimeToString(today, true, false, false, false));
				
				PostMsgInfo.push_back(Var4);
			}
			else
			{
				Var3.Key = XorStr("filter") ;
				Var3.Value = XorStr("0") ;
				PostMsgInfo.push_back(Var3);
			}

			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(XorStr("code"), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(XorStr("result"), result);
					result.Get(XorStr("point"), point);
					点数余额 = atoi(point.c_str());
					point = encode_str(point, 本地字串加密key);

					return true;
				}
				else
				{

					LastErroMsg = encode_str(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = encode_str(XorStr("请求失败！") , 本地字串加密key);
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
			api.Key = XorStr("action") ;
			api.Value = XorStr("deducttime") ;
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = XorStr("user") ;
			Var1.Value = this->GetUser();
			PostMsgInfo.push_back(Var1);
			Info Var3;
			Var3.Key = XorStr("num") ;
			Var3.Value = number;
			PostMsgInfo.push_back(Var3);
			Info Var4;
			Var4.Key = XorStr("msg") ;
			Var4.Value = XorStr("DeductTime:")  + DatetimeToString(time(NULL), true, true, true, false);
			PostMsgInfo.push_back(Var4);
			Info Var5;
			Var5.Key = XorStr("filter") ;
			Var5.Value = XorStr("0") ;
			PostMsgInfo.push_back(Var5);
			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{

				
				std::string codestr;
				retJson.Get(XorStr("code"), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					neb::CJsonObject result;
					retJson.Get(XorStr("result"), result);

					result.Get(XorStr("endtime"), endtime);
					到期时间戳 = StringToDatetime(endtime);

					endtime = encode_str(endtime, 本地字串加密key);
					return true;
				}
				else
				{
					LastErroMsg = encode_str(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}

			else
			{
				LastErroMsg = encode_str(XorStr("请求失败！") , 本地字串加密key);
				return false;
			}
			return false;
		}
		//登出
		bool LogOut()
		{
			std::vector<Info> PostMsgInfo;
			Info api;
			api.Key = XorStr("action") ;
			api.Value = XorStr("logout") ;
			PostMsgInfo.push_back(api);
			Info Var1;
			Var1.Key = XorStr("user") ;
			Var1.Value = this->GetUser();
			PostMsgInfo.push_back(Var1);

			//测试
			neb::CJsonObject retJson;
			if (HttpRequest(PostMsgInfo, retJson))
			{
				std::string codestr;
				retJson.Get(XorStr("code"), codestr);
				int code = std::stoi(codestr);
				if (code == 200)
				{
					return true;
				}
				else
				{
					LastErroMsg = encode_str(GetMessageWithErroCode(code), 本地字串加密key);
					return false;
				}
			}
			else
			{
				LastErroMsg = encode_str(XorStr("请求失败！") , 本地字串加密key);
				return false;
			}
			return false;
		}

	private:
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
			size_t Time = (size_t)time(NULL);
			std::string timeStr = std::to_string(Time);


			neb::CJsonObject json;
			json.Add(XorStr("sid") , this->Sid);
			json.Add(XorStr("uuid") , uuid);
			json.Add(XorStr("t") , Time);
			json.Add(XorStr("m1") , MD5(this->Sid + this->Key + timeStr).toString());
			json.Add(XorStr("m2") , this->Md5_2);
			json.Add(XorStr("m3") , this->Md5_3);
			json.Add(XorStr("mcode") , this->Mac_code);
			json.Add(XorStr("clientid") , this->ClientId);
			json.Add(XorStr("webkey") , this->WebKey);
			//可变参数
			for (size_t i = 0; i < Variable.size(); i++)
			{
				json.Add(Variable[i].Key, Variable[i].Value);
			}
			
			std::string out_json_text = json.ToString();
			

#ifdef _DEBUG
			std::cout << "组包JSON明文：" << std::endl << out_json_text << std::endl;
			std::cout << std::endl;
#endif // _DEBUG

			//转为UTF8编码
			std::string UTF8_Str = STR_EC::GBKToUTF8(out_json_text);
			//进行AES加密
			std::string 密文 = AES::Encryption(UTF8_Str, this->Key, nullptr, AES::PADDING::ZERO,AES::MODE::ECB_, AES::OUTMODE::HEX);
#ifdef _DEBUG
			std::cout << "发送密文：" << std::endl << 密文 << std::endl;
			std::cout << std::endl;
#endif // _DEBUG
			//进行sign拼接
			std::string sign拼接 = this->SignRuleClient;
			sign拼接 = this->replace_all(sign拼接, XorStr("[data]"), 密文);
			sign拼接 = this->replace_all(sign拼接, XorStr("[key]"), this->Key);
			std::string sign值 = MD5(sign拼接).toString();

			//进行url编码，防止传输过程中丢失特殊字符
			UrlEncoder url;
			std::string url编码 = url.Encode(密文, false);

			//进行封包 
			std::string 封包 = XorStr("data=") + url编码 + XorStr("&sign=") + sign值;

			//设置请求头
			httplib::Headers headers = 
			{
				{ "Accept", "*/*" },
				{ "Accept-Language", "zh-cn" }
			};

			//发送封包
			std::string 请求页 = "/" + PageAddr;
			httplib::Client cli(Domain.c_str());
			auto res = cli.Post(请求页.c_str(), headers, 封包.c_str(), "application/x-www-form-urlencoded");
			if (!res)
			{
				return false;
			}
			std::string 返回数据 = res->body;


			/*************解包验证*******************/

			//取得密文与sign
			neb::CJsonObject RetJson(返回数据);
			std::string RetData;
			std::string RetSign;
			RetJson.Get(XorStr("data"), RetData);
			RetJson.Get(XorStr("sign"), RetSign);

			//url解码
			UrlEncoder RetUrl;
			std::string url解码;
			RetUrl.Decode(RetData, &url解码);
			//进行sign拼接
			std::string Retsign拼接 = this->SignRuleServer;
			Retsign拼接 = this->replace_all(Retsign拼接, XorStr("[data]"), url解码);
			Retsign拼接 = this->replace_all(Retsign拼接, XorStr("[key]"), this->Key);
			std::string Retsign值 = MD5(Retsign拼接).toString();

			//校验封包合法性   1对比sign值是否正确、2对比封包uuid是否正确、3对比封包时间是否相差太长、
			//对比sign值
			if (Retsign值 != RetSign)
			{
				return false;
			}

			//DES解密
			std::string 返回解密数据 = AES::Decryption(url解码, this->Key, nullptr, AES::MODE::ECB_, AES::OUTMODE::HEX);

			std::string ret_string = STR_EC::UTF8ToGBK(返回解密数据);

			RetJson_ = ret_string;
			std::string uuid_new;
			RetJson_.Get(XorStr("uuid"), uuid_new);
			int time_new = 0;
			RetJson_.Get(XorStr("t"), time_new);

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
				return(std::string(yearStr) + "/" + std::string(monthStr) + "/" + std::string(dayStr) + "/");
			}
			else if (hour_)
			{
				return(std::string(yearStr) + "/" + std::string(monthStr) + "/" + std::string(dayStr) + "/" + std::string(hourStr) + "/");
			}
			else if (minute_)
			{
				return(std::string(yearStr) + "/" + std::string(monthStr) + "/" + std::string(dayStr) + "/" + std::string(hourStr) + "/" + std::string(minuteStr) + "/");
			}
			else if (second_)
			{
				return(std::string(yearStr) + "/" + std::string(monthStr) + "/" + std::string(dayStr) + "/" + std::string(hourStr) + "/" + std::string(minuteStr) + "/" + std::string(secondStr) + "/");
			}
			else
			{
				return(std::string(yearStr) + "/" + std::string(monthStr) + "/" + std::string(dayStr) + "/" + std::string(hourStr) + "/" + std::string(minuteStr) + "/" + std::string(secondStr) + "/");
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

		//本地字串保存AES加密
		std::string encode_str(const std::string& strData, const std::string& password)
		{
			return AES::Encryption(strData, password, nullptr, AES::PADDING::ZERO, AES::MODE::CBC_, AES::OUTMODE::HEX);
		}
		//本地字串保存AES解密
		std::string decode_str(const std::string& strData, const std::string& password)
		{
			return AES::Decryption(strData, password, nullptr, AES::MODE::CBC_, AES::OUTMODE::HEX);
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
		//设置错误信息
		void SetLastErroMessage(std::string msg)
		{
			LastErroMsg = encode_str(msg, 本地字串加密key);

		}

	};

	std::map<size_t, std::string> CHwdNetWork::ErroMap =
	{
		{ 201 , XorStr("软件不存在") },
		{ 202 , XorStr("通信秘钥校验失败") },
		{ 203 , XorStr("软件MD5校验失败") },
		{ 206 , XorStr("账号或密码错误") },
		{ 207 , XorStr("充值卡不存在") },
		{ 209 , XorStr("当前机器码与绑定机器不符") },
		{ 210 , XorStr("您的账户已过期,请充值后登录") },
		{ 211 , XorStr("您的账户点数为0,请充值后登录") },
		{ 212 , XorStr("软件维护") },
		{ 213 , XorStr("通行证被封停,禁止登录") },
		{ 214 , XorStr("您的账户已过期,无法转绑,使用本机充值后将自动绑定至本机") },
		{ 215 , XorStr("您的剩余时间不足以支付转绑扣除时间,请充值.使用本机充值后将自动绑定至本机") },
		{ 216 , XorStr("转绑失败,未知原因,请联系客服处理") },
		{ 217 , XorStr("您的账户点数为0,无法转绑,使用本机充值后将自动绑定至本机") },
		{ 218 , XorStr("您的剩余点数不足以支付转绑扣除点数,请充值.使用本机充值后将自动绑定至本机") },
		{ 219 , XorStr("充值账号不存在") },
		{ 220 , XorStr("充值卡不存在") },
		{ 221 , XorStr("充值卡类目不存在,请联系客服") },
		{ 222 , XorStr("您的充值卡与当前账号类型不符,请到期后再充值") },
		{ 223 , XorStr("您的充值卡与当前账号类型不符,请将点数用完后再充值") },
		{ 224 , XorStr("扣点账户不存在") },
		{ 225 , XorStr("点数不足,扣点失败") },
		{ 226 , XorStr("扣点失败,未知原因,请联系客服") },
		{ 227 , XorStr("账户被封停,禁止登录") },
		{ 228 , XorStr("通行证已删除,即将下线") },
		{ 229 , XorStr("通行证已被封停,即将下线") },
		{ 230 , XorStr("软件账户已被删除,即将下线") },
		{ 231 , XorStr("软件账户已被封停,即将下线") },
		{ 232 , XorStr("您的点数为0,即将下线") },
		{ 233 , XorStr("您的账户已到期,即将下线") },
		{ 234 , XorStr("您的账户已离线,即将关闭.") },
		{ 235 , XorStr("请登录后绑定") },
		{ 236 , XorStr("用户资料绑定失败,未知原因") },
		{ 237 , XorStr("扣时账户不存在") },
		{ 238 , XorStr("时间不足,扣时失败") },
		{ 239 , XorStr("扣时失败,未知原因,请联系客服") },
		{ 240 , XorStr("您的账号已满额在线,请稍后重试,如异常退出,请等待三分钟后重新登录") },
		{ 241 , XorStr("禁止转绑") },
		{ 242 , XorStr("推荐人不存在") },
		{ 243 , XorStr("用户名为3-12位,支持中文") },
		{ 244 , XorStr("密码为6-16位") },
		{ 245 , XorStr("用户名已存在,请更换!") },
		{ 246 , XorStr("邮箱已被使用,请更换!") },
		{ 247 , XorStr("注册失败,未知原因.") },
		{ 248 , XorStr("用户不存在或已被封停") },
		{ 249 , XorStr("邮件发送失败,请联系客服处理.") },
		{ 250 , XorStr("邮件验证码错误") },
		{ 251 , XorStr("密码修改失败,请联系客服处理") },
		{ 252 , XorStr("绑定失败,欲绑定的软件用户不存在") },
		{ 253 , XorStr("账户未登录,或自定义PHP函数不存在") },
		{ 500 , XorStr("软件ID错误") },
		{ 601 , XorStr("电脑时间与服务器相差太久,通信失败") },
		{ 602 , XorStr("请勿重复提交") },
	};

}

