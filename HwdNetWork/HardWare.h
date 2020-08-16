#pragma once
#include <WbemIdl.h>  
#include <iostream>  
#pragma  warning(disable:4996)
#pragma comment(lib,"WbemUuid.lib")
class HardWare
{
public:
	HardWare() : m_pWbemSvc(nullptr), m_pWbemLoc(nullptr), m_pEnumClsObj(nullptr)
	{
		//初始化
		this->InitWmi();
		//获取网卡原生MAC地址
		this->GetSingleItemInfo("Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (NOT (PNPDeviceID LIKE 'ROOT%'))",
			"PNPDeviceID",
			this->strNetwork);

		//获取硬盘序列号
		this->GetSingleItemInfo("Win32_DiskDrive WHERE (SerialNumber IS NOT NULL) AND (MediaType LIKE 'Fixed hard disk%')",
			"SerialNumber",
			this->strDiskDrive);

		//获取主板序列号
		this->GetSingleItemInfo("Win32_BaseBoard WHERE (SerialNumber IS NOT NULL)",
			"SerialNumber",
			this->strBaseBoard);

		//获取处理器ID 
		this->GetSingleItemInfo("Win32_Processor WHERE (ProcessorId IS NOT NULL)",
			"ProcessorId",
			this->strProcessorID);

		//获取BIOS序列号
		this->GetSingleItemInfo("Win32_BIOS WHERE (SerialNumber IS NOT NULL)",
			"SerialNumber",
			this->strBIOS);

		//获取主板型号
		this->GetSingleItemInfo("Win32_BaseBoard WHERE (Product IS NOT NULL)",
			"Product",
			this->strBaseBoardType);

		//获取网卡当前MAC地址
		this->GetSingleItemInfo("Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (NOT (PNPDeviceID LIKE 'ROOT%'))",
			"MACAddress",
			this->strCurrentNetwork);
		//序列号组合
		strAllMacInfo = strNetwork + strDiskDrive + strBaseBoard + strProcessorID + strBIOS + strBaseBoardType + strCurrentNetwork;

	}
	~HardWare()
	{
		m_pWbemSvc = NULL;
		m_pWbemLoc = NULL;
		m_pEnumClsObj = NULL;

		this->ReleaseWmi();
	}
	
public:
	// 所有序列号的组合
	std::string strAllMacInfo;
	// 网卡原生MAC地址
	std::string strNetwork;
	// 硬盘序列号
	std::string strDiskDrive;
	// 主板序列号 
	std::string strBaseBoard;
	// 处理器ID  
	std::string strProcessorID;
	// BIOS序列号
	std::string strBIOS;
	// 主板型号
	std::string strBaseBoardType;
	// 网卡当前MAC地址
	std::string strCurrentNetwork;

private:
	//初始化WMI 
	HRESULT InitWmi()
	{
		HRESULT hr;
		//一、初始化COM组件  
		//初始化COM  
		hr = ::CoInitializeEx(0, COINIT_MULTITHREADED);
		if (SUCCEEDED(hr) || RPC_E_CHANGED_MODE == hr)
		{
			//设置进程的安全级别，（调用COM组件时在初始化COM之后要调用CoInitializeSecurity设置进程安全级别，否则会被系统识别为病毒）  
			hr = CoInitializeSecurity(NULL,
				-1,
				NULL,
				NULL,
				RPC_C_AUTHN_LEVEL_PKT,
				RPC_C_IMP_LEVEL_IMPERSONATE,
				NULL,
				EOAC_NONE,
				NULL);
			//VERIFY(SUCCEEDED(hr));  

			//二、创建一个WMI命名空间连接  
			//创建一个CLSID_WbemLocator对象  
			hr = CoCreateInstance(CLSID_WbemLocator,
				0,
				CLSCTX_INPROC_SERVER,
				IID_IWbemLocator,
				(LPVOID*)&m_pWbemLoc);
			//        VERIFY(SUCCEEDED(hr));  

					//使用m_pWbemLoc连接到"root\cimv2"并设置m_pWbemSvc的指针  
			hr = m_pWbemLoc->ConnectServer((PWCHAR)L"ROOT\\CIMV2",
				NULL,
				NULL,
				0,
				NULL,
				0,
				0,
				&m_pWbemSvc);
			//        VERIFY(SUCCEEDED(hr));  

					//三、设置WMI连接的安全性  
			hr = CoSetProxyBlanket((IUnknown*)m_pWbemSvc,
				RPC_C_AUTHN_WINNT,
				RPC_C_AUTHZ_NONE,
				NULL,
				RPC_C_AUTHN_LEVEL_CALL,
				RPC_C_IMP_LEVEL_IMPERSONATE,
				NULL,
				EOAC_NONE);
			//        VERIFY(SUCCEEDED(hr));  

		}
		return(hr);
	}
	//释放 
	HRESULT ReleaseWmi()
	{
		HRESULT hr = CoInitialize(NULL);

		if (NULL != m_pWbemSvc)
		{
			hr = m_pWbemSvc->Release();
		}
		if (NULL != m_pWbemLoc)
		{
			hr = m_pWbemLoc->Release();
		}
		if (NULL != m_pEnumClsObj)
		{
			hr = m_pEnumClsObj->Release();
		}

		::CoUninitialize();

		return(hr);
	}
	
private:

	//获取一个类成员
	BOOL GetSingleItemInfo(std::string ClassName, std::string ClassMember, std::string& chRetValue)
	{

		std::string query = "SELECT * FROM ";
		VARIANT vtProp;
		ULONG uReturn;
		HRESULT hr;
		BOOL bRet = FALSE;

		if (NULL != m_pWbemSvc)
		{
			//查询类ClassName中的所有字段,保存到m_pEnumClsObj中  
			query += ClassName;
			hr = m_pWbemSvc->ExecQuery((BSTR)L"WQL", (BSTR)this->s_To_ws(query).c_str(), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
				0, &m_pEnumClsObj);
			if (SUCCEEDED(hr))
			{
				//初始化vtProp值  
				VariantInit(&vtProp);
				uReturn = 0;

				//返回从当前位置起的第一个对象到m_pWbemClsObj中  
				hr = m_pEnumClsObj->Next(WBEM_INFINITE, 1, &m_pWbemClsObj, &uReturn);
				if (SUCCEEDED(hr) && uReturn > 0)
				{
					//从m_pWbemClsObj中找出ClassMember标识的成员属性值,并保存到vtProp变量中  
					hr = m_pWbemClsObj->Get(this->s_To_ws(ClassMember).c_str(), 0, &vtProp, 0, 0);
					if (SUCCEEDED(hr))
					{
						VariantToString(&vtProp, chRetValue);
						VariantClear(&vtProp);//清空vtProp  
						bRet = TRUE;
					}
				}
			}
		}
		if (NULL != m_pEnumClsObj)
		{
			hr = m_pEnumClsObj->Release();
			m_pEnumClsObj = NULL;
		}
		if (NULL != m_pWbemClsObj)
		{
			hr = m_pWbemClsObj->Release();
			m_pWbemClsObj = NULL;
		}
		return bRet;

	}
	//获取一个类的多个成员
	BOOL GetGroupItemInfo(std::string ClassName, std::string ClassMember[], int n, std::string& chRetValue)
	{

		std::string query = "SELECT * FROM ";
		std::string result, info;
		VARIANT vtProp;
		ULONG uReturn;
		HRESULT hr;
		int i;
		BOOL bRet = FALSE;
		if (NULL != m_pWbemSvc)
		{
			query += ClassName;
			hr = m_pWbemSvc->ExecQuery((BSTR)L"WQL", (BSTR)this->s_To_ws(query).c_str(), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 0, &m_pEnumClsObj);
			if (SUCCEEDED(hr))
			{
				VariantInit(&vtProp); //初始化vtProp变量  
				if (m_pEnumClsObj)
				{
					Sleep(10);
					uReturn = 0;
					hr = m_pEnumClsObj->Next(WBEM_INFINITE, 1, &m_pWbemClsObj, &uReturn);
					if (SUCCEEDED(hr) && uReturn > 0)
					{
						for (i = 0; i < n; ++i)
						{
							hr = m_pWbemClsObj->Get(this->char_To_wstring(ClassMember[i].c_str()).c_str(), 0, &vtProp, 0, 0);
							if (SUCCEEDED(hr))
							{
								VariantToString(&vtProp, info);
								chRetValue += info + "\t";
								VariantClear(&vtProp);
								bRet = TRUE;
							}
						}
						chRetValue += "\r\n";
					}
				}
			}
		}

		if (NULL != m_pEnumClsObj)
		{
			hr = m_pEnumClsObj->Release();
			m_pEnumClsObj = NULL;
		}
		if (NULL != m_pWbemClsObj)
		{
			hr = m_pWbemClsObj->Release();
			m_pWbemClsObj = NULL;
		}
		return bRet;
	}
	//将Variant类型的变量转换为CString
	void VariantToString(const LPVARIANT pVar, std::string& chRetValue)
	{

		wchar_t* pBstr;
		BYTE HUGEP* pBuf;
		LONG low, high, i;
		HRESULT hr;

		switch (pVar->vt)
		{
		case VT_BSTR:
		{
			chRetValue = this->wchar_To_string((wchar_t*)pVar->bstrVal);
		}
		break;
		case VT_BOOL:
		{
			if (VARIANT_TRUE == pVar->boolVal)
				chRetValue = "是";
			else
				chRetValue = "否";
		}
		break;
		case VT_I4:
		{
			//chRetValue.Format(_T("%d"), pVar->lVal);
			char buffer[50] = { 0 };
			sprintf(buffer, "%d", pVar->lVal);
			chRetValue += buffer;
		}
		break;
		case VT_UI1:
		{
			//chRetValue.Format(_T("%d"), pVar->bVal);
			char buffer[50] = { 0 };
			sprintf(buffer, "%d", pVar->bVal);
			chRetValue += buffer;
		}
		break;
		case VT_UI4:
		{
			//chRetValue.Format(_T("%d"), pVar->ulVal);
			char buffer[50] = { 0 };
			sprintf(buffer, "%d", pVar->ulVal);
			chRetValue += buffer;
		}
		break;

		case VT_BSTR | VT_ARRAY:
		{

			hr = SafeArrayAccessData(pVar->parray, (void HUGEP**) & pBstr);
			hr = SafeArrayUnaccessData(pVar->parray);
			chRetValue = wchar_To_string(pBstr);

		}
		break;

		case VT_I4 | VT_ARRAY:
		{
			SafeArrayGetLBound(pVar->parray, 1, &low);
			SafeArrayGetUBound(pVar->parray, 1, &high);

			hr = SafeArrayAccessData(pVar->parray, (void HUGEP**) & pBuf);
			hr = SafeArrayUnaccessData(pVar->parray);
			std::string strTmp;
			high = min(high, MAX_PATH * 2 - 1);
			for (i = low; i <= high; ++i)
			{
				char buffer[50] = { 0 };
				sprintf(buffer, "%02X", pBuf[i]);
				chRetValue += strTmp;
			}
		}
		break;
		default:
			break;
		}
	}
	//编码转换
	std::string wchar_To_string(const wchar_t* wchar)
	{
		char* m_char;
		SIZE_T len = WideCharToMultiByte(CP_ACP, 0, wchar, wcslen(wchar), NULL, 0, NULL, NULL);
		m_char = new char[len + 1];
		WideCharToMultiByte(CP_ACP, 0, wchar, wcslen(wchar), m_char, len, NULL, NULL);
		m_char[len] = '\0';
		std::string retStr(m_char);
		delete[] m_char;
		return retStr;
	}
	//编码转换
	std::wstring char_To_wstring(const char* cchar)
	{
		//宽字符串指针 未初始化
		wchar_t* m_wchar;
		//获取转换后宽字符长度
		SIZE_T len = MultiByteToWideChar(CP_ACP, 0, cchar, strlen(cchar), NULL, 0);
		//用获取的长度+1 new一个宽字符串
		m_wchar = new wchar_t[len + 1];
		//转换宽字符串
		MultiByteToWideChar(CP_ACP, 0, cchar, strlen(cchar), m_wchar, len);
		//结尾补上0
		m_wchar[len] = '\0';
		std::wstring retStr(m_wchar);
		delete[] m_wchar;
		return retStr;
	}
	//编码转换
	std::wstring s_To_ws(const std::string& s)
	{
		int len;
		int slength = (int)s.length() + 1;
		len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
		wchar_t* buf = new wchar_t[len];
		MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
		std::wstring r(buf);
		delete[] buf;
		return r;
	}
	//去掉字符串中的指定字符
	void del_chr(char* s, char ch)
	{
		char* t = s; //目标指针先指向原串头
		while (*s != '\0') //遍历字符串s
		{
			if (*s != ch) //如果当前字符不是要删除的，则保存到目标串中
				*t++ = *s;
			s++; //检查下一个字符
		}
		*t = '\0'; //置目标串结束符。
	}

private:
	IEnumWbemClassObject* m_pEnumClsObj;
	IWbemClassObject* m_pWbemClsObj;
	IWbemServices* m_pWbemSvc;
	IWbemLocator* m_pWbemLoc;
};

