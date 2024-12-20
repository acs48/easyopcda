// ******  easyopcda v0.2  ******
// Copyright (C) 2024 Carlo Seghi. All rights reserved.
// Author Carlo Seghi github.com/acs48.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Library General Public
// License as published by the Free Software Foundation v3.0
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Library General Public License for more details.
//
// Use of this source code is governed by a GNU General Public License v3.0
// License that can be found in the LICENSE file.


#ifndef EASYOPCDA_H
#define EASYOPCDA_H

#include <atlbase.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/ostream_sink.h"

#include "opccomn.h"
#include "opcda.h"
#include "OpcEnum.h"
#include "opcerror.h"

#include <sstream>
#include <functional>
#include <iomanip>
#include <codecvt>
#include <chrono>


#define DEBUG_LOG(...) if(easyopcda::logEnabler.logToDefault)spdlog::debug(__VA_ARGS__);if(easyopcda::logEnabler.logToString){easyopcda::logEnabler.logger->debug(__VA_ARGS__);}
#define INFO_LOG(...)  if(easyopcda::logEnabler.logToDefault)spdlog::info(__VA_ARGS__); if(easyopcda::logEnabler.logToString){easyopcda::logEnabler.logger->info(__VA_ARGS__);}
#define WARN_LOG(...) if(easyopcda::logEnabler.logToDefault)spdlog::warn(__VA_ARGS__);if(easyopcda::logEnabler.logToString){easyopcda::logEnabler.logger->warn(__VA_ARGS__);}
#define ERROR_LOG(...) if(easyopcda::logEnabler.logToDefault)spdlog::error(__VA_ARGS__);if(easyopcda::logEnabler.logToString){easyopcda::logEnabler.logger->error(__VA_ARGS__);}

namespace easyopcda {
    typedef struct {
        std::wstring tagName;
        FILETIME timestamp;
        VARIANT value;
        WORD quality;
        HRESULT error;
    } opcTagResult;

    typedef std::function<void(std::wstring groupName, opcTagResult)> ASyncCallback;

    class logEnablerClass {
    public:
        logEnablerClass() { logToDefault=true;logToString=false;}
        bool logToDefault;
        bool logToString;

        std::stringstream ss;
        std::shared_ptr<spdlog::sinks::ostream_sink_mt> ss_sink;
        std::shared_ptr<spdlog::logger> logger;


        void setLogLevel(spdlog::level::level_enum level) { logger->set_level(level); }
    };

    inline logEnablerClass logEnabler;

    inline std::string getLogs() {
        auto rv = logEnabler.ss.str();
        logEnabler.ss.clear();
        return rv;
    }


    inline void disableLogToDefault() {logEnabler.logToDefault=false;}
    inline void disableLogToClass() {logEnabler.logToString = false;}
    inline void enableLogToDefault() {logEnabler.logToDefault=true;}
    inline void enableLogToClass() {logEnabler.logToString = true;}
}

inline std::string wstringToUTF8(const std::wstring& wstr) {
    static std::wstring_convert<std::codecvt_utf8<wchar_t>> string_converter;
    return string_converter.to_bytes(wstr);
}


std::wstring inline opcQualityToWstring(WORD quality) {
    switch (quality) {
        case OPC_QUALITY_BAD: return L"bad";
        case OPC_QUALITY_UNCERTAIN: return L"uncertain";
        case OPC_QUALITY_GOOD: return L"good";
        case OPC_QUALITY_CONFIG_ERROR: return L"config error";
        case OPC_QUALITY_NOT_CONNECTED: return L"not connected";
        case OPC_QUALITY_DEVICE_FAILURE: return L"device failure";
        case OPC_QUALITY_SENSOR_FAILURE: return L"sensor failure";
        case OPC_QUALITY_LAST_KNOWN: return L"last known";
        case OPC_QUALITY_COMM_FAILURE: return L"comm failure";
        case OPC_QUALITY_OUT_OF_SERVICE: return L"out of service";
        case OPC_QUALITY_WAITING_FOR_INITIAL_DATA: return L"waiting for initial data";
        case OPC_QUALITY_LAST_USABLE: return L"last usable";
        case OPC_QUALITY_SENSOR_CAL: return L"sensor cal";
        case OPC_QUALITY_EGU_EXCEEDED: return L"egu exceeded";
        case OPC_QUALITY_SUB_NORMAL: return L"sub normal";
        case OPC_QUALITY_LOCAL_OVERRIDE: return L"local override";
        case OPC_LIMIT_LOW: return L"limit low";
        case OPC_LIMIT_HIGH: return L"limit high";
        case OPC_LIMIT_CONST: return L"limit const";
        default: return L"unknown";
    }
}

std::string inline opcQualityToUTF8(WORD quality) {
    switch (quality) {
        case OPC_QUALITY_BAD: return "bad";
        case OPC_QUALITY_UNCERTAIN: return "uncertain";
        case OPC_QUALITY_GOOD: return "good";
        case OPC_QUALITY_CONFIG_ERROR: return "config error";
        case OPC_QUALITY_NOT_CONNECTED: return "not connected";
        case OPC_QUALITY_DEVICE_FAILURE: return "device failure";
        case OPC_QUALITY_SENSOR_FAILURE: return "sensor failure";
        case OPC_QUALITY_LAST_KNOWN: return "last known";
        case OPC_QUALITY_COMM_FAILURE: return "comm failure";
        case OPC_QUALITY_OUT_OF_SERVICE: return "out of service";
        case OPC_QUALITY_WAITING_FOR_INITIAL_DATA: return "waiting for initial data";
        case OPC_QUALITY_LAST_USABLE: return "last usable";
        case OPC_QUALITY_SENSOR_CAL: return "sensor cal";
        case OPC_QUALITY_EGU_EXCEEDED: return "egu exceeded";
        case OPC_QUALITY_SUB_NORMAL: return "sub normal";
        case OPC_QUALITY_LOCAL_OVERRIDE: return "local override";
        case OPC_LIMIT_LOW: return "limit low";
        case OPC_LIMIT_HIGH: return "limit high";
        case OPC_LIMIT_CONST: return "limit const";
        default: return "unknown";
    }
}

std::wstring inline hresultToWstring(HRESULT hr) {
    switch (hr) {
        case OPC_E_INVALIDHANDLE: return L"The value of the handle is invalid";
        case OPC_E_BADTYPE: return L"The server cannot convert the data between the requested data type and the canonical data type";
        case OPC_E_PUBLIC: return L"The requested operation cannot be done on a public group";
        case OPC_E_BADRIGHTS: return L"The Items AccessRights do not allow the operation";
        case OPC_E_UNKNOWNITEMID: return L"The item is no longer available in the server address space";
        case OPC_E_INVALIDITEMID: return L"The item definition doesn't conform to the server's syntax";
        case OPC_E_INVALIDFILTER: return L"The filter string was not valid";
        case OPC_E_UNKNOWNPATH: return L"The item's access path is not known to the server";
        case OPC_E_RANGE: return L"The value was out of range";
        case OPC_E_DUPLICATENAME: return L"Duplicate name not allowed";
        case OPC_S_UNSUPPORTEDRATE: return L"The server does not support the requested data rate but will use the closest available rate";
        case OPC_S_CLAMP: return L"A value passed to WRITE was accepted but the output was clamped";
        case OPC_S_INUSE: return L"The operation cannot be completed because the object still has references that exist";
        case OPC_E_INVALIDCONFIGFILE: return L"The server's configuration file is an invalid format";
        case OPC_E_NOTFOUND: return L"The server could not locate the requested object";
        case OPC_E_INVALID_PID: return L"The server does not recognise the passed property ID";
        case S_OK: return L"Succeeded";
        case S_FALSE: return L"Succeeded with warnings";
        case E_UNEXPECTED: return L"Catastrophic failure";
        case E_NOTIMPL: return L"Not implemented";
        case E_OUTOFMEMORY: return L"Ran out of memory";
        case E_INVALIDARG: return L"One or more arguments are invalid";
        case E_NOINTERFACE: return L"No such interface supported";
        case E_POINTER: return L"Invalid pointer";
        case E_HANDLE: return L"Invalid handle";
        case E_ABORT: return L"Operation aborted";
        case E_FAIL: return L"Unspecified error";
        case E_ACCESSDENIED: return L"General access denied error";
        case E_PENDING: return L"The data necessary to complete this operation is not yet available";
        case E_BOUNDS: return L"The operation attempted to access data outside the valid range";
        case E_CHANGED_STATE: return
                    L"A concurrent or interleaved operation changed the state of the object, invalidating this operation.";
        case E_ILLEGAL_STATE_CHANGE: return L"An illegal state change was requested";
        case E_ILLEGAL_METHOD_CALL: return L"A method was called at an unexpected time";
        default:
            std::wstringstream ws;
            ws << std::hex << hr;
            std::wstring hrAsWString = ws.str();
            return hrAsWString;
    }
}

std::string inline hresultToUTF8(HRESULT hr) {
       switch (hr) {
        case OPC_E_INVALIDHANDLE: return "The value of the handle is invalid";
        case OPC_E_BADTYPE: return"The server cannot convert the data between the requested data type and the canonical data type";
        case OPC_E_PUBLIC: return "The requested operation cannot be done on a public group";
        case OPC_E_BADRIGHTS: return "The Items AccessRights do not allow the operation";
        case OPC_E_UNKNOWNITEMID: return "The item is no longer available in the server address space";
        case OPC_E_INVALIDITEMID: return "The item definition doesn't conform to the server's syntax";
        case OPC_E_INVALIDFILTER: return "The filter string was not valid";
        case OPC_E_UNKNOWNPATH: return "The item's access path is not known to the server";
        case OPC_E_RANGE: return "The value was out of range";
        case OPC_E_DUPLICATENAME: return "Duplicate name not allowed";
        case OPC_S_UNSUPPORTEDRATE: return "The server does not support the requested data rate but will use the closest available rate";
        case OPC_S_CLAMP: return "A value passed to WRITE was accepted but the output was clamped";
        case OPC_S_INUSE: return "The operation cannot be completed because the object still has references that exist";
        case OPC_E_INVALIDCONFIGFILE: return "The server's configuration file is an invalid format";
        case OPC_E_NOTFOUND: return "The server could not locate the requested object";
        case OPC_E_INVALID_PID: return "The server does not recognise the passed property ID";
        case S_OK: return "Succeeded";
        case S_FALSE: return "Succeeded with warnings";
        case E_UNEXPECTED: return "Catastrophic failure";
        case E_NOTIMPL: return "Not implemented";
        case E_OUTOFMEMORY: return "Ran out of memory";
        case E_INVALIDARG: return "One or more arguments are invalid";
        case E_NOINTERFACE: return "No such interface supported";
        case E_POINTER: return "Invalid pointer";
        case E_HANDLE: return "Invalid handle";
        case E_ABORT: return "Operation aborted";
        case E_FAIL: return "Unspecified error";
        case E_ACCESSDENIED: return "General access denied error";
        case E_PENDING: return "The data necessary to complete this operation is not yet available";
        case E_BOUNDS: return "The operation attempted to access data outside the valid range";
        case E_CHANGED_STATE: return "A concurrent or interleaved operation changed the state of the object, invalidating this operation.";
        case E_ILLEGAL_STATE_CHANGE: return "An illegal state change was requested";
        case E_ILLEGAL_METHOD_CALL: return "A method was called at an unexpected time";
        default:
            std::stringstream ss;
            ss << std::hex << hr;
            return ss.str();
    }
}


HRESULT inline OPCServerListCreateInstance(COSERVERINFO *serverInfo, COAUTHIDENTITY *authIdent, bool localhost, ATL::CComPtr<IOPCServerList> &iCatInfo) {
    MULTI_QI qiList[1] =
    {
        {&IID_IOPCServerList, nullptr, 0}
    };

    HRESULT hr;

    if (localhost) {
        hr = CoCreateInstanceEx(CLSID_OpcServerList, nullptr, CLSCTX_LOCAL_SERVER, serverInfo, 1, qiList);
        if (SUCCEEDED(hr)) {
            iCatInfo = static_cast<IOPCServerList *>(qiList[0].pItf);
            HRESULT hrAuth = CoSetProxyBlanket(
                iCatInfo, // the proxy to set
                RPC_C_AUTHN_WINNT, // authentication service
                RPC_C_AUTHZ_NONE, // authorization service
                NULL, // server principal name
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
                RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
                authIdent, // authentication information
                EOAC_NONE // additional capabilities
            );
            if (FAILED(hrAuth)) {
                spdlog::error("CoSetProxyBlanket failed on the IOPCServerList with error = {}", hresultToUTF8(hrAuth));
                //return hrAuth;
            }
        } else {
            spdlog::error("CoCreateInstance failed querying the interface IOPCServerList with error = {}", hresultToUTF8(hr));
            iCatInfo = nullptr;
        }
    } else {
        hr = CoCreateInstanceEx(CLSID_OpcServerList, nullptr, CLSCTX_REMOTE_SERVER, serverInfo, 1, qiList);
        if (SUCCEEDED(hr)) {
            iCatInfo = static_cast<IOPCServerList *>(qiList[0].pItf);
            HRESULT hrAuth = CoSetProxyBlanket(
                iCatInfo, // the proxy to set
                RPC_C_AUTHN_WINNT, // authentication service
                RPC_C_AUTHZ_NONE, // authorization service
                NULL, // server principal name
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
                RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
                authIdent, // authentication information
                EOAC_NONE // additional capabilities
            );
            if (FAILED(hrAuth)) {
                spdlog::error("CoSetProxyBlanket failed on the IOPCServerList with error = {}", hresultToUTF8(hrAuth));
                //return hrAuth;
            }
        } else {
            spdlog::error("CoCreateInstance failed querying the interface IOPCServerList with error = {}", hresultToUTF8(hr));
            iCatInfo = nullptr;
        }
    }
    return hr;
}

HRESULT inline OPCServerCreateInstance(COSERVERINFO *serverInfo, COAUTHIDENTITY *authIdent, bool localhost, CLSID clsid, ATL::CComPtr<IOPCServer> &pOPCServer) {
    MULTI_QI qiList[1] =
    {
        {&IID_IOPCServer, nullptr, 0}
    };

    HRESULT hr;

    if (localhost) {
        hr = CoCreateInstanceEx(clsid, nullptr, CLSCTX_LOCAL_SERVER, serverInfo, 1, qiList);
        if (SUCCEEDED(hr)) {
            pOPCServer = static_cast<IOPCServer *>(qiList[0].pItf);
            HRESULT hrAuth = CoSetProxyBlanket(
                pOPCServer, // the proxy to set
                RPC_C_AUTHN_WINNT, // authentication service
                RPC_C_AUTHZ_NONE, // authorization service
                NULL, // server principal name
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
                RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
                authIdent, // authentication information
                EOAC_NONE // additional capabilities
            );
            if (FAILED(hrAuth)) {
                spdlog::error("CoSetProxyBlanket failed on the IOPCServer with error = {}", hresultToUTF8(hrAuth));
                //return hrAuth;
            }
        } else {
            spdlog::error("CoCreateInstance failed querying the interface IOPCServer with error = {}", hresultToUTF8(hr));
            pOPCServer = nullptr;
        }
    } else {
        hr = CoCreateInstanceEx(clsid, nullptr, CLSCTX_REMOTE_SERVER, serverInfo, 1, qiList);
        if (SUCCEEDED(hr)) {
            pOPCServer = static_cast<IOPCServer *>(qiList[0].pItf);
            HRESULT hrAuth = CoSetProxyBlanket(
                pOPCServer, // the proxy to set
                RPC_C_AUTHN_WINNT, // authentication service
                RPC_C_AUTHZ_NONE, // authorization service
                NULL, // server principal name
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
                RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
                authIdent, // authentication information
                EOAC_NONE // additional capabilities
            );
            if (FAILED(hrAuth)) {
                spdlog::error("CoSetProxyBlanket failed on the IOPCServer with error = {}",hresultToUTF8(hrAuth));
                //return hrAuth;
            }
        } else {
            spdlog::error("CoCreateInstance failed querying the interface IOPCServer with error = {}", hresultToUTF8(hr));
            pOPCServer = nullptr;
        }
    }
    return hr;
}

std::string inline variant2UTF8(const VARIANT &myVal) {
    std::stringstream ss;

    if (myVal.vt == VT_R4) ss << static_cast<double>(myVal.fltVal);
    else if (myVal.vt == VT_R8) ss << static_cast<double>(myVal.dblVal);
    else if (myVal.vt == VT_I1) ss << static_cast<int64_t>(myVal.cVal);
    else if (myVal.vt == VT_I2) ss << static_cast<int64_t>(myVal.iVal);
    else if (myVal.vt == VT_I4) ss << static_cast<int64_t>(myVal.lVal);
    else if (myVal.vt == VT_I8) ss << static_cast<int64_t>(myVal.llVal);
    else if (myVal.vt == VT_UI1) ss << static_cast<int64_t>(myVal.bVal);
    else if (myVal.vt == VT_UI2) ss << static_cast<int64_t>(myVal.uiVal);
    else if (myVal.vt == VT_UI4) ss << static_cast<int64_t>(myVal.ulVal);
    else if (myVal.vt == VT_UI8) ss << static_cast<int64_t>(myVal.ullVal);
    else if (myVal.vt == VT_INT) ss << static_cast<int64_t>(myVal.intVal);
    else if (myVal.vt == VT_UINT) ss << static_cast<int64_t>(myVal.uintVal);
    else if (myVal.vt == VT_LPSTR) ss << std::string(myVal.pcVal);
    else if (myVal.vt == VT_LPWSTR) ss << wstringToUTF8(std::wstring(myVal.bstrVal));
    else if (myVal.vt == VT_BSTR) ss << wstringToUTF8(std::wstring(myVal.bstrVal));
    else ss << "unsupported data type";

    return ss.str();
}

std::wstring inline outputVariant(const std::wstring &name, const VARIANT &myVal, const FILETIME &ft,const WORD quality) {
    std::wstringstream ws;


    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    wchar_t date[20], time[20];
    GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &st, nullptr, date, 20);
    GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &st, nullptr, time, 20);

    std::wstringstream outputVariant;
    if (myVal.vt == VT_R4) outputVariant << static_cast<double>(myVal.fltVal);
    else if (myVal.vt == VT_R8) outputVariant << static_cast<double>(myVal.dblVal);
    else if (myVal.vt == VT_I1) outputVariant << static_cast<int64_t>(myVal.cVal);
    else if (myVal.vt == VT_I2) outputVariant << static_cast<int64_t>(myVal.iVal);
    else if (myVal.vt == VT_I4) outputVariant << static_cast<int64_t>(myVal.lVal);
    else if (myVal.vt == VT_I8) outputVariant << static_cast<int64_t>(myVal.llVal);
    else if (myVal.vt == VT_UI1) outputVariant << static_cast<int64_t>(myVal.bVal);
    else if (myVal.vt == VT_UI2) outputVariant << static_cast<int64_t>(myVal.uiVal);
    else if (myVal.vt == VT_UI4) outputVariant << static_cast<int64_t>(myVal.ulVal);
    else if (myVal.vt == VT_UI8) outputVariant << static_cast<int64_t>(myVal.ullVal);
    else if (myVal.vt == VT_INT) outputVariant << static_cast<int64_t>(myVal.intVal);
    else if (myVal.vt == VT_UINT) outputVariant << static_cast<int64_t>(myVal.uintVal);
    else if (myVal.vt == VT_LPSTR) {
        int len = MultiByteToWideChar(CP_ACP, 0, myVal.pcVal, -1, nullptr, 0);
        if (len > 0) {
            std::wstring wstr(len, L'\0');
            MultiByteToWideChar(CP_ACP, 0, myVal.pcVal, -1, &wstr[0], len);
            wstr.resize(len - 1); // Remove the null terminator added by MultiByteToWideChar
            outputVariant << wstr.c_str();
        } else {
            throw std::runtime_error("Failed to convert LPSTR to std::wstring");
        }
    } else if (myVal.vt == VT_LPWSTR) outputVariant << std::wstring(myVal.bstrVal);
    else if (myVal.vt == VT_BSTR) outputVariant << std::wstring(myVal.bstrVal);
    else outputVariant << L" unsupported data type";

    ws << std::setw(10) << std::right << date << L" " << std::setw(10) << std::left << time
            << std::setw(10) << std::right << L"Item: " << std::setw(30) << std::left << name
            << std::setw(10) << std::right << L" Value: " << std::setw(30) << std::left << outputVariant.str()
            << std::setw(10) << std::right << L" Quality: " << std::setw(30) << std::left <<
            opcQualityToWstring(quality);

    std::wstring hrAsWString = ws.str();
    return hrAsWString;
}

inline uint64_t FileTimeToUint64(FILETIME ft) {
    // Using a union to respect type punning rules
    union {
        FILETIME as_file_time;
        ULONGLONG as_ulonglong; // ULONGLONG is equivalent to uint64_t on Windows
    } time_union{};

    time_union.as_file_time = ft;

    return time_union.as_ulonglong;
}

// Function to convert FILETIME to std::chrono::system_clock::time_point
inline std::chrono::system_clock::time_point FileTimeToChrono(const FILETIME& ft)
{
    // Copy the FILETIME struct to a ULARGE_INTEGER union to make it easier to work with.
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    // Convert to microseconds and adjust to Unix epoch.
    auto microseconds = ull.QuadPart / 10;
    auto unixEpochTime = microseconds - 11644473600000000ULL; // FILETIME epoch (1601) to Unix epoch (1970)

    return std::chrono::system_clock::time_point(std::chrono::microseconds(unixEpochTime));
}

inline std::string GUIDToUTF8(const GUID& guid) {
    wchar_t guidString[39]; // GUID string format is 38 characters plus null terminator
    int result = StringFromGUID2(guid, guidString, ARRAYSIZE(guidString));
    if (result == 0) {
        if(easyopcda::logEnabler.logToDefault)
            spdlog::error("unable to print GUID, error: {}", hresultToUTF8(result));
        return "";
    }
    return wstringToUTF8(std::wstring(guidString));
}

inline bool stringToGUID(const std::wstring& guidString, GUID& guid) {
    HRESULT hr = CLSIDFromString(guidString.c_str(), &guid);
    return SUCCEEDED(hr);
}

inline USHORT* CopyWStringToAuthIdentity(const std::wstring& wstr) {
    USHORT* pCopy = (USHORT*)CoTaskMemAlloc((wstr.length() + 1) * sizeof(USHORT));
    if (pCopy) {
        memcpy(pCopy, wstr.c_str(), (wstr.length() + 1) * sizeof(USHORT));
    }
    return pCopy;
}


#endif //EASYOPCDA_H
