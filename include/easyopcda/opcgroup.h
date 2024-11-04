// ******  easyopcda v0.1  ******
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


#ifndef OPCGROUP_H
#define OPCGROUP_H


#include <atlbase.h>

#include "easyopcda.h"
#include "opccomn.h"
#include "opcda.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/ostream_sink.h"
#include "spdlog/fmt/chrono.h"

#include <string>
#include <vector>
#include <map>
#include <condition_variable>
#include <mutex>

struct itemDef {
    OPCITEMRESULT itemRes;
    HRESULT itemErr;
};

class OPCGroup : public IOPCDataCallback, public IOPCShutdown {
private:
    IOPCServer* myOPCServer;

    DWORD ReferencesCount;

    std::wstring myName;

    bool error;
    std::stringstream ss;
    std::shared_ptr<spdlog::sinks::ostream_sink_mt> ss_sink;
    std::shared_ptr<spdlog::logger> logger;

    ATL::CComPtr<IOPCGroupStateMgt> groupMgr;
    ATL::CComPtr<IOPCItemMgt> itemMgr;
    ATL::CComPtr<IOPCSyncIO> syncIO;
    ATL::CComPtr<IOPCSyncIO2> syncIO2;
    ATL::CComPtr<IOPCAsyncIO> asyncIO;
    ATL::CComPtr<IOPCAsyncIO2> asyncIO2;
    ATL::CComPtr<IOPCAsyncIO3> asyncIO3;

    ATL::CComPtr<IConnectionPointContainer> connectionPointContainer;
    ATL::CComPtr<IConnectionPoint> asyncDataCallbackConnectionPoint;
    ATL::CComPtr<IConnectionPoint> shutdownConnectionPoint;
    DWORD asyncCallbackHandle;
    DWORD shutdownHandle;

    std::mutex transactionMutex;
    DWORD lastClientTransactionID;
    std::map<DWORD,DWORD> clientServerTransactionID;
    std::condition_variable cv;

    OPCHANDLE thisGroupHandle;

    std::map<std::wstring,itemDef> itemsMap;
    std::map<OPCHANDLE,std::wstring> serverItemHandlesMap;
    OPCHANDLE lastClientItemHandle;
    std::map<OPCHANDLE,std::wstring> clientItemHandlesMap;

    easyopcda::ASyncCallback externalAsyncCallback;

public:
    DWORD realUpdateRate;

    OPCGroup(std::wstring name, CComPtr<IOPCServer> &pOPCServer, COAUTHIDENTITY *pAuthIdent, DWORD reqUpdRate, easyopcda::ASyncCallback func);
    virtual ~OPCGroup();

    void validateItems(std::vector<std::wstring> &inputItems);
    void addItems(std::vector<std::wstring> &inputItems);
    void removeItems(std::vector<std::wstring> &items);

    void asyncEnableAutoReadGroup();
    void asyncDisableAutoReadGroup();

    void syncReadItems(std::vector<std::wstring> &items);
    void syncReadGroup();
    void asyncReadGroup();
    void waitForTransactionsComplete();

    // implementation of IUNKOWN
    STDMETHODIMP QueryInterface(REFIID iid, LPVOID *ppInterface) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;
    // implementation of IOPCDataCallback
    STDMETHODIMP OnDataChange(DWORD transactionID, OPCHANDLE groupHandle, HRESULT masterQuality, HRESULT masterError,
        DWORD count, OPCHANDLE *clientHandles, VARIANT *values, WORD *quality, FILETIME *time,HRESULT *errors) override;
    STDMETHODIMP OnReadComplete(DWORD transactionID, OPCHANDLE groupHandle, HRESULT masterQuality, HRESULT masterError,
        DWORD count, OPCHANDLE *clientHandles, VARIANT *values, WORD *quality, FILETIME *time, HRESULT *errors) override;
    STDMETHODIMP OnWriteComplete(DWORD transactionID, OPCHANDLE groupHandle, HRESULT masterError, DWORD count,
        OPCHANDLE *clientHandles, HRESULT *errors) override;
    STDMETHODIMP OnCancelComplete(DWORD transactionID, OPCHANDLE groupHandle) override;
    // implementation of IOPCShutdown
    STDMETHODIMP ShutdownRequest(LPCWSTR szReason) override;

    HRESULT internalAsyncCallback(DWORD count, OPCHANDLE *clientHandles, VARIANT *values, WORD *quality, FILETIME *time,HRESULT *errors);

    void syncWriteItems(std::vector<std::wstring> &items, std::vector<double> values);

    bool isError() const {return error;}
    std::string lastMessage() {
        auto rv = ss.str();
        ss.clear();
        return rv;
    }
};

#endif //OPCGROUP_H
