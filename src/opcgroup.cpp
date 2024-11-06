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


#include "easyopcda/easyopcda.h"
#include "easyopcda/opcgroup.h"
#include "easyopcda/opcda.h"

#include"spdlog/spdlog.h"

#include <string>
#include <utility>

OPCGroup::OPCGroup(std::wstring name, CComPtr<IOPCServer> &pOPCServer, COAUTHIDENTITY *pAuthIdent, DWORD reqUpdRate, easyopcda::ASyncCallback func)
//: ss_sink(std::make_shared<spdlog::sinks::ostream_sink_mt>(ss)),
//  logger(std::make_shared<spdlog::logger>("easyopcda", ss_sink))
{
    error = false;
    myOPCServer = pOPCServer.p;

    myName = std::move(name);

    externalAsyncCallback = std::move(func);

    ReferencesCount = 0;

    lastClientItemHandle = 0;

    lastClientTransactionID = 0;

    HRESULT hr;
    OPCHANDLE clientHandle = 0;
    DWORD lcid = 0x409; // Code 0x409 = ENGLISH

    if (pOPCServer == nullptr) {
        error = true;
        ERROR_LOG("invalid OPC server");
        return;
    }

    groupMgr = nullptr;
    itemMgr = nullptr;
    syncIO = nullptr;
    syncIO2 = nullptr;
    asyncIO = nullptr;
    asyncIO2 = nullptr;
    asyncIO3 = nullptr;
    connectionPointContainer = nullptr;
    asyncDataCallbackConnectionPoint = nullptr;
    asyncCallbackHandle = 0;
    shutdownConnectionPoint = nullptr;
    shutdownHandle = 0;

    thisGroupHandle = NULL;
    realUpdateRate = 0;

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Thread building OPC group: {}", hid);

    hr = pOPCServer->AddGroup(myName.c_str(), //	una stringa con il nome del gruppo?
                              FALSE, //	attivo o no??
                              reqUpdRate, //	update rate richiesto
                              clientHandle, //	handle richiesto
                              nullptr, //	fuso orario?
                              nullptr, //	banda morta?
                              lcid, //	lingua
                              &thisGroupHandle, //	restituisce l'handle vero
                              &realUpdateRate, //	update rate vero
                              IID_IOPCGroupStateMgt, //	quale interfaccia vuoi?
                              (LPUNKNOWN *) &groupMgr); //	puntatore dove mettere interfaccia
    if (FAILED(hr)) {
        groupMgr = nullptr;
        error = true;
        ERROR_LOG("function AddGroup of OPCServer instance failed. Error: {}", hresultToUTF8(hr));
        return;
    }
    HRESULT hrAuth = CoSetProxyBlanket(
        groupMgr, // the proxy to set
        RPC_C_AUTHN_WINNT, // authentication service
        RPC_C_AUTHZ_NONE, // authorization service
        NULL, // server principal name
        RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
        RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
        pAuthIdent, // authentication information
        EOAC_NONE // additional capabilities
    );
    if (FAILED(hrAuth)) {
        ERROR_LOG("CoSetProxyBlanket failed on the IOPCGroupStateMgt with error ", hresultToUTF8(hrAuth));
        //return;
    }


    hr = groupMgr->QueryInterface(IID_IOPCItemMgt, (void **) &itemMgr);
    if (FAILED(hr)) {
        itemMgr = nullptr;
        error = true;
        ERROR_LOG("QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCItemMgt. Error: {}", hresultToUTF8(hr));
        return;
    } else {
        HRESULT hrAuth = CoSetProxyBlanket(
            itemMgr, // the proxy to set
            RPC_C_AUTHN_WINNT, // authentication service
            RPC_C_AUTHZ_NONE, // authorization service
            NULL, // server principal name
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
            RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
            pAuthIdent, // authentication information
            EOAC_NONE // additional capabilities
        );
        if (FAILED(hrAuth)) {
            ERROR_LOG("CoSetProxyBlanket failed on the IOPCItemMgt with error: {}", hresultToUTF8(hrAuth));
        }
    }

    hr = groupMgr->QueryInterface(IID_IOPCSyncIO, (void **) &syncIO);
    if (FAILED(hr)) {
        syncIO = nullptr;
        ERROR_LOG("QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCSyncIO. Error: {}", hresultToUTF8(hr));
    } else {
        HRESULT hrAuth = CoSetProxyBlanket(
            syncIO, // the proxy to set
            RPC_C_AUTHN_WINNT, // authentication service
            RPC_C_AUTHZ_NONE, // authorization service
            NULL, // server principal name
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
            RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
            pAuthIdent, // authentication information
            EOAC_NONE // additional capabilities
        );
        if (FAILED(hrAuth)) {
            ERROR_LOG("CoSetProxyBlanket failed on the IOPCSyncIO with error: {}", hresultToUTF8(hrAuth));
        }
    }


    hr = groupMgr->QueryInterface(IID_IOPCSyncIO2, (void **) &syncIO2);
    if (FAILED(hr)) {
        syncIO2 = nullptr;
        ERROR_LOG("QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCSyncIO2. Error: {}", hresultToUTF8(hr));
    } else {
        HRESULT hrAuth = CoSetProxyBlanket(
            syncIO2, // the proxy to set
            RPC_C_AUTHN_WINNT, // authentication service
            RPC_C_AUTHZ_NONE, // authorization service
            NULL, // server principal name
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
            RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
            pAuthIdent, // authentication information
            EOAC_NONE // additional capabilities
        );
        if (FAILED(hrAuth)) {
            ERROR_LOG("CoSetProxyBlanket failed on the IOPCSyncIO2 with error: {}", hresultToUTF8(hrAuth));
        }
    }

    bool daSpec10 = false;
    bool daSpec20 = false;
    bool daSpec30 = false;

    HRESULT hr1 = groupMgr->QueryInterface(IID_IOPCAsyncIO, (void **) &asyncIO);
    if SUCCEEDED(hr1) {
        daSpec10 = true;

        HRESULT hrAuth = CoSetProxyBlanket(
            asyncIO, // the proxy to set
            RPC_C_AUTHN_WINNT, // authentication service
            RPC_C_AUTHZ_NONE, // authorization service
            NULL, // server principal name
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
            RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
            pAuthIdent, // authentication information
            EOAC_NONE // additional capabilities
        );
        if (FAILED(hrAuth)) {
            ERROR_LOG("CoSetProxyBlanket failed on the IOPCAsyncIO with error: {}", hresultToUTF8(hrAuth));
        }
    } else {
        asyncIO = nullptr;
        ERROR_LOG("QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCAsyncIO. Error: {}", hresultToUTF8(hr1));
    }

    HRESULT hr2 = groupMgr->QueryInterface(IID_IOPCAsyncIO2, (void **) &asyncIO2);
    if SUCCEEDED(hr2) {
        daSpec20 = true;

        HRESULT hrAuth = CoSetProxyBlanket(
            asyncIO2, // the proxy to set
            RPC_C_AUTHN_WINNT, // authentication service
            RPC_C_AUTHZ_NONE, // authorization service
            NULL, // server principal name
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
            RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
            pAuthIdent, // authentication information
            EOAC_NONE // additional capabilities
        );
        if (FAILED(hrAuth)) {
            ERROR_LOG("CoSetProxyBlanket failed on the IOPCAsyncIO2 with error: {}", hresultToUTF8(hrAuth));
        }
    } else {
        asyncIO2 = nullptr;
        ERROR_LOG("QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCAsyncIO2. Error: {}", hresultToUTF8(hr2));
    }

    HRESULT hr3 = groupMgr->QueryInterface(IID_IOPCAsyncIO3, (void **) &asyncIO3);
    if SUCCEEDED(hr3) {
        daSpec30 = true;

        HRESULT hrAuth = CoSetProxyBlanket(
            asyncIO3, // the proxy to set
            RPC_C_AUTHN_WINNT, // authentication service
            RPC_C_AUTHZ_NONE, // authorization service
            NULL, // server principal name
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
            RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
            pAuthIdent, // authentication information
            EOAC_NONE // additional capabilities
        );
        if (FAILED(hrAuth)) {
            ERROR_LOG("CoSetProxyBlanket failed on the IOPCAsyncIO3 with error: {}", hresultToUTF8(hrAuth));
        }
    } else {
        asyncIO3 = nullptr;
        ERROR_LOG("QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCAsyncIO3. Error: {}", hresultToUTF8(hr3));
    }

    if (daSpec20 || daSpec30) {
        HRESULT result = groupMgr->QueryInterface(IID_IConnectionPointContainer, (void **) &connectionPointContainer);
        if (SUCCEEDED(result)) {
            HRESULT hrAuth = CoSetProxyBlanket(
                connectionPointContainer, // the proxy to set
                RPC_C_AUTHN_WINNT, // authentication service
                RPC_C_AUTHZ_NONE, // authorization service
                NULL, // server principal name
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
                RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
                pAuthIdent, // authentication information
                EOAC_NONE // additional capabilities
            );
            if (FAILED(hrAuth)) {
                ERROR_LOG("CoSetProxyBlanket failed on the IConnectionPointContainer with error: {}", hresultToUTF8(hrAuth));
            }

            result = connectionPointContainer->FindConnectionPoint(IID_IOPCDataCallback,&asyncDataCallbackConnectionPoint);
            if (SUCCEEDED(result)) {
                HRESULT hrAuth = CoSetProxyBlanket(
                    asyncDataCallbackConnectionPoint, // the proxy to set
                    RPC_C_AUTHN_WINNT, // authentication service
                    RPC_C_AUTHZ_NONE, // authorization service
                    NULL, // server principal name
                    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
                    RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
                    pAuthIdent, // authentication information
                    EOAC_NONE // additional capabilities
                    );
                if (FAILED(hrAuth)) {
                    ERROR_LOG("CoSetProxyBlanket failed on the IConnectionPoint with error: {}", hresultToUTF8(hrAuth));
                }

                result = asyncDataCallbackConnectionPoint->Advise((IUnknown *) ((IOPCDataCallback *) this),&asyncCallbackHandle);
                if (FAILED(result)) {
                    if(asyncIO2) {
                        asyncIO2.Release();
                        asyncIO2 = nullptr;
                    }
                    if(asyncIO3) {
                        asyncIO3.Release();
                        asyncIO3 = nullptr;
                    }
                    asyncDataCallbackConnectionPoint = nullptr;
                    asyncCallbackHandle = 0;
                    ERROR_LOG("Failed to retrieve handle of IOPCDataCallback from class IID_IOPCDataCallback. Cannot implement async read/write connection. Error: {}", hresultToUTF8(result));
                }
            } else {
                if(asyncIO2) {
                    asyncIO2.Release();
                    asyncIO2 = nullptr;
                }
                if(asyncIO3) {
                    asyncIO3.Release();
                    asyncIO3 = nullptr;
                }
                asyncDataCallbackConnectionPoint = nullptr;
                asyncCallbackHandle = 0;
                ERROR_LOG("Failed to retrieve interface pointer IID_IOPCDataCallback from class IID_IConnectionPointContainer. Cannot implement async read/write connection. Error: {}", hresultToUTF8(result));
            }

            result = connectionPointContainer->FindConnectionPoint(IID_IOPCShutdown, &shutdownConnectionPoint);
            if (SUCCEEDED(result)) {
                HRESULT hrAuth = CoSetProxyBlanket(
                    shutdownConnectionPoint, // the proxy to set
                    RPC_C_AUTHN_WINNT, // authentication service
                    RPC_C_AUTHZ_NONE, // authorization service
                    NULL, // server principal name
                    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
                    RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
                    pAuthIdent, // authentication information
                    EOAC_NONE // additional capabilities
                );
                if (FAILED(hrAuth)) {
                    ERROR_LOG("CoSetProxyBlanket failed on the IConnectionPoint with error: {}", hresultToUTF8(hrAuth));
                }

                result = shutdownConnectionPoint->Advise((IUnknown *) ((IOPCShutdown *) this), &shutdownHandle);
                if (FAILED(result)) {
                    shutdownConnectionPoint = nullptr;
                    shutdownHandle = 0;
                    ERROR_LOG("Failed to retrieve handle of IOPCShutdown from class IID_IOPCShutdown. Cannot implement async shutdown connection. Error: {}",hresultToUTF8(result));
                }
            } else {
                asyncDataCallbackConnectionPoint = nullptr;
                shutdownConnectionPoint = nullptr;
                ERROR_LOG("Failed to retrieve interface pointer IID_IOPCShutdown from class IID_IConnectionPointContainer. Cannot implement async shutdown connection. Error: {}", hresultToUTF8(result));
            }
        }
    }
}


OPCGroup::~OPCGroup() {
    asyncDisableAutoReadGroup();

    std::map<DWORD,DWORD> copyIDs;
    {
        std::lock_guard<std::mutex> stackLock(transactionMutex);
        copyIDs = clientServerTransactionID;
   }

    for (auto i = copyIDs.begin(); i != copyIDs.end(); ++i) {
        HRESULT hr;
        if (asyncIO3) {
            hr = asyncIO3->Cancel2(i->second);
            if FAILED(hr) {
                error = true;
                ERROR_LOG("Call to asyncIO3->Cancel2 returned error: {}", hresultToUTF8(hr));
            }
        } else if (asyncIO2) {
            hr = asyncIO2->Cancel2(i->second);
            if FAILED(hr) {
                error = true;
                ERROR_LOG("Call to asyncIO2->Read returned error: {}", hresultToUTF8(hr));
            }
        } else {
            ERROR_LOG("No async interfaces available (support only IID_IOPCAsyncIO2 and IID_IOPCAsyncIO3");
            return;
        }
    }

    if (myOPCServer) {
        HRESULT hr = myOPCServer->RemoveGroup(thisGroupHandle,TRUE);
        if FAILED(hr) {
            ERROR_LOG("Call to IOPCSerer->RemoveGroup failed with error: {}", hresultToUTF8(hr));
        }
    }
    myOPCServer = nullptr;

    if (asyncDataCallbackConnectionPoint) asyncDataCallbackConnectionPoint->Unadvise(asyncCallbackHandle);
    if (shutdownConnectionPoint) shutdownConnectionPoint->Unadvise(shutdownHandle);

    for (auto it = itemsMap.begin(); it != itemsMap.end(); ++it) {
        if (it->second.itemRes.pBlob) CoTaskMemFree(it->second.itemRes.pBlob);
    }
}


void OPCGroup::addItems(std::vector<std::wstring> &inputItems) {
    if (error) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return;
    }

    std::vector<OPCITEMDEF> itemDefs;
    std::vector<std::wstring> itemNames;
    OPCITEMRESULT *pAddResult = nullptr;
    HRESULT *pErrors = nullptr;
    HRESULT hr;


    for (size_t i = 0; i < inputItems.size(); i++) {
        if (itemsMap.count(inputItems[i]) == 0) {
            OPCITEMDEF newItem;
            //	define an item table with one item as in-paramter for AddItem
            newItem.szAccessPath = &(std::wstring(L"")[0]); //	Accesspath not needed
            newItem.szItemID = &inputItems[i][0]; //	ItemID
            newItem.bActive = FALSE;
            newItem.hClient = ++lastClientItemHandle;
            newItem.dwBlobSize = 0;
            newItem.pBlob = nullptr;
            newItem.vtRequestedDataType = 0; //	return values in native (cannonical) datatype
            itemDefs.push_back(newItem);
            itemNames.push_back(inputItems[i]);
            clientItemHandlesMap[lastClientItemHandle] = inputItems[i];
        }
    }

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Thread adding OPC items: {}", hid);

    hr = itemMgr->AddItems(itemDefs.size(), itemDefs.data(), &pAddResult, &pErrors);
    if SUCCEEDED(hr) {
        for (size_t i = 0; i < itemDefs.size(); i++) {
            INFO_LOG("Requested tag: {} returned status: {}", wstringToUTF8(itemNames[i]), hresultToUTF8((pErrors[i])));
            itemsMap[itemNames[i]].itemRes = pAddResult[i];
            itemsMap[itemNames[i]].itemErr = pErrors[i];
            serverItemHandlesMap[pAddResult[i].hServer] = itemNames[i];
        }
    } else {
        error = true;
        ERROR_LOG("Call to AddItems returned error: {}", hresultToUTF8(hr));
    }

    if (pAddResult) CoTaskMemFree(pAddResult);
    if (pErrors) CoTaskMemFree(pErrors);
}

void OPCGroup::validateItems(std::vector<std::wstring> &inputItems) {
    if (error) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return;
    }

    std::map<std::wstring, OPCITEMDEF> localItemsMap;
    std::vector<OPCITEMDEF> itemDefs;
    std::vector<std::wstring> itemNames;

    OPCITEMRESULT *pAddResult = nullptr;
    HRESULT *pErrors = nullptr;
    HRESULT hr;


    for (size_t i = 0; i < inputItems.size(); i++) {
        if (localItemsMap.count(inputItems[i]) == 0) {
            OPCITEMDEF newItem;
            newItem.szAccessPath = L""; //	Accesspath not needed
            newItem.szItemID = &inputItems[i][0]; //	ItemID
            newItem.bActive = FALSE;
            newItem.hClient = 1;
            newItem.dwBlobSize = 0;
            newItem.pBlob = nullptr;
            newItem.vtRequestedDataType = 0; //	return values in native (cannonical) datatype
            itemDefs.push_back(newItem);
            itemNames.push_back(inputItems[i]);
            localItemsMap[inputItems[i]] = newItem;
        }
    }

    hr = itemMgr->ValidateItems(itemDefs.size(), itemDefs.data(), false, &pAddResult, &pErrors);
    if SUCCEEDED(hr) {
        for (auto i = 0; i < itemDefs.size(); i++) {
            INFO_LOG("Requested tag: {} returned status: {}", wstringToUTF8(itemNames[i]), hresultToUTF8(pErrors[i]));
            if (itemsMap.count(itemNames[i]) > 0) {
                itemsMap[itemNames[i]].itemErr = pErrors[i];
            }
        }
    } else {
        error = true;
        ERROR_LOG("Call to ValidateItems returned error: {]", hresultToUTF8(hr));
    }

    if (pAddResult) {
        for (size_t i = 0; i < itemDefs.size(); i++) {
            if (pAddResult[i].pBlob) CoTaskMemFree(pAddResult[i].pBlob);
        }
        CoTaskMemFree(pAddResult);
    }
    if (pErrors) CoTaskMemFree(pErrors);

}

void OPCGroup::removeItems(std::vector<std::wstring> &items) {
    if (error) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return;
    }

    ERROR_LOG("not yet implemented");
}

void OPCGroup::syncReadGroup() {
    if (error) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return;
    }

    std::vector<OPCHANDLE> itemHandles;
    std::vector<std::wstring> itemNames;
    OPCITEMSTATE *pItemValues = nullptr;
    HRESULT *pErrors = nullptr;

    for (auto i = itemsMap.begin(); i != itemsMap.end(); ++i) {
        if SUCCEEDED(i->second.itemErr) {
            itemNames.push_back(i->first);
            itemHandles.push_back(i->second.itemRes.hServer);
        }
    }

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Thread sync reading group: {}",hid);

    HRESULT hr;
    if (syncIO2) {
        hr = syncIO2->Read(OPC_DS_CACHE, itemHandles.size(), itemHandles.data(), &pItemValues, &pErrors);
        // we can use ReadMaxAge here
    } else if (syncIO) {
        hr = syncIO->Read(OPC_DS_CACHE, itemHandles.size(), itemHandles.data(), &pItemValues, &pErrors);
    } else {
        ERROR_LOG("No sync read interfaces available! operation not performed");
        return;
    }
    if SUCCEEDED(hr) {
        std::vector<OPCHANDLE> clientHandles(itemHandles.size());
        std::vector<VARIANT> VARIANTValues(itemHandles.size());
        std::vector<WORD> qualityValues(itemHandles.size());
        std::vector<FILETIME> timeValues(itemHandles.size());
        std::vector<HRESULT> errors(itemHandles.size());
        for (auto i = 0; i < itemHandles.size(); i++) {
            clientHandles[i]=pItemValues[i].hClient;
            VARIANTValues[i]=pItemValues[i].vDataValue;
            qualityValues[i]=pItemValues[i].wQuality;
            timeValues[i] = pItemValues[i].ftTimeStamp;
            errors[i]=pErrors[i];
        }
        INFO_LOG("Sync Read processed {} items",itemHandles.size());
        internalAsyncCallback(itemHandles.size(),clientHandles.data(), VARIANTValues.data(), qualityValues.data(),timeValues.data(),errors.data());

        for (auto i = 0; i < itemHandles.size(); i++) {
            if FAILED(pErrors[i]) {
                if (clientItemHandlesMap.count(pItemValues[i].hClient)>0)
                   WARN_LOG("Call to SyncIO returned error for specific item: {:<20}: {}", wstringToUTF8(clientItemHandlesMap[pItemValues[i].hClient]), hresultToUTF8(hr));
            } else {
                if (clientItemHandlesMap.count(pItemValues[i].hClient)>0)
                    INFO_LOG(
                        "group: {:<10}item: {:<20}time: {:<30}\tvalue: {:<20}\tquality: {:<15}\terror: {:<15}",
                        wstringToUTF8(myName),
                        wstringToUTF8(clientItemHandlesMap[pItemValues[i].hClient]),
                        FileTimeToChrono(pItemValues[i].ftTimeStamp),
                        variant2UTF8(pItemValues[i].vDataValue),
                        opcQualityToUTF8(pItemValues[i].wQuality),
                        hresultToUTF8(pErrors[i])
                        );
            }
        }
    } else {
        error = true;
        ERROR_LOG("Call to SyncIO returned error: {}", hresultToUTF8(hr));
    }


    if (pItemValues != NULL) {
        for (auto i = 0; i < itemHandles.size(); i++) {
            hr = VariantClear(&(pItemValues[i].vDataValue));
            if FAILED(hr) {
                error = true;
                ERROR_LOG("Call to VariantClear returned error: {}", hresultToUTF8(hr));
            }
        }
        CoTaskMemFree(pItemValues);
    }
    if (pErrors != NULL) CoTaskMemFree(pErrors);
}

void OPCGroup::asyncReadGroup() {
    if (error) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return;
    }

    std::vector<OPCHANDLE> itemHandles;
    std::vector<std::wstring> itemNames;
    DWORD serverCancelID = 0;
    HRESULT *pErrors = nullptr;

    for (auto i = itemsMap.begin(); i != itemsMap.end(); ++i) {
        if SUCCEEDED(i->second.itemErr) {
            itemNames.push_back(i->first);
            itemHandles.push_back(i->second.itemRes.hServer);
        }
    }

    HRESULT hr;
    {
        std::lock_guard<std::mutex> stackLock(transactionMutex);
        while (clientServerTransactionID.count(++lastClientTransactionID) != 0);
    }

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Thread async reading group: {}",hid);

    if (asyncIO3) {
        hr = asyncIO3->Read(itemHandles.size(), itemHandles.data(), lastClientTransactionID, &serverCancelID, &pErrors);
        if FAILED(hr) {
            error = true;
            ERROR_LOG("Call to asyncIO3->Read returned error: {}", hresultToUTF8(hr));
            return;
        }
    } else if (asyncIO2) {
        hr = asyncIO2->Read(itemHandles.size(), itemHandles.data(), lastClientTransactionID, &serverCancelID, &pErrors);
        if FAILED(hr) {
            error = true;
            ERROR_LOG("Call to asyncIO2->Read returned error: {}", hresultToUTF8(hr));
            return;
        }
    } else {
        ERROR_LOG("No async interfaces available (support only IID_IOPCAsyncIO2 and IID_IOPCAsyncIO3");
        return;
    }

    {
        std::lock_guard<std::mutex> stackLock(transactionMutex);
        clientServerTransactionID[lastClientTransactionID] = serverCancelID;
    }

    INFO_LOG("Async Read processed {} items",itemHandles.size());

    if (!error) {
        if (pErrors) {
            for (auto i = 0; i < itemHandles.size(); i++) {
                if(FAILED(pErrors[i]))
                    WARN_LOG("Async Read requested tag: {:<20} returned status: {}", wstringToUTF8(itemNames[i]), hresultToUTF8(pErrors[i]));
            }
        }
    }

    if (pErrors != NULL) CoTaskMemFree(pErrors);
}

void OPCGroup::syncReadItems(std::vector<std::wstring> &items) {
    if (error) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return;
    }
    ERROR_LOG("not yet implemented");
}

void OPCGroup::syncWriteItems(std::vector<std::wstring> &items, std::vector<double> values) {
    if (error) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return;
    }
    ERROR_LOG("not yet implemented");
}

// implementation of DCOM interfaces
STDMETHODIMP OPCGroup::QueryInterface(REFIID iid, LPVOID *ppInterface) {
    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Queryinterface called on OPCGroup. Thread running QueryInterface: {}",hid);

    if (!ppInterface) {
        return E_POINTER;
    }

    DEBUG_LOG("Requested iid: {}", GUIDToUTF8(iid));
    DEBUG_LOG("IID_IUnknown: ", GUIDToUTF8(IID_IUnknown));
    DEBUG_LOG("IID_IOPCDataCallback: ", GUIDToUTF8(IID_IOPCDataCallback));
    DEBUG_LOG("IID_IOPCShutdown: ", GUIDToUTF8(IID_IOPCShutdown));

    if (iid == IID_IUnknown) {
        DEBUG_LOG("Queryinterface is passing IUnknown");
        *ppInterface = (IUnknown*)((IOPCDataCallback*)this);
    } else if (iid == IID_IOPCDataCallback) {
        DEBUG_LOG("Queryinterface is passing IOPCDataCallback");
        *ppInterface = (IOPCDataCallback*)this;
    } else if (iid == IID_IOPCShutdown) {
        DEBUG_LOG("Queryinterface is passing IOPCShutdown");
        *ppInterface = (IOPCShutdown*)this;
    } else {
        DEBUG_LOG("Queryinterface is passing null");
        *ppInterface = nullptr;
        return E_NOINTERFACE;
    } // else

    AddRef();
    return S_OK;
} // QueryInterface

STDMETHODIMP_(ULONG) OPCGroup::AddRef() {
    return ++ReferencesCount;
} // AddRef

STDMETHODIMP_(ULONG) OPCGroup::Release() {
    DWORD count = ReferencesCount ? --ReferencesCount : 0;
    if (!count) {
        //delete this;
    }
    return count;
} // Release

// implementation of OPC callback
HRESULT OPCGroup::internalAsyncCallback(DWORD count, OPCHANDLE *clientHandles, VARIANT *values, WORD *quality,
                                        FILETIME *time, HRESULT *errors) {
    for (auto i = 0; i < count; i++) {
        OPCHANDLE itemHandle = clientHandles[i];
        if (clientItemHandlesMap.count(itemHandle) > 0) {
            std::wstring itemName = clientItemHandlesMap[itemHandle];
            HRESULT error = S_OK;
            if (errors) {
                if (itemsMap.count(itemName) > 0) {
                    if (itemsMap[itemName].itemErr != errors[i]) itemsMap[itemName].itemErr = errors[i];
                    error = errors[i];
                }
            }
            INFO_LOG(
               "group: {:<10}item: {:<20}time: {:<30}\tvalue: {:<20}\tquality: {:<15}\terror: {:<15}",
                wstringToUTF8(myName),
                wstringToUTF8(itemName),
                FileTimeToChrono(time[i]),
                variant2UTF8(values[i]),
                opcQualityToUTF8(quality[i]),
                hresultToUTF8(error)
                );
            externalAsyncCallback(myName, {itemName, time[i], values[i], quality[i], error});
        } else {
            ERROR_LOG("Invalid client item handle passed to async callback function");
            return S_FALSE;
        }
    }

    return S_OK;
}

STDMETHODIMP OPCGroup::OnDataChange(DWORD transactionID, OPCHANDLE groupHandle, HRESULT masterQuality,
                                    HRESULT masterError,
                                    DWORD count, OPCHANDLE *clientHandles, VARIANT *values, WORD *quality,
                                    FILETIME *time, HRESULT *errors) {
    if (isError()) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return E_FAIL;
    }

    {
        std::lock_guard<std::mutex> stackLock(transactionMutex);
        if (clientServerTransactionID.count(transactionID) > 0) {
            clientServerTransactionID.erase(transactionID);
        }
    }
    cv.notify_all();

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Thread running OnDataChange: {}", hid);

    return internalAsyncCallback(count, clientHandles, values, quality, time, errors);
}

STDMETHODIMP OPCGroup::OnReadComplete(DWORD transactionID, OPCHANDLE groupHandle, HRESULT masterQuality,
                                      HRESULT masterError,
                                      DWORD count, OPCHANDLE *clientHandles, VARIANT *values, WORD *quality,
                                      FILETIME *time, HRESULT *errors) {
    if (isError()) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return E_FAIL;
    }

    {
        std::lock_guard<std::mutex> stackLock(transactionMutex);
        if (clientServerTransactionID.count(transactionID) > 0) {
            clientServerTransactionID.erase(transactionID);
        }
    }
    cv.notify_all();

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Thread running OnReadComplete {}",hid);

    return internalAsyncCallback(count, clientHandles, values, quality, time, errors);
}

STDMETHODIMP OPCGroup::OnWriteComplete(DWORD transactionID, OPCHANDLE groupHandle, HRESULT masterError, DWORD count, OPCHANDLE *clientHandles, HRESULT *errors) {
    if (error) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return E_FAIL;
    }
    ERROR_LOG("not yet implemented");
    return S_OK;
}

STDMETHODIMP OPCGroup::OnCancelComplete(DWORD transactionID, OPCHANDLE groupHandle) {
    if (isError()) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return E_FAIL;
    }

    {
        std::lock_guard<std::mutex> stackLock(transactionMutex);
        if (clientServerTransactionID.count(transactionID) > 0) {
            clientServerTransactionID.erase(transactionID);
        }
    }
    cv.notify_all();

    return S_OK;
}

void OPCGroup::waitForTransactionsComplete() {
    std::unique_lock<std::mutex> lock(transactionMutex);
    if(!clientServerTransactionID.empty()) {
        cv.wait(lock, [this] { return (this->clientServerTransactionID.empty()); } );
    }
}

void OPCGroup::asyncEnableAutoReadGroup() {
    if (error) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return;
    }

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    ERROR_LOG("Thread setting group and items active: {}", hid);

    if (groupMgr) {
        DWORD rUpRt;
        BOOL active = FALSE;
        HRESULT hr = groupMgr->SetState(nullptr, &rUpRt, &active, nullptr, nullptr, nullptr, nullptr);
        if FAILED(hr) {
            error = true;
            ERROR_LOG("Call to IOPCGroup->SetState failed");
            return;
        }

        std::vector<OPCHANDLE> handles;
        for (auto i = itemsMap.begin(); i != itemsMap.end(); ++i) {
            handles.push_back(i->second.itemRes.hServer);
        }
        active = TRUE;
        HRESULT *pErrors;

        if (itemMgr) {
            hr = itemMgr->SetActiveState(handles.size(), handles.data(), active, &pErrors);
            if FAILED(hr) {
                error = true;
                ERROR_LOG("Call to IOPCItem->SetActiveState failed");
                return;
            }
        }
        hr = groupMgr->SetState(nullptr, &rUpRt, &active, nullptr, nullptr, nullptr, nullptr);
        if FAILED(hr) {
            error = true;
            ERROR_LOG("Call to IOPCGroup->SetState failed");
            return;
        }
    }
    INFO_LOG("group and items set active");
}

void OPCGroup::asyncDisableAutoReadGroup() {
    if (error) {
        DEBUG_LOG("OPC connection in error state. cannot accept further requests");
        return;
    }

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Thread setting group and items inactive: {}", hid);

    if (groupMgr) {
        DWORD rUpRt;
        BOOL active = FALSE;
        HRESULT hr = groupMgr->SetState(nullptr, &rUpRt, &active, nullptr, nullptr, nullptr, nullptr);
        if FAILED(hr) {
            error = true;
            ERROR_LOG("Call to IOPCItem->SetState failed. Error: {}", hresultToUTF8(hr));
            return;
        }
    }
    INFO_LOG("group set inactive");
}

STDMETHODIMP OPCGroup::ShutdownRequest(LPCWSTR szReason) {
    if (error) {
        ERROR_LOG("OPC connection in error state. cannot accept further requests");
        return E_FAIL;
    }
    ERROR_LOG("not yet implemented");
    return S_OK;
}
