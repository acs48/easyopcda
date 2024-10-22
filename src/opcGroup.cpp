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


#include "easyopcda/opcGroup.h"
#include "easyopcda/utility.h"
#include <easyopcda/opcda.h>

#include <string>
#include <iostream>
#include <locale>
#include <utility>

OPCGroup::OPCGroup(std::wstring name, CComPtr<IOPCServer> &pOPCServer, COAUTHIDENTITY *pAuthIdent, DWORD reqUpdRate, ASyncCallback func) {
    std::wstringstream wss;

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
        VERBOSE_PRINT(L"invalid OPC server" << std::endl);
        messageString = L"invalid OPC server";
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

    VERBOSE_PRINT(L"Thread building OPC group: " << std::this_thread::get_id() << std::endl);

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
        VERBOSE_PRINT(L"function AddGroup of OPCServer instance failed. Error: " << hresultTowstring(hr) << std::endl);
        wss << L"function AddGroup of OPCServer instance failed. Error: " << hresultTowstring(hr) << std::endl;
        messageString = wss.str();
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
        VERBOSE_PRINT(L"CoSetProxyBlanket failed on the IOPCGroupStateMgt with error " << hresultTowstring(hrAuth) << std::endl);
        wss << L"CoSetProxyBlanket failed on the IOPCGroupStateMgt with error " << hresultTowstring(hrAuth) << std::endl;
        messageString = wss.str();
        //return;
    }


    hr = groupMgr->QueryInterface(IID_IOPCItemMgt, (void **) &itemMgr);
    if (FAILED(hr)) {
        itemMgr = nullptr;
        error = true;
        VERBOSE_PRINT(L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCItemMgt. Error: " << hresultTowstring(hr) << std::endl);
        wss << L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCItemMgt. Error: " << hresultTowstring(hr) << std::endl;
        messageString = wss.str();
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
            VERBOSE_PRINT(L"CoSetProxyBlanket failed on the IOPCItemMgt with error " << hresultTowstring(hrAuth) << std::endl);
            wss << L"CoSetProxyBlanket failed on the IOPCItemMgt with error " << hresultTowstring(hrAuth) << std::endl;
            messageString = wss.str();
            //return;
        }
    }

    hr = groupMgr->QueryInterface(IID_IOPCSyncIO, (void **) &syncIO);
    if (FAILED(hr)) {
        syncIO = nullptr;
        VERBOSE_PRINT(L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCSyncIO. Error: "<< hresultTowstring(hr) << std::endl);
        wss << L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCSyncIO. Error: "<< hresultTowstring(hr) << std::endl;
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
            VERBOSE_PRINT(L"CoSetProxyBlanket failed on the IOPCSyncIO with error " << hresultTowstring(hrAuth) << std::endl);
            wss << L"CoSetProxyBlanket failed on the IOPCSyncIO with error " << hresultTowstring(hrAuth) << std::endl;
            messageString = wss.str();
            //return;
        }
    }


    hr = groupMgr->QueryInterface(IID_IOPCSyncIO2, (void **) &syncIO2);
    if (FAILED(hr)) {
        syncIO2 = nullptr;
        wss << L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCSyncIO2. Error: " << hresultTowstring(hr) << std::endl;
        VERBOSE_PRINT(L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCSyncIO2. Error: " << hresultTowstring(hr) << std::endl);
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
            VERBOSE_PRINT(L"CoSetProxyBlanket failed on the IOPCSyncIO2 with error " << hresultTowstring(hrAuth) << std::endl);
            wss << L"CoSetProxyBlanket failed on the IOPCSyncIO2 with error " << hresultTowstring(hrAuth) << std::endl;
            messageString = wss.str();
            //return;
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
            VERBOSE_PRINT(L"CoSetProxyBlanket failed on the IOPCAsyncIO with error " << hresultTowstring(hrAuth) <<std::endl);
            wss << L"CoSetProxyBlanket failed on the IOPCAsyncIO with error " << hresultTowstring(hrAuth) << std::endl;
            messageString = wss.str();
            //return;
        }
    } else {
        asyncIO = nullptr;
        VERBOSE_PRINT(L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCAsyncIO. Error: " << hresultTowstring(hr1) << std::endl);
        wss <<  L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCAsyncIO. Error: " << hresultTowstring(hr1) << std::endl;
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
            VERBOSE_PRINT(L"CoSetProxyBlanket failed on the IOPCAsyncIO2 with error " << hresultTowstring(hrAuth) << std::endl);
            wss << L"CoSetProxyBlanket failed on the IOPCAsyncIO2 with error " << hresultTowstring(hrAuth) << std::endl;
            messageString = wss.str();
            //return;
        }
    } else {
        asyncIO2 = nullptr;
        VERBOSE_PRINT(L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCAsyncIO2. Error: " << hresultTowstring(hr2) << std::endl);
        wss << L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCAsyncIO2. Error: " << hresultTowstring(hr2) << std::endl;
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
            VERBOSE_PRINT(L"CoSetProxyBlanket failed on the IOPCAsyncIO3 with error " << hresultTowstring(hrAuth) << std::endl);
            wss << L"CoSetProxyBlanket failed on the IOPCAsyncIO3 with error " << hresultTowstring(hrAuth) << std::endl;
            messageString = wss.str();
            //return;
        }
    } else {
        asyncIO3 = nullptr;
        VERBOSE_PRINT(L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCAsyncIO3. Error: " << hresultTowstring(hr3) << std::endl);
        wss << L"QueryInterFace on instance of IID_IOPCGroupStateMgt could not retrieve instance of IID_IOPCAsyncIO3. Error: " << hresultTowstring(hr3) << std::endl;
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
                VERBOSE_PRINT(L"CoSetProxyBlanket failed on the IConnectionPointContainer with error " << hresultTowstring(hrAuth) << std::endl);
                wss << L"CoSetProxyBlanket failed on the IConnectionPointContainer with error " << hresultTowstring(hrAuth) << std::endl;
                messageString = wss.str();
                //return;
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
                    VERBOSE_PRINT(L"CoSetProxyBlanket failed on the IConnectionPoint with error " << hresultTowstring(hrAuth) << std::endl);
                    wss << L"CoSetProxyBlanket failed on the IConnectionPoint with error " << hresultTowstring(hrAuth) << std::endl;
                    messageString = wss.str();
                    //return;
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
                    VERBOSE_PRINT(L"Failed to retrieve handle of IOPCDataCallback from class IID_IOPCDataCallback. Cannot implement async read/write connection. Error: " << hresultTowstring(result) << std::endl);
                    wss << L"Failed to retrieve handle of IOPCDataCallback from class IID_IOPCDataCallback. Cannot implement async read/write connection. Error: " << hresultTowstring(result) << std::endl;
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
                VERBOSE_PRINT(L"Failed to retrieve interface pointer IID_IOPCDataCallback from class IID_IConnectionPointContainer. Cannot implement async read/write connection. Error: " << hresultTowstring(result) << std::endl);
                wss << L"Failed to retrieve interface pointer IID_IOPCDataCallback from class IID_IConnectionPointContainer. Cannot implement async read/write connection. Error: " << hresultTowstring(result) << std::endl;
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
                    VERBOSE_PRINT(L"CoSetProxyBlanket failed on the IConnectionPoint with error " << hresultTowstring(hrAuth) << std::endl);
                    wss << L"CoSetProxyBlanket failed on the IConnectionPoint with error " << hresultTowstring(hrAuth) << std::endl;
                    messageString = wss.str();
                    //return;
                }

                result = shutdownConnectionPoint->Advise((IUnknown *) ((IOPCShutdown *) this), &shutdownHandle);
                if (FAILED(result)) {
                    shutdownConnectionPoint = nullptr;
                    shutdownHandle = 0;
                    VERBOSE_PRINT(L"Failed to retrieve handle of IOPCShutdown from class IID_IOPCShutdown. Cannot implement async shutdown connection. Error: " << hresultTowstring(result) << std::endl);
                    wss << L"Failed to retrieve handle of IOPCShutdown from class IID_IOPCShutdown. Cannot implement async shutdown connection. Error: " << hresultTowstring(result) << std::endl;
                }
            } else {
                asyncDataCallbackConnectionPoint = nullptr;
                shutdownConnectionPoint = nullptr;
                VERBOSE_PRINT(L"Failed to retrieve interface pointer IID_IOPCShutdown from class IID_IConnectionPointContainer. Cannot implement async shutdown connection. Error: " << hresultTowstring(result) << std::endl);
                wss << L"Failed to retrieve interface pointer IID_IOPCShutdown from class IID_IConnectionPointContainer. Cannot implement async shutdown connection. Error: " << hresultTowstring(result) << std::endl;
            }
        }
    }
    messageString = wss.str();
}


OPCGroup::~OPCGroup() {
    asyncDisableAutoReadGroup();

    auto copyIDs = clientServerTransactionID;

    for (auto i = copyIDs.begin(); i != copyIDs.end(); ++i) {
        HRESULT hr;
        if (asyncIO3) {
            hr = asyncIO3->Cancel2(i->second);
            if FAILED(hr) {
                error = true;
                VERBOSE_PRINT( L"Call to asyncIO3->Cancel2 returned error: " << hresultTowstring(hr) << std::endl);
            }
        } else if (asyncIO2) {
            hr = asyncIO2->Cancel2(i->second);
            if FAILED(hr) {
                error = true;
                VERBOSE_PRINT(L"Call to asyncIO2->Read returned error: " << hresultTowstring(hr) << std::endl);
            }
        } else {
            VERBOSE_PRINT(L"No async interfaces available (support only IID_IOPCAsyncIO2 and IID_IOPCAsyncIO3" << std::endl);
            return;
        }
    }

    if (myOPCServer) {
        HRESULT hr = myOPCServer->RemoveGroup(thisGroupHandle,TRUE);
        if FAILED(hr) {
            VERBOSE_PRINT(L"Call to IOPCSerer->RemoveGroup failed with error " << hresultTowstring(hr) << std::endl);
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
    std::wstringstream wss;
    if (error) {
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        messageString = L"OPC connection in error state. cannot accept further requests";
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

    VERBOSE_PRINT(L"Thread adding OPC items: " << std::this_thread::get_id() << std::endl);

    hr = itemMgr->AddItems(itemDefs.size(), itemDefs.data(), &pAddResult, &pErrors);
    if SUCCEEDED(hr) {
        for (size_t i = 0; i < itemDefs.size(); i++) {
            wss << L"Requested tag: " << itemNames[i] << " returned status: " << hresultTowstring(pErrors[i]) << std::endl;
            VERBOSE_PRINT(L"Requested tag: " << itemNames[i] << " returned status: " << hresultTowstring(pErrors[i]) << std::endl);
            itemsMap[itemNames[i]].itemRes = pAddResult[i];
            itemsMap[itemNames[i]].itemErr = pErrors[i];
            serverItemHandlesMap[pAddResult[i].hServer] = itemNames[i];
        }
    } else {
        error = true;
        VERBOSE_PRINT(L"Call to AddItems returned error: " << hresultTowstring(hr) << std::endl);
        wss << L"Call to AddItems returned error: " << hresultTowstring(hr) << std::endl;
    }

    if (pAddResult) CoTaskMemFree(pAddResult);
    if (pErrors) CoTaskMemFree(pErrors);

    messageString = wss.str();
}

void OPCGroup::validateItems(std::vector<std::wstring> &inputItems) {
    std::wstringstream wss;
    if (error) {
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        messageString = L"OPC connection in error state. cannot accept further requests";
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
            wss << L"Requested tag: " << itemNames[i] << " returned status: " << hresultTowstring(pErrors[i]) << std::endl;
            VERBOSE_PRINT(L"Requested tag: " << itemNames[i] << " returned status: " << hresultTowstring(pErrors[i]) << std::endl);
            if (itemsMap.count(itemNames[i]) > 0) {
                itemsMap[itemNames[i]].itemErr = pErrors[i];
            }
        }
    } else {
        error = true;
        VERBOSE_PRINT(L"Call to ValidateItems returned error: " << hresultTowstring(hr) << std::endl);
        wss << L"Call to ValidateItems returned error: " << hresultTowstring(hr) << std::endl;
    }

    if (pAddResult) {
        for (size_t i = 0; i < itemDefs.size(); i++) {
            if (pAddResult[i].pBlob) CoTaskMemFree(pAddResult[i].pBlob);
        }
        CoTaskMemFree(pAddResult);
    }
    if (pErrors) CoTaskMemFree(pErrors);

    messageString = wss.str();
}

void OPCGroup::removeItems(std::vector<std::wstring> &items) {
    if (error) {
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        messageString = L"OPC connection in error state. cannot accept further requests";
        return;
    }

    VERBOSE_PRINT(L"not yet implemented" << std::endl);
    messageString = L"not yet implemented";
}

void OPCGroup::syncReadGroup() {
    std::wstringstream wss;
    if (error) {
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        messageString = L"OPC connection in error state. cannot accept further requests";
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

    VERBOSE_PRINT(L"Thread sync reading group: " << std::this_thread::get_id() << std::endl);

    HRESULT hr;
    if (syncIO2) {
        hr = syncIO2->Read(OPC_DS_CACHE, itemHandles.size(), itemHandles.data(), &pItemValues, &pErrors);
        // we can use ReadMaxAge here, try
    } else if (syncIO) {
        hr = syncIO->Read(OPC_DS_CACHE, itemHandles.size(), itemHandles.data(), &pItemValues, &pErrors);
    } else {
        VERBOSE_PRINT(L"No sync read interfaces available! operation not performed" << std::endl);
        messageString = L"No sync read interfaces available! operation not performed";
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
        wss << L"Sync Read processed " << itemHandles.size() << L" items" << std::endl;
        VERBOSE_PRINT(L"Sync Read processed " << itemHandles.size() << L" items" << std::endl);
        internalAsyncCallback(itemHandles.size(),clientHandles.data(), VARIANTValues.data(), qualityValues.data(),timeValues.data(),errors.data());

        for (auto i = 0; i < itemHandles.size(); i++) {
            if FAILED(pErrors[i]) {
                if (clientItemHandlesMap.count(pItemValues[i].hClient)>0)
                    wss << L"Call to SyncIO returned error for specific item: " << clientItemHandlesMap[pItemValues[i].hClient] << L":" << hresultTowstring(hr) << std::endl;
            } else {
                if (clientItemHandlesMap.count(pItemValues[i].hClient)>0)
                    wss << outputVariant(clientItemHandlesMap[pItemValues[i].hClient], pItemValues[i].vDataValue, pItemValues[i].ftTimeStamp,pItemValues[i].wQuality) << std::endl;
            }
        }
    } else {
        error = true;
        VERBOSE_PRINT(L"Call to SyncIO returned error: " << hresultTowstring(hr) << std::endl);
        wss << L"Call to SyncIO returned error: " << hresultTowstring(hr) << std::endl;
    }


    if (pItemValues != NULL) {
        for (auto i = 0; i < itemHandles.size(); i++) {
            hr = VariantClear(&(pItemValues[i].vDataValue));
            if FAILED(hr) {
                error = true;
                VERBOSE_PRINT(L"Call to VariantClear returned error: " << hresultTowstring(hr) << std::endl);
                wss << L"Call to VariantClear returned error: " << hresultTowstring(hr) << std::endl;
            }
        }
        CoTaskMemFree(pItemValues);
    }
    if (pErrors != NULL) CoTaskMemFree(pErrors);
    wss<<L"Sync Read completed and data published" << std::endl;
    messageString = wss.str();
}

void OPCGroup::asyncReadGroup() {
    std::wstringstream wss;
    if (error) {
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        messageString = L"OPC connection in error state. cannot accept further requests";
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
    while (clientServerTransactionID.count(++lastClientTransactionID) != 0);

    VERBOSE_PRINT(L"Thread async reading group: " << std::this_thread::get_id() << std::endl);

    if (asyncIO3) {
        hr = asyncIO3->Read(itemHandles.size(), itemHandles.data(), lastClientTransactionID, &serverCancelID, &pErrors);
        if FAILED(hr) {
            error = true;
            VERBOSE_PRINT(L"Call to asyncIO3->Read returned error: " << hresultTowstring(hr) << std::endl);
            wss << L"Call to asyncIO3->Read returned error: " << hresultTowstring(hr) << std::endl;
            messageString = wss.str();
            return;
        }
    } else if (asyncIO2) {
        hr = asyncIO2->Read(itemHandles.size(), itemHandles.data(), lastClientTransactionID, &serverCancelID, &pErrors);
        if FAILED(hr) {
            error = true;
            VERBOSE_PRINT(L"Call to asyncIO2->Read returned error: " << hresultTowstring(hr) << std::endl);
            wss << L"Call to asyncIO2->Read returned error: " << hresultTowstring(hr) << std::endl;
            messageString = wss.str();
            return;
        }
    } else {
        VERBOSE_PRINT(L"No async interfaces available (support only IID_IOPCAsyncIO2 and IID_IOPCAsyncIO3" << std::endl);
        wss << L"No async interfaces available (support only IID_IOPCAsyncIO2 and IID_IOPCAsyncIO3" << std::endl;
        messageString = wss.str();
        return;
    }

    clientServerTransactionID[lastClientTransactionID] = serverCancelID;

    if (!error) {
        if (pErrors) {
            for (auto i = 0; i < itemHandles.size(); i++) {
                wss << L"Async Read requested tag: " << itemNames[i] << L" returned status: " << hresultTowstring(pErrors[i]) << std::endl;
            }
        }
    }

    if (pErrors != NULL) CoTaskMemFree(pErrors);
    messageString = wss.str();
}

void OPCGroup::syncReadItems(std::vector<std::wstring> &items) {
    if (error) {
        messageString = L"OPC connection in error state. cannot accept further requests";
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        return;
    }
    VERBOSE_PRINT(L"not yet implemented" << std::endl);
    messageString = L"not yet implemented";
}

void OPCGroup::syncWriteItems(std::vector<std::wstring> &items, std::vector<double> values) {
    if (error) {
        messageString = L"OPC connection in error state. cannot accept further requests";
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        return;
    }
    VERBOSE_PRINT(L"not yet implemented" << std::endl);
    messageString = L"not yet implemented";
}

// implementation of DCOM interfaces
STDMETHODIMP OPCGroup::QueryInterface(REFIID iid, LPVOID *ppInterface) {
    VERBOSE_PRINT(L"Queryinterface called on OPCGroup" << std::endl);
    VERBOSE_PRINT(L"Thread running QueryInterface: " << std::this_thread::get_id() << std::endl);

    if (!ppInterface) {
        return E_POINTER;
    }

    VERBOSE_PRINT(L"Requested iid: " << GUIDToString(iid) << std::endl);
    VERBOSE_PRINT(L"IID_IUnknown: " << GUIDToString(IID_IUnknown) << std::endl);
    VERBOSE_PRINT(L"IID_IOPCDataCallback: " << GUIDToString(IID_IOPCDataCallback) << std::endl);
    VERBOSE_PRINT(L"IID_IOPCShutdown: " << GUIDToString(IID_IOPCShutdown) << std::endl);

    if (iid == IID_IUnknown) {
        VERBOSE_PRINT(L"Queryinterface is passing IUnknown" << std::endl);
        *ppInterface = (IUnknown*)((IOPCDataCallback*)this);
    } else if (iid == IID_IOPCDataCallback) {
        VERBOSE_PRINT(L"Queryinterface is passing IOPCDataCallback" << std::endl);
        *ppInterface = (IOPCDataCallback*)this;
    } else if (iid == IID_IOPCShutdown) {
        VERBOSE_PRINT(L"Queryinterface is passing IOPCShutdown" << std::endl);
        *ppInterface = (IOPCShutdown*)this;
    } else {
        VERBOSE_PRINT(L"Queryinterface is passing null" << std::endl);
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
            externalAsyncCallback(myName, {itemName, time[i], values[i], quality[i], error});
            //std::wcout << outputVariant(itemName, values[i], time[i], quality[i]) << std::endl;
        } else {
            VERBOSE_PRINT(L"Invalid client item handle passed to async callback function" << std::endl);
            messageString = L"Invalid client item handle passed to async callback function";
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
        VERBOSE_PRINT("OPC connection in error state. cannot accept further requests" << std::endl);
        messageString = L"OPC connection in error state. cannot accept further requests";
        return E_FAIL;
    }
    if (clientServerTransactionID.count(transactionID) > 0) {
        clientServerTransactionID.erase(transactionID);
    }

    VERBOSE_PRINT(L"Thread running OnDataChange: " << std::this_thread::get_id() << std::endl);

    return internalAsyncCallback(count, clientHandles, values, quality, time, errors);
}

STDMETHODIMP OPCGroup::OnReadComplete(DWORD transactionID, OPCHANDLE groupHandle, HRESULT masterQuality,
                                      HRESULT masterError,
                                      DWORD count, OPCHANDLE *clientHandles, VARIANT *values, WORD *quality,
                                      FILETIME *time, HRESULT *errors) {
    if (isError()) {
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        messageString = L"OPC connection in error state. cannot accept further requests";
        return E_FAIL;
    }
    if (clientServerTransactionID.count(transactionID) > 0) {
        clientServerTransactionID.erase(transactionID);
    }

    VERBOSE_PRINT(L"Thread running OnReadComplete " << std::this_thread::get_id() << std::endl);

    return internalAsyncCallback(count, clientHandles, values, quality, time, errors);
}

STDMETHODIMP OPCGroup::OnWriteComplete(DWORD transactionID, OPCHANDLE groupHandle, HRESULT masterError, DWORD count, OPCHANDLE *clientHandles, HRESULT *errors) {
    if (error) {
        messageString = L"OPC connection in error state. cannot accept further requests";
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        return E_FAIL;
    }
    VERBOSE_PRINT(L"not yet implemented" << std::endl);
    messageString = L"not yet implemented";
    return S_OK;
}

STDMETHODIMP OPCGroup::OnCancelComplete(DWORD transactionID, OPCHANDLE groupHandle) {
    if (isError()) {
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        messageString = L"OPC connection in error state. cannot accept further requests";
        return E_FAIL;
    }
    if (clientServerTransactionID.count(transactionID) > 0) {
        clientServerTransactionID.erase(transactionID);
    }
    return S_OK;
}

void OPCGroup::asyncEnableAutoReadGroup() {
    std::wstringstream wss;
    if (error) {
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        messageString = L"OPC connection in error state. cannot accept further requests";
        return;
    }

    VERBOSE_PRINT(L"Thread setting group and items activee: " << std::this_thread::get_id() << std::endl);

    if (groupMgr) {
        DWORD rUpRt;
        BOOL active = FALSE;
        HRESULT hr = groupMgr->SetState(nullptr, &rUpRt, &active, nullptr, nullptr, nullptr, nullptr);
        if FAILED(hr) {
            error = true;
            messageString = L"Call to IOPCGroup->SetState failed";
            VERBOSE_PRINT(L"Call to IOPCGroup->SetState failed" << std::endl);
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
                messageString = L"Call to IOPCItem->SetActiveState failed";
                VERBOSE_PRINT(L"Call to IOPCItem->SetActiveState failed" << std::endl);
                return;
            }
        }
        hr = groupMgr->SetState(nullptr, &rUpRt, &active, nullptr, nullptr, nullptr, nullptr);
        if FAILED(hr) {
            error = true;
            messageString = L"Call to IOPCItem->SetState failed";
            VERBOSE_PRINT(L"Call to IOPCGroup->SetState failed" << std::endl);
            return;
        }
    }
    messageString = L"auto read successfully activated";
    VERBOSE_PRINT(L"auto read successfully activated" << std::endl);

}

void OPCGroup::asyncDisableAutoReadGroup() {
    if (error) {
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        messageString = L"OPC connection in error state. cannot accept further requests";
        return;
    }

    VERBOSE_PRINT(L"Thread setting group and items inactivee: " << std::this_thread::get_id() << std::endl);

    if (groupMgr) {
        DWORD rUpRt;
        BOOL active = FALSE;
        HRESULT hr = groupMgr->SetState(nullptr, &rUpRt, &active, nullptr, nullptr, nullptr, nullptr);
        if FAILED(hr) {
            error = true;
            messageString = L"Call to IOPCItem->SetState failed";
            VERBOSE_PRINT(L"Call to IOPCItem->SetState failed" << std::endl);
            return;
        }
    }
    messageString = L"auto read successfully deactivated";
    VERBOSE_PRINT(L"auto read successfully deactivated" << std::endl);
}

STDMETHODIMP OPCGroup::ShutdownRequest(LPCWSTR szReason) {
    if (error) {
        messageString = L"OPC connection in error state. cannot accept further requests";
        VERBOSE_PRINT(L"OPC connection in error state. cannot accept further requests" << std::endl);
        return E_FAIL;
    }
    VERBOSE_PRINT(L"not yet implemented" << std::endl);
    messageString = L"not yet implemented";
    return S_OK;
}
