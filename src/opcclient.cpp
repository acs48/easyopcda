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
#include "easyopcda/opcclient.h"
#include <easyopcda/opccomn.h>

#include "spdlog/spdlog.h"

#include <locale>
#include <string>
#include <map>

#include <atlbase.h>


OPCClient::OPCClient(easyopcda::ASyncCallback func)
//: ss_sink(std::make_shared<spdlog::sinks::ostream_sink_mt>(ss)),
//  logger(std::make_shared<spdlog::logger>("easyopcda", ss_sink))
{
    error=false;
    pOPCServer=nullptr;
    identitySet = false;
    mCallbackFunc = std::move(func);
}

OPCClient::~OPCClient() {
    for(auto i=groups.begin();i!=groups.end();++i) {
        delete i->second;
    }
}

void OPCClient::setOPCServerHostAndUser(std::wstring hostName, const std::wstring& domain, const std::wstring& user, const std::wstring &password) {
    if (error) {
        ERROR_LOG("Client in error state cannot further process requests");
        return;
    }
    if (hostName.empty()) {
        hostName = L"localhost";
    }
    this->hostName = hostName;
    INFO_LOG("Host name: >>>{}<<<", wstringToUTF8(hostName));

    ZeroMemory(&authInfo, sizeof(COAUTHINFO));
    ZeroMemory(&authIdent, sizeof(COAUTHIDENTITY));

    serverInfo.dwReserved1 = 0;
    serverInfo.pwszName = &this->hostName[0];
    serverInfo.dwReserved2 = 0;
    serverInfo.pAuthInfo = nullptr;

    authInfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
    authInfo.dwAuthzSvc = RPC_C_AUTHZ_NONE;
    authInfo.pwszServerPrincName = nullptr;
    authInfo.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_INTEGRITY;
    authInfo.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
    authInfo.dwCapabilities = EOAC_NONE;
    authInfo.pAuthIdentityData = nullptr;

    INFO_LOG("Domain name: >>>{}<<<",wstringToUTF8(domain));
    INFO_LOG("User name: >>>{}<<<", wstringToUTF8(user));
    INFO_LOG("Password: >>>{}<<<", wstringToUTF8(password));

    this->domain=domain;
    this->user=user;
    this->password=password;

    if (!this->user.empty()) {
        identitySet = true;
        // Set up the COAUTHIDENTITY structure
        authIdent.User = CopyWStringToAuthIdentity(this->user);
        authIdent.UserLength = (ULONG)this->user.length();
        authIdent.Password = CopyWStringToAuthIdentity(this->password);
        authIdent.PasswordLength = (ULONG)this->password.length();
        authIdent.Domain = CopyWStringToAuthIdentity(this->domain);
        authIdent.DomainLength = (ULONG)this->domain.length();
        authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

        authInfo.pAuthIdentityData = &authIdent;

        serverInfo.pAuthInfo = &authInfo;
    }
}


bool OPCClient::listDAServers(const std::wstring &spec) {
    if (error) {
        ERROR_LOG("Client in error state cannot further process requests");
        return false;
    }

    CATID requiredDASpec;

    DEBUG_LOG("Required DA specification: {}",wstringToUTF8(spec));
    
    if (spec==L"10") requiredDASpec=CATID_OPCDAServer10;
    else if (spec==L"20") requiredDASpec=CATID_OPCDAServer20;
    else if (spec==L"30") requiredDASpec=CATID_OPCDAServer30;
    else {
        ERROR_LOG("Invalid DA specification: >>>{}<<<",wstringToUTF8(spec));
        return false;
    }

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Thread listing OPC servers: {}", hid);

    ATL::CComPtr<IOPCServerList> iCatInfo;
    HRESULT hr = OPCServerListCreateInstance(&serverInfo, identitySet?&authIdent:nullptr, this->hostName==L"localhost",iCatInfo);
    if (SUCCEEDED(hr)) {
        CATID Implist[1];
        Implist[0] = requiredDASpec; // CATID for OPC DA servers. Use appropriate CATID for other types of servers

        ATL::CComPtr<IEnumCLSID> iEnum;
        hr = iCatInfo->EnumClassesOfCategories(1, Implist, 0, nullptr, &iEnum);
        if (SUCCEEDED(hr)) {
            HRESULT hrAuth = CoSetProxyBlanket(
                iEnum, // the proxy to set
                RPC_C_AUTHN_WINNT, // authentication service
                RPC_C_AUTHZ_NONE, // authorization service
                NULL, // server principal name
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // authentication level
                RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
                identitySet?&authIdent:nullptr, // authentication information
                EOAC_NONE // additional capabilities
            );
            if (FAILED(hrAuth)) {
                ERROR_LOG("CoSetProxyBlanket failed on the ICatInformation with error = {}", hresultToUTF8(hrAuth));
            }

            ULONG cActual;
            CLSID clsid;
            while(iEnum->Next(1, &clsid, &cActual) == S_OK)
            {
                LPOLESTR progID = nullptr;
                LPOLESTR userType = nullptr;
                HRESULT result = iCatInfo->GetClassDetails(clsid, &progID, &userType);
                if (SUCCEEDED(result)){
                    INFO_LOG("Discovered server >>>{}<<< {} CLSID >>>{}<<<", wstringToUTF8(progID), wstringToUTF8(userType), GUIDToUTF8(clsid));
                    progIDtoCLSIDMap[progID] = clsid;
                }
                if(progID) CoTaskMemFree(progID); // Release the memory allocated
                if(userType) CoTaskMemFree(userType); // Release the memory allocated

                // Release the enumerator
                // iEnum->Release(); not necessary because of use of ccomptr
            }
            // Release the pServerList
            //iCatInfo->Release(); not necessary because of ccomptr usage
        } else {
            ERROR_LOG("EnumClassesOfCategories failed to enum classes of type CATID_OPCDAServer20 from instance of interface IID_IOPCServerList with error = {}", hresultToUTF8(hr));
            return false;
        }
    } else {
        ERROR_LOG("CoCreateInstanceEx failed to get instance of interface IID_IOPCServerList from class CLSID_OpcServerList on the {} server with error = {}",  wstringToUTF8(this->hostName), hresultToUTF8(hr));
        return false;
    }

    return true;
}


bool OPCClient::connectToOPCByProgID(const std::wstring &progID) {
    if (error) {
        ERROR_LOG("Client in error state cannot further process requests");
        return false;
    }

    serverProgID=progID;
    INFO_LOG("ProgID for connection: >>>{}<<<", wstringToUTF8(serverProgID));

    if (serverProgID.empty()) {
        WARN_LOG("Invalid progID requested: {}", wstringToUTF8(serverProgID));
        return false;
    }

    if (progIDtoCLSIDMap.count(serverProgID)==0) {
        WARN_LOG("Requested progID {} could not be found; attempting to look for clsid again", wstringToUTF8(serverProgID));
        CLSID sClsid;
        HRESULT hrGetProcID = CLSIDFromProgID ( serverProgID.c_str(), &sClsid );
        if FAILED(hrGetProcID) {
            ERROR_LOG("Requested progID could not be found");
            return false;
        }
        serverCLSID = sClsid;
    } else {
        serverCLSID = progIDtoCLSIDMap[serverProgID];
    }

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Thread connecting to OPC server: {}", hid);

    HRESULT hrOPCServerInstance = OPCServerCreateInstance(&serverInfo,identitySet?&authIdent:nullptr,hostName==L"localhost",serverCLSID,pOPCServer);
    if FAILED(hrOPCServerInstance) {
        ERROR_LOG("CoCreateInstanceEx could not create instance of interface IID_OPCServer from requested class");
        error=true;
        return false;
    }

    INFO_LOG("OPC connected");
    return true;
}


void OPCClient::connectToOPCByClsid(const CLSID &clsid) {
    if (error) {
        ERROR_LOG("Client in error state cannot further process requests");
        return;
    }

    serverCLSID=clsid;
    INFO_LOG("clsid for connection: >>>{}<<<", GUIDToUTF8(clsid));

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Thread connecting to OPC server: {}",hid);

    HRESULT hrOPCServerInstance = OPCServerCreateInstance(&serverInfo,identitySet?&authIdent:nullptr,hostName==L"localhost",serverCLSID,pOPCServer);
    if FAILED(hrOPCServerInstance) {
        ERROR_LOG("CoCreateInstanceEx could not create instance of interface IID_OPCServer from requested class");
        error=true;
        return;
    }
}

OPCGroup* OPCClient::addGroup(std::wstring name, DWORD requestedUpdateRate) {
    if (error) {
        ERROR_LOG("Client in error state cannot further process requests");
        return nullptr;
    }
    
    if (name.empty()) {
        ERROR_LOG("Invalid group name");
        return nullptr;
    }

    INFO_LOG("Group name: >>>{}<<< Update rate: >>>{}<<<", wstringToUTF8(name), requestedUpdateRate);

    if(groups.count(name)>0) {
        WARN_LOG("Group with this name already exists. Skipping...");
        return nullptr;
    } else {
        groups[name] = new OPCGroup(name,pOPCServer,identitySet?&authIdent:nullptr,requestedUpdateRate,mCallbackFunc);
        INFO_LOG("Group {} created", wstringToUTF8(name));
    }

    return groups[name];
}

OPCGroup* OPCClient::getGroup(const std::wstring& name) {
    if (error) {
        ERROR_LOG("Client in error state cannot further process requests");
        return nullptr;
    }

    if (groups.count(name) == 0) {
        ERROR_LOG("Invalid group name");
        return nullptr;
    }

    return groups[name];
}


void OPCClient::removeGroup(std::wstring name) {
    if (error) {
        ERROR_LOG("Client in error state cannot further process requests");
        return;
    }

    if (groups.count(name) == 0) {
        ERROR_LOG("Invalid group name");
        return;
    }

    delete groups[name];
    groups.erase(name);

    INFO_LOG("Group {} deleted",wstringToUTF8(name));
}
