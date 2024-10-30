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


#include "easyopcda/easyopcda.h"
#include "easyopcda/OPCClient.h"
#include <easyopcda/opccomn.h>

#include "spdlog/spdlog.h"

#include <locale>
#include <string>
#include <map>

#include <atlbase.h>



OPCClient::OPCClient(ASyncCallback func) {
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
    std::wstringstream wss;

    if (error) {
        spdlog::error("Client in error state cannot further process requests");
        wss << L"Client in error state cannot further process requests" << std::endl;
        messageString = wss.str();
        return;
    }
    if (hostName.empty()) {
        hostName = L"localhost";
    }
    this->hostName = hostName;
    spdlog::info("Host name: >>>{}<<<", wstring_to_utf8(hostName));
    wss << L"Host name: " << L">>>"<<hostName<<L"<<<"<< std::endl;


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

    wss << L"Domain name: " << ">>>"<<domain<<"<<<"<<std::endl;
    wss << L"User name: " << ">>>"<<user<<"<<<"<<std::endl;
    wss << L"Password: " << ">>>"<<password<<"<<<"<<std::endl;
    spdlog::info("Domain name: >>>{}<<<",wstring_to_utf8(domain));
    spdlog::info("User name: >>>{}<<<", wstring_to_utf8(user));
    spdlog::info("Password: >>>{}<<<", wstring_to_utf8(password));

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
    messageString = wss.str();
}


bool OPCClient::listDAServers(const std::wstring &spec) {
    std::wstringstream wss;

    if (error) {
        messageString = L"Client in error state cannot further process requests";
        spdlog::error("Client in error state cannot further process requests");
        return false;
    }

    CATID requiredDASpec;

    wss << L"Required DA specification: " << ">>>"<<spec<<"<<<"<<std::endl;
    if (spec==L"10") requiredDASpec=CATID_OPCDAServer10;
    else if (spec==L"20") requiredDASpec=CATID_OPCDAServer20;
    else if (spec==L"30") requiredDASpec=CATID_OPCDAServer30;
    else {
        wss << L"Invalid DA specification: " << ">>>"<<spec<<"<<<"<<std::endl;
        spdlog::error("Invalid DA specification: >>>{}<<<",wstring_to_utf8(spec));
        lastMessage() = wss.str();
        return false;
    }

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    spdlog::debug("Thread listing OPC servers: {}", hid);

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
                spdlog::error("CoSetProxyBlanket failed on the ICatInformation with error = {}", hresultToUTF8(hrAuth));
                wss << "CoSetProxyBlanket failed on the ICatInformation with error " << hrAuth << std::endl;
                messageString = wss.str();
                //return hrAuth;
            }

            ULONG cActual;
            CLSID clsid;
            while(iEnum->Next(1, &clsid, &cActual) == S_OK)
            {
                LPOLESTR progID = nullptr;
                LPOLESTR userType = nullptr;
                HRESULT result = iCatInfo->GetClassDetails(clsid, &progID, &userType);
                if (SUCCEEDED(result)){
                    spdlog::info("Discovered server >>>{}<<< {}", wstring_to_utf8(progID), wstring_to_utf8(userType));
                    wss << L"Discovered server " << progID << L" " << userType << std::endl;
                    progIDtoCLSIDmap[progID] = clsid;
                }
                if(progID) CoTaskMemFree(progID); // Release the memory allocated
                if(userType) CoTaskMemFree(userType); // Release the memory allocated

                // Release the enumerator
                // iEnum->Release(); not necessary because of use of ccomptr
            }
            // Release the pServerList
            //iCatInfo->Release(); not necessary because of ccomptr usage
        } else {
            wss << L"EnumClassesOfCategories failed to enum classes of type CATID_OPCDAServer20 from instance of interface IID_IOPCServerList with error " << hresultTowstring(hr) << std::endl;
            spdlog::error("EnumClassesOfCategories failed to enum classes of type CATID_OPCDAServer20 from instance of interface IID_IOPCServerList with error = {}", hresultToUTF8(hr));
            messageString = wss.str();
            return false;
        }
    } else {
        wss << L"CoCreateInstanceEx failed to get instance of interface IID_IOPCServerList from class CLSID_OpcServerList on the " << this->hostName << "server with error " << hresultTowstring(hr) << std::endl;
        spdlog::error("CoCreateInstanceEx failed to get instance of interface IID_IOPCServerList from class CLSID_OpcServerList on the {} server with error = {}",  wstring_to_utf8(this->hostName), hresultToUTF8(hr));
        messageString = wss.str();
        return false;
    }

    messageString = wss.str();
    return true;
}


bool OPCClient::connectToOPCByProgID(const std::wstring &progID) {
    std::wstringstream wss;
    if (error) {
        messageString = L"Client in error state cannot further process requests";
        spdlog::error("Client in error state cannot further process requests");
        return false;
    }

    serverProgID=progID;
    wss << L"ProgID for connection: " << ">>>"<<serverProgID<<"<<<"<<std::endl;
    spdlog::info("ProgID for connection: >>>{}<<<", wstring_to_utf8(serverProgID));

    if (serverProgID.empty()) {
        spdlog::warn("Invalid progID requested: {}", wstring_to_utf8(serverProgID));
        wss <<  L"Invalid progID requested" << std::endl;
        //error=true;
        messageString = wss.str();
        return false;
    }

    if (progIDtoCLSIDmap.count(serverProgID)==0) {
        wss << L"Requested progID could not be found; attempting to look for clsid again" << std::endl;
        spdlog::warn("Requested progID {} could not be found; attempting to look for clsid again", wstring_to_utf8(serverProgID));
        CLSID sClsid;
        HRESULT hrGetProcID = CLSIDFromProgID ( serverProgID.c_str(), &sClsid );
        if FAILED(hrGetProcID) {
            wss << L"Requested progID could not be found." << std::endl;
            spdlog::error("Requested progID could not be found");
            //error=true;
            messageString = wss.str();
            return false;
        }
        serverclsid = sClsid;
    } else {
        serverclsid = progIDtoCLSIDmap[serverProgID];
    }

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    spdlog::debug("Thread connecting to OPC server: {}", hid);

    HRESULT hrOPCServerInstance = OPCServerCreateInstance(&serverInfo,identitySet?&authIdent:nullptr,hostName==L"localhost",serverclsid,pOPCServer);
    if FAILED(hrOPCServerInstance) {
        spdlog::error("CoCreateInstanceEx could not create instance of interface IID_OPCServer from requested class");
        wss << L"CoCreateInstanceEx could not create instance of interface IID_OPCServer from requested class" << std::endl;
        error=true;
        messageString = wss.str();
        return false;
    }
    messageString = wss.str();
    return true;
}


void OPCClient::connectToOPCByClsid(const CLSID &clsid) {
    std::wstringstream wss;
    if (error) {
        messageString =  L"Client in error state cannot further process requests";
        spdlog::error("Client in error state cannot further process requests");
        return;
    }

    serverclsid=clsid;
    wss << L"clsid for connection: " << ">>>"<<GUIDToString(clsid)<<"<<<"<<std::endl;
    spdlog::info("clsid for connection: >>>{}<<<", wstring_to_utf8(GUIDToString(clsid)));

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    spdlog::debug("Thread connecting to OPC server: {}",hid);

    HRESULT hrOPCServerInstance = OPCServerCreateInstance(&serverInfo,identitySet?&authIdent:nullptr,hostName==L"localhost",serverclsid,pOPCServer);
    if FAILED(hrOPCServerInstance) {
        wss << L"CoCreateInstanceEx could not create instance of interface IID_OPCServer from requested class" << std::endl;
        spdlog::error("CoCreateInstanceEx could not create instance of interface IID_OPCServer from requested class");
        error=true;
        messageString=wss.str();
        return;
    }
    wss << L"OPC server connected"<< std::endl;
    messageString = wss.str();
}

OPCGroup* OPCClient::addGroup(std::wstring name, DWORD requestedUpdateRate) {
    std::wstringstream wss;
    if (error) {
        messageString = L"Client in error state cannot further process requests";
        spdlog::error("Client in error state cannot further process requests");
        return nullptr;
    }
    
    if (name.empty()) {
        spdlog::error("Invalid group name");
        messageString=L"Invalid group name";
        return nullptr;
    }

    wss << L"Group name: >>>" << name << L"<<<" << std::endl << L"Update rate: >>>" << requestedUpdateRate << L"<<<" << std::endl;
    spdlog::info("Group name: >>>{}<<< Update rate: >>>{}<<<", wstring_to_utf8(name), requestedUpdateRate);

    if(groups.count(name)>0) {
        wss << L"Group with this name already exists. Skipping..." << std::endl;
        spdlog::warn("Group with this name already exists. Skipping...");
        messageString = wss.str();
        return nullptr;
    } else {
        groups[name] = new OPCGroup(name,pOPCServer,identitySet?&authIdent:nullptr,requestedUpdateRate,mCallbackFunc);
        wss << L"Group created" << std::endl;
        spdlog::info("Group {} created", wstring_to_utf8(name));
    }

    messageString = wss.str();
    return groups[name];
}

OPCGroup* OPCClient::getGroup(const std::wstring& name) {
    if (error) {
        messageString = L"Client in error state cannot further process requests";
        spdlog::error("Client in error state cannot further process requests");
        return nullptr;
    }

    if (groups.count(name) == 0) {
        spdlog::error("Invalid group name");
        messageString = L"Invalid group name";
        return nullptr;
    }

    return groups[name];
}


void OPCClient::removeGroup(std::wstring name) {
    std::wstringstream wss;
    if (error) {
        messageString = L"Client in error state cannot further process requests";
        spdlog::error("Client in error state cannot further process requests");
        return;
    }

    if (groups.count(name) == 0) {
        spdlog::error("Invalid group name");
        wss << L"Invalid group name " << name;
        messageString = wss.str();
        return;
    }

    delete groups[name];
    groups.erase(name);

    wss <<  L"Group " << name << L" deleted";
    spdlog::info("Group {} deleted",wstring_to_utf8(name));
    messageString = wss.str();
}
