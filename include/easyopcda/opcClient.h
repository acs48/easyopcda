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

#ifndef OPC_CLIENT_H
#define OPC_CLIENT_H

#include <atlbase.h>

#include "opcda.h"
#include "opcGroup.h"
#include "utility.h"

#include <string>
#include <map>


class OPCClient
{
private:
    bool error;
    std::wstring messageString;

    std::wstring hostName;
    std::wstring domain;
    std::wstring user;
    std::wstring password;

    COSERVERINFO serverInfo;
    COAUTHINFO authInfo;
    COAUTHIDENTITY authIdent;
    bool identitySet;

    std::map<std::wstring, CLSID> progIDtoCLSIDmap;

    std::wstring serverProgID;
    CLSID serverclsid;

    CComPtr<IOPCServer> pOPCServer;

    std::map<std::wstring, OPCGroup*> groups;

    ASyncCallback mCallbackFunc;

public:
    explicit OPCClient(ASyncCallback func);
    ~OPCClient();

    void setOPCServerHostAndUser(std::wstring hostName,std::wstring domain, std::wstring user, std::wstring password);
    bool listDAServers(std::wstring spec);
    bool connectToOPCByProgID(std::wstring progID);
    void connectToOPCByClsid(CLSID clsid);
    OPCGroup* addGroup(std::wstring, DWORD);
    OPCGroup* getGroup(std::wstring);
    void removeGroup(std::wstring);

    bool isError() {return error;}
    std::wstring lastMessage() {
        if(messageString.size()>10000) messageString.resize(10000);
        return messageString;
    }


};

#endif //OPC_CLIENT_H