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

#ifndef OPC_CLIENT_H
#define OPC_CLIENT_H

#include <atlbase.h>

#include "easyopcda.h"
#include "opcda.h"
#include "opcgroup.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/ostream_sink.h"

#include <string>
#include <map>


class OPCClient
{
private:
    bool error;
    //std::stringstream ss;
    //std::shared_ptr<spdlog::sinks::ostream_sink_mt> ss_sink;
    //std::shared_ptr<spdlog::logger> logger;

    std::wstring hostName;
    std::wstring domain;
    std::wstring user;
    std::wstring password;

    COSERVERINFO serverInfo;
    COAUTHINFO authInfo;
    COAUTHIDENTITY authIdent;
    bool identitySet;

    std::map<std::wstring, CLSID> progIDtoCLSIDMap;

    std::wstring serverProgID;
    CLSID serverCLSID;

    CComPtr<IOPCServer> pOPCServer;

    std::map<std::wstring, OPCGroup*> groups;

    easyopcda::ASyncCallback mCallbackFunc;

public:
    explicit OPCClient(easyopcda::ASyncCallback func);
    ~OPCClient();

    void setOPCServerHostAndUser(std::wstring hostName,const std::wstring& domain, const std::wstring& user, const std::wstring& password);
    bool listDAServers(const std::wstring &spec);
    bool connectToOPCByProgID(const std::wstring &progID);
    void connectToOPCByClsid(const CLSID &clsid);
    OPCGroup* addGroup(std::wstring, DWORD);
    OPCGroup* getGroup(const std::wstring&);
    void removeGroup(std::wstring);

    bool isError() const {return error;}
    /*
    std::string getLogs() {
        auto rv = ss.str();
        ss.clear();
        return rv;
    }
    void setLogLevel(spdlog::level::level_enum level) { logger->set_level(level); }
    */
};

#endif //OPC_CLIENT_H