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

#ifndef OPCINIT_H
#define OPCINIT_H

#include "easyopcda.h"
#include "OPCClient.h"

void listDA20Servers(COSERVERINFO *serverInfo, bool localhost, std::map<std::wstring, CLSID> &progidClsidMap);

class OPCInit
{
private:
    bool error;
    std::wstring messageString;

    OPCClient * mClient;
    ASyncCallback mCallbackFunc;
public:
    OPCInit(bool multiThreaded, ASyncCallback func);
    ~OPCInit();

    bool isError() {return error;}
    std::wstring lastMessage() {
        if(messageString.size()>10000) messageString.resize(10000);
        return messageString;
    }

    OPCClient* getClient();
};


#endif //OPCINIT_H
