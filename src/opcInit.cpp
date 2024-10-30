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
#include "easyopcda/opcInit.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/ostream_sink.h"

#include <atlbase.h>

#include <sstream>
#include <utility>


OPCInit::OPCInit(bool multiThreaded, ASyncCallback func)
{
    std::wstringstream wss;
    error=false;
    mClient = nullptr;
    mCallbackFunc = std::move(func);
    wss << L"Initialization of DCOM connection." << std::endl;

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    spdlog::debug("Initializing COM on thread {}", hid);
    if (multiThreaded) {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        //COINIT_APARTMENTTHREADED
        //COINIT_MULTITHREADED
        if (FAILED(hr)) {
            spdlog::error("Failed to initialize COM library using CoInitializeEx Error code = {}", hresultToUTF8(hr));
            wss << L"Failed to initialize COM library using CoInitializeEx Error code = " << hresultTowstring(hr) << std::endl;
            error = true;
        }
        hr = CoInitializeSecurity(
            NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE, NULL);
        if (FAILED(hr)) {
            wss << L"Failed to initialize COM security using CoInitializeSecurity Error code = " << hresultTowstring(hr) << std::endl;
            spdlog::error("Failed to initialize COM security using CoInitializeSecurity Error code = {}", hresultToUTF8(hr));
            error = true;
        }
    } else {
        HRESULT hr = CoInitialize(nullptr);
        if (FAILED(hr))
        {
            wss << L"Failed to initialize COM library using CoInitialize Error code = " << hr << std::endl;
            spdlog::error("Failed to initialize COM library using CoInitialize Error code = {}", hresultToUTF8(hr));
            error = true;
        }
    }

    messageString = wss.str();

    if(!error) {
        mClient = new OPCClient(mCallbackFunc);
    }
}

OPCInit::~OPCInit() {
    delete mClient;
    spdlog::debug("Calling CoUninitialize");
    CoUninitialize();
}

OPCClient *OPCInit::getClient() {
    if (error) {
    std::wstringstream wss;
        wss << L"Client in error state cannot further process requests" << std::endl;
        spdlog::error("Client in error state cannot further process requests");
        lastMessage() = wss.str();
        return nullptr;
    }
    return mClient;
}


