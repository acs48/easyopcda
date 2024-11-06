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
#include "easyopcda/opcinit.h"

#include <atlbase.h>

#include <sstream>
#include <utility>


OPCInit::OPCInit(easyopcda::ASyncCallback func)
//    : ss_sink(std::make_shared<spdlog::sinks::ostream_sink_mt>(ss)),
//      logger(std::make_shared<spdlog::logger>("easyopcda", ss_sink))
{
    error=false;
    mClient = nullptr;
    mCallbackFunc = std::move(func);

    auto tid = std::this_thread::get_id();
    auto hid = std::hash<std::thread::id>{}(tid);
    DEBUG_LOG("Initializing COM on thread {}", hid);

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    //COINIT_APARTMENTTHREADED
    //COINIT_MULTITHREADED
    if (FAILED(hr)) {
        ERROR_LOG("Failed to initialize COM library using CoInitializeEx. Error code = {}", hresultToUTF8(hr));
        error = true;
    }
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) {
        ERROR_LOG("Failed to initialize COM security using CoInitializeSecurity. Error code = {}", hresultToUTF8(hr));
        error = true;
    }


    if(!error) {
        INFO_LOG("DCOM initialized");
        mClient = new OPCClient(mCallbackFunc);
    }
}

OPCInit::~OPCInit() {
    delete mClient;
    DEBUG_LOG("Calling CoUninitialize");
    CoUninitialize();
}

OPCClient *OPCInit::getClient() {
    if (error) {
        ERROR_LOG("Client in error state cannot further process requests");
        return nullptr;
    }
    return mClient;
}


