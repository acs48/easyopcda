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
#include "easyopcda/opcclient.h"
#include "easyopcda/opcgroup.h"

#include <chrono>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/fmt/chrono.h"


int main(int argc, char **argv) {
	auto console = spdlog::stdout_color_mt("easyopcda_example");
	spdlog::set_default_logger(console);
	spdlog::set_level(spdlog::level::info);

	easyopcda::disableLogToClass();
	easyopcda::enableLogToDefault();

	auto opcConnection = new OPCInit([](std::wstring groupName, easyopcda::opcTagResult inputData) {
		spdlog::info("group: {:<10}item: {:<20}time: {:<30}value: {:<20}quality: {:<15}error: {:<15}", wstringToUTF8(groupName),wstringToUTF8(inputData.tagName), FileTimeToChrono(inputData.timestamp), variant2UTF8(inputData.value), opcQualityToUTF8(inputData.quality),hresultToUTF8(inputData.error));
	});
	auto client = opcConnection->getClient();
	client->setOPCServerHostAndUser(L"localhost",L"",L"",L"");
	client->listDAServers(L"20");
	client->connectToOPCByProgID(L"Matrikon.OPC.Simulation.1");

	auto group = client->addGroup(L"gp1",10000);
	std::vector<std::wstring> items = {L"Random.Real8",L"Random.String",L"Random.Int4"};
	group->addItems(items);

	group->syncReadGroup();
	group->asyncReadGroup();

	group->waitForTransactionsComplete();

	delete opcConnection;
}