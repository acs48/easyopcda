//
// Created by ACS on 30/10/2024.
//

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

	auto opcConnection = new OPCInit([](std::wstring groupName, easyopcda::dataAtom inputData) {
		spdlog::info("group: {:<10}item: {:<20}time: {:<30}\tvalue: {:<20}\tquality: {:<15}\terror: {:<15}", wstringToUTF8(groupName),wstringToUTF8(inputData.tagName), FileTimeToChrono(inputData.timestamp), variant2UTF8(inputData.value), opcQualityToUTF8(inputData.quality),hresultToUTF8(inputData.error));
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