#include <cstdlib>
#include <memory>
#include <tuple>
#include <iostream>
#include <algorithm>
#include <sys/mman.h>
#include "Options.h"
#include "Configuration.h"
#include "utils/Log.h"
#include "utils/Codes.h"
#include "utils/jsoncpp/include/json/json.h"
#include "utils/easyloggingpp/src/easylogging++.h"
#include "distribution/Server.h"
#include "distribution/Client.h"

INITIALIZE_EASYLOGGINGPP

int main(int argc, char* argv[])
{
	/* Get command line options */
	std::tuple<std::string, bool, bool, std::string> result;
	try
	{
		result = Options(argc, argv).get();
	}
	catch (OptionsException& e)
	{
		std::cerr << "[Options Error] " << e.what() << std::endl;
		exit(OPTIONS_INVALID);
	}
	auto[mode, secure, issueImmediately, configFilePath] = result;
	
	if (secure)
	{   /* Check root privilege */
		if (getuid() != 0)
		{
			std::cerr << "Error: root privilege required!" << std::endl;
			exit(NO_ROOT_PRIVILEGE);
		}
		/* Disable swap to protect the sensitive data. (root privilege required) */
		if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		{
			std::cerr << "Error: mlockall() failed!" << std::endl;
			exit(MLOCKALL_FAILED);
		}
	}
	
	/* Get configurations */
	Json::Value globalConfigs;
	try
	{
		Configuration loader = Configuration(configFilePath, mode);
		globalConfigs = loader.getJson();
	}
	catch (ConfigurationException& e)
	{
		std::cerr << "[Config Error] " << e.what() << std::endl;
		exit(CONFIG_FILE_INVALID);
	}
	
	/* Easylogging */
	SetupEasylogger(globalConfigs, mode);
	
	/* Start server or client */
	try
	{
		if (mode == "server")
		{
			Server server(globalConfigs, issueImmediately);
			server.run();
		}
		else if (mode == "client")
		{
			Client client(globalConfigs, issueImmediately);
			client.run();
		}
	}
	catch (ServerFatalException& e)
	{
		LOG(INFO) << "Fatal error occurs in the main thread, exit.";
		exit(FATAL_ERROR_OCCURS_IN_THE_MAIN_THREAD);
	}
	catch (ClientFatalException& e)
	{
		LOG(INFO) << "Fatal error occurs in the main thread, exit.";
		exit(FATAL_ERROR_OCCURS_IN_THE_MAIN_THREAD);
	}
	
	return 0;
}

