//
// Created by nova on 7/23/20.
//

#include "Options.h"

std::tuple<std::string, bool, bool, std::string> Options::get()
{
	int index = 0;
	int opt = 0;
	while(EOF != (opt = getopt_long(argc, argv, "m:ic:svh", longOptions, &index)))
	{
		switch (opt)
		{
			case 'm':
			{
				std::map<std::string, std::string> optionKV;
				optionKV["value"] = std::string(optarg);
				selectedOption["mode"] = optionKV;
				break;
			}
			case 'i':
			{
				std::map<std::string, std::string> optionKV;
				optionKV["value"] = std::string("true");
				selectedOption["immediately"] = optionKV;
				break;
			}
			case 'c':
			{
				std::map<std::string, std::string> optionKV;
				optionKV["value"] = std::string(optarg);
				selectedOption["config"] = optionKV;
				break;
			}
			case 's':
			{
				std::map<std::string, std::string> optionKV;
				optionKV["value"] = std::string("true");
				selectedOption["secure"] = optionKV;
				break;
			}
			case 'v':
			{
				std::cout << VERSION << std::endl;
				exit(EXIT_SUCCESS);
			}
			case 'h':
			{
				std::cout << R"(AcmeCat )" << VERSION << std::endl;
				std::cout << R"()" << std::endl;
				std::cout << R"(Usage: acmecat -m MODE -c PATH)" << std::endl;
				std::cout << R"(       acmecat -m MODE -c PATH --secure --immediately)" << std::endl;
				std::cout << R"(       acmecat -m MODE -c PATH --secure)" << std::endl;
				std::cout << R"(       acmecat -m MODE -c PATH --immediately)" << std::endl;
				std::cout << R"()" << std::endl;
				std::cout << R"(Options:)" << std::endl;
				std::cout << R"(Either long or short options are allowed.)" << std::endl;
				std::cout << R"(  --version     -v         Print acmecat's version.)" << std::endl;
				std::cout << R"(  --help        -h         Print this message.)" << std::endl;
				std::cout << R"(  --secure      -s         Disable the program's memory from entering the.)" << std::endl;
				std::cout << R"(                           swap area, root privilege required for this option.)" << std::endl;
				std::cout << R"(  --mode        -m [MODE]  Specific which mode should run, "server" or "client".)" << std::endl;
				std::cout << R"(  --immediately -i         Request immediately at startup, don't wait for the)" << std::endl;
				std::cout << R"(                           next time point of cron expression.)" << std::endl;
				std::cout << R"(  --config      -c [PATH]  Configuration json file's path.)" << std::endl;
				exit(EXIT_SUCCESS);
			}
			default: exit(OPTIONS_INVALID);
		}
	}
	
	auto notFound = selectedOption.end();
	if (selectedOption.find("mode") == notFound)
		throw OptionsException("Missing option '--mode' or '-m'.");
	else if (selectedOption["mode"]["value"] != std::string("server") and selectedOption["mode"]["value"] != std::string("client"))
		throw OptionsException(R"(Argument of option '--mode' or '-m' could only be "server" or "client".)");
	else if (selectedOption.find("config") == notFound)
		throw OptionsException("Missing option '--config' or '-c'."); // --config not selected
	else
	{
		std::string mode = selectedOption["mode"]["value"];
		bool immediately = selectedOption["immediately"]["value"] == "true";
		bool secure = selectedOption["secure"]["value"] == "true";
		std::string configFilePath = selectedOption["config"]["value"];
		return make_tuple(mode, secure, immediately, configFilePath);
	}
}

Options::Options(int argc, char** argv)
{
	this->argc = argc;
	this->argv = argv;
	
	longOptions = (struct option*)malloc(6 * sizeof(option));
	longOptions[0] = {"mode", required_argument, nullptr, 'm'};
	longOptions[1] = {"immediately", no_argument, nullptr, 'i'};
	longOptions[2] = {"config", required_argument, nullptr, 'c'};
	longOptions[3] = {"secure", no_argument, nullptr, 's'};
	longOptions[4] = {"version", no_argument, nullptr, 'v'};
	longOptions[5] = {"help", no_argument, nullptr, 'h'};
}

Options::~Options()
{
	free(longOptions);
}
