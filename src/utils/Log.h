//
// Created by nova on 8/5/20.
//

#ifndef ACMED_LOG_H
#define ACMED_LOG_H

#include "jsoncpp/include/json/json.h"
#include "easyloggingpp/src/easylogging++.h"

static const std::string serverLogFileName = "acmecat_server.log";
static const std::string clientLogFileName = "acmecat_client.log";

inline void PreRollOutCallback(const char* fullPath, std::size_t s)
{
	auto utcZone = Utils::Time::localTimeZoneUTC();
	auto newName = std::string(fullPath) + "." + Utils::Time::UnixTimeToRFC3339(std::time(nullptr), utcZone);
	rename(fullPath, newName.c_str());
}

inline void SetupEasylogger(const Json::Value& configs, const std::string& mode)
{
	el::Configurations loggerConf;      /* Logger configuration */
	el::Helpers::installPreRollOutCallback(PreRollOutCallback);
	el::Loggers::addFlag(el::LoggingFlag::StrictLogFileSizeCheck);
	loggerConf.setToDefault();
#ifndef NDEBUG
	loggerConf.set(el::Level::Global, el::ConfigurationType::Format,
	               "%datetime [%level] (%fbase:%line) %msg");       /* Set log format */
#else
	loggerConf.set(el::Level::Global, el::ConfigurationType::Format,
	               "%datetime [%level] %msg");       /* Set log format */
#endif
	loggerConf.set(el::Level::Global, el::ConfigurationType::MaxLogFileSize, "4194304");  /* 4 MiB */
	loggerConf.set(el::Level::Global, el::ConfigurationType::ToFile, "true");   /* Set log to file */
	loggerConf.set(el::Level::Global, el::ConfigurationType::ToStandardOutput, "true"); /* Set log to stdout */
	loggerConf.set(el::Level::Global, el::ConfigurationType::Filename, configs["log"]["dir"].asString() +
	                                                                   (mode == "server" ? "/" + serverLogFileName
	                                                                                     : "/" + clientLogFileName));     /* Set log file path */
	el::Loggers::reconfigureAllLoggers(loggerConf);      /* Apply configuration to all loggers */
}

#endif //ACMED_LOG_H
