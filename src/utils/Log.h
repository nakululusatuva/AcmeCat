//
// Created by nova on 8/5/20.
//

#ifndef ACMED_LOG_H
#define ACMED_LOG_H

#include "jsoncpp/include/json/json.h"
#include "easyloggingpp/src/easylogging++.h"

// TODO: Add log rotate
inline void SetupEasylogger(const Json::Value& configs, const std::string& mode)
{
	el::Configurations loggerConf;      /* Logger configuration */
	loggerConf.setToDefault();
#ifndef NDEBUG
	loggerConf.set(el::Level::Global, el::ConfigurationType::Format,
	               "%datetime [%level] (%fbase:%line) %msg");       /* Set log format */
#else
	loggerConf.set(el::Level::Global, el::ConfigurationType::Format,
	               "%datetime [%level] %msg");       /* Set log format */
#endif
	loggerConf.set(el::Level::Global, el::ConfigurationType::MaxLogFileSize, "16777216");
	loggerConf.set(el::Level::Global, el::ConfigurationType::ToFile, "true");   /* Set log to file */
	loggerConf.set(el::Level::Global, el::ConfigurationType::ToStandardOutput, "true"); /* Set log to stdout */
	loggerConf.set(el::Level::Global, el::ConfigurationType::Filename, configs["log"]["dir"].asString() +
	                                                                   (mode == "server" ? "/acme_server.log"
	                                                                                     : "/acme_client.log"));     /* Set log file path */
	el::Loggers::reconfigureAllLoggers(loggerConf);      /* Apply configuration to all loggers */
}

#endif //ACMED_LOG_H
