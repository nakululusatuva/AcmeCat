//
// Created by nova on 8/29/20.
//

#ifndef ACMECAT_SERVER_H
#define ACMECAT_SERVER_H

#include <netinet/in.h>
#include <utility>
#include "../utils/jsoncpp/include/json/json.h"
#include "../acme/CertCache.h"
#include "../utils/easyloggingpp/src/easylogging++.h"
#include "../acme/Acme.h"
#include "../utils/croncpp/include/croncpp.h"
#include "../utils/ThreadPool.h"
#include "Protocol.h"

class Server
{
public:
	explicit Server(Json::Value globalConfigs, bool issueImmediately) : globalConfigs(std::move(globalConfigs)), issueImmediately(issueImmediately) {};
	~Server() = default;
	void run();
private:
	Json::Value globalConfigs;
	bool issueImmediately;
	static void acmeThread(const std::shared_ptr<CertCache>& cert, const Json::Value& globalConfigs, bool immediately);
	static void handlerThread(const std::shared_ptr<CertCache>& cert, int fd, const std::shared_ptr<RSA>& serverPrivateKey, OpensslWrap::AsymmetricRSA::PublicKeyList authorizedKeys);
};

class ServerFatalException : std::exception
{
public:
	ServerFatalException() = default;
	explicit ServerFatalException(std::string str) : message(std::move(str)) {}
	~ServerFatalException() noexcept override = default;;
	[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }

private:
	std::string message;
};

#endif //ACMECAT_SERVER_H
