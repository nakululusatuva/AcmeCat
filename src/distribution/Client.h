//
// Created by nova on 8/30/20.
//

#ifndef ACMECAT_CLIENT_H
#define ACMECAT_CLIENT_H

#include <netdb.h>
#include <unistd.h>
#include "../utils/easyloggingpp/src/easylogging++.h"
#include "../utils/jsoncpp/include/json/json.h"
#include "../utils/croncpp/include/croncpp.h"
#include "../utils/OpensslWrap.h"
#include "../utils/Utils.h"
#include "../acme/CertCache.h"
#include "Protocol.h"
#include "../utils/ThreadPool.h"

class Client
{
public:
	explicit Client(Json::Value globalConfigs, bool issueImmediately) : globalConfigs(std::move(globalConfigs)), issueImmediately(issueImmediately) {};
	~Client() = default;
	void run();
	
private:
	Json::Value globalConfigs;
	bool issueImmediately;
	static bool request(
			const std::string& hostname, int port,
			CertCache& cache,
			const std::string& fingerprint,
			const std::shared_ptr<RSA>& serverPublicKey,
			const std::shared_ptr<RSA>& clientPrivateKey);
};

class ClientFatalException : std::exception
{
public:
	ClientFatalException() = default;
	explicit ClientFatalException(std::string str) : message(std::move(str)) {}
	~ClientFatalException() noexcept override = default;;
	[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }

private:
	std::string message;
};

#endif //ACMECAT_CLIENT_H
