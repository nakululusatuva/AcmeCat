//
// Created by nova on 8/12/20.
//

#ifndef ACMED_CONFIGURATION_H
#define ACMED_CONFIGURATION_H

#include <string>
#include <regex>
#include <fstream>
#include <memory>
#include <unistd.h>
#include "utils/jsoncpp/include/json/json.h"
#include "utils/OpensslWrap.h"
#include "utils/croncpp/include/croncpp.h"
#include "acme/DNS.h"
#include "acme/Acme.h"

class Configuration
{
public:
	explicit Configuration(std::string& configPath, std::string& mode) :
							mode(mode), configFilePath(std::move(configPath)) { load(); }
	~Configuration() = default;
	const Json::Value& getJson();

private:
	void load();
	std::string mode;
	std::string configFilePath;
	Json::Value configs;
	
	/* Functions below are property checker, indentation represents the call level. */
	void checkConfigs();
	void propertyLog();
		static void propertyLogDir(const Json::Value& log);
	void propertyServer();
		static void propertyServerPort(const Json::Value& server);
		static void propertyServerWorkers(const Json::Value& server);
		static void propertyServerAuthorizedkeys(const Json::Value& server);
		static void propertyServerPrivatekey(const Json::Value& server);
			static void propertyServerPrivatekeypassphrase(const Json::Value& server);
		static void propertyServerAcme(const Json::Value& server);
			static void propertyServerAcmeMailto(const Json::Value& acme);
			static void propertyServerAcmeCA(const Json::Value& acme);
			static void propertyServerAcmeDomains(const Json::Value& acme);
			static void propertyServerAcmeChallenge(const Json::Value& acme);
				static void propertyServerAcmeChallengeType(const Json::Value& method);
				static void propertyServerAcmeChallengeDnssettings(const Json::Value& method);
					static void propertyServerAcmeChallengeDnssettingsProvider(const Json::Value& dnsSettings);
						static void propertiesOfCloudflareProvider(const Json::Value& dnsSettings);
			static void propertyServerAcmeSavedir(const Json::Value& dnsSettings);
			static void propertyServerAcmeCronexpression(const Json::Value& acme);
			static void propertyServerAcmeShellcommand(const Json::Value& acme);
	void propertyClient();
		static void propertyClientHost(const Json::Value& client);
		static void propertyClientPort(const Json::Value& client);
		static void propertyClientServerpublickey(const Json::Value& client);
		static void propertyClientPrivatekey(const Json::Value& client);
		static void propertyClientPrivatekeypassphrase(const Json::Value& client);
		static void propertyClientDistribution(const Json::Value& client);
			static void propertyClientDistributionSavedir(const Json::Value& distribution);
			static void propertyClientDistributionCronexpression(const Json::Value& distribution);
			static void propertyClientDistributionShellcommand(const Json::Value& distribution);
};

class ConfigurationException : std::exception
{
public:
	explicit ConfigurationException(std::string str) : message(std::move(str)) {}
	~ConfigurationException() noexcept override = default;;
	[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }

private:
	std::string message;
};

#endif //ACMED_CONFIGURATION_H
