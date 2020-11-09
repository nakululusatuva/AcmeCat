//
// Created by nova on 8/12/20.
//

#include "Configuration.h"

const Json::Value& Configuration::getJson()
{
	return configs;
}

void Configuration::load()
{
	// Check if json file exists
	if (access(configFilePath.c_str(), R_OK) == -1 || access(configFilePath.c_str(), W_OK))
		throw ConfigurationException("config file inaccessible.");
	
	// Read string from file
	std::ifstream in(configFilePath);
	std::string jsonString((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	
	// Parse string to json
	std::string errs;
	Json::CharReaderBuilder builder;
	std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	bool ok = reader->parse(jsonString.c_str(), jsonString.c_str() + jsonString.size(), &configs, &errs);
	if (!ok)
		throw ConfigurationException("Errors in config file:\n" + errs);
	
	// Check configurations
	checkConfigs();
}

void Configuration::checkConfigs()
{
	propertyLog();
	if (mode == "server")
		propertyServer();
	else
		propertyClient();
}

void Configuration::propertyLog()
{
	if (configs["log"].isNull())
		throw ConfigurationException("property 'log' not found.");
	else
		propertyLogDir(configs["log"]);
}

void Configuration::propertyLogDir(const Json::Value& log)
{
	if (log.isNull())
		throw ConfigurationException("property 'log.dir' not found.");
	
	else if (!log["dir"].isString())
		throw ConfigurationException("value of 'log.dir' must be a string.");
	
	else if (access(log["dir"].asCString(), R_OK) == -1 ||
	         access(log["dir"].asCString(), W_OK)) /* Check if property 'log.dir' readable and writable */
		throw ConfigurationException("value of 'log.dir', the location of log files is inaccessible.");
}

void Configuration::propertyServer()
{
	if (configs["server"].isNull())
		throw ConfigurationException("property 'server' not found.");
	
	else
	{
		propertyServerPort(configs["server"]);
		propertyServerWorkers(configs["server"]);
		propertyServerAuthorizedkeys(configs["server"]);
		propertyServerPrivatekey(configs["server"]);
		propertyServerAcme(configs["server"]);
	}
}

void Configuration::propertyServerPort(const Json::Value& server)
{
	if (server["port"].isNull())
		throw ConfigurationException("property 'server.port' not found.");
	
	else if (!server["port"].isNumeric())
		throw ConfigurationException("value of 'server.port' must be a number.");
	
	else if (!server["port"].isIntegral())
		throw ConfigurationException("value of 'server.port' must be an integer.");
	
	else if (server["port"].asInt() <= 0 || server["port"].asInt() > 65535)
		throw ConfigurationException("value of 'server.port', port number out of range.");
}

void Configuration::propertyServerWorkers(const Json::Value& server)
{
	if (server["workers"].isNull())
		throw ConfigurationException("property 'server.workers' not found.");
	
	else if (!server["workers"].isNumeric())
		throw ConfigurationException("value of 'server.workers' must be a number.");
	
	else if (!server["workers"].isIntegral())
		throw ConfigurationException("value of 'server.workers' must be an integer.");
	
	else if (server["workers"].asInt() < 1)
		throw ConfigurationException("value of 'server.workers', thread number must be at least one.");
}

void Configuration::propertyServerAuthorizedkeys(const Json::Value& server)
{
	if (!server["authorized_keys"].isNull())
	{
        if (!server["authorized_keys"].isArray())
            throw ConfigurationException("value of 'server.authorized_keys' must be an array.");
        else
        {
            for (const auto& nameAndPem : server["authorized_keys"])
            {
                if (nameAndPem["name"].isNull())
                    throw ConfigurationException("value of 'server.authorized_keys', property 'name' should not be empty.");
                else if (!nameAndPem["name"].isString())
                    throw ConfigurationException("value of 'server.authorized_keys', property 'name' must be a string.");

                /* Cast stringify "\n" to control character '\n' */
                auto key = std::regex_replace(nameAndPem["public_key"].asString(), std::regex("\\n"), "\n");

                if (!OpensslWrap::PEM::IsPublicKey(key))    /* Check if a public key */
                    throw ConfigurationException(
                            "property 'server.authorized_keys' contains key(s) which is not a public key.");

                try    /* Check if the key is a valid rsa key */
                {
                    auto rsa = OpensslWrap::PEM::ToRsa(key);
                    if (OpensslWrap::AsymmetricRSA::KeyBits(rsa) < MINIMUM_RSA_KEY_BITS_OF_SECURE)
                        throw ConfigurationException("value of 'server.authorized_keys', keys' size should be at least " + std::to_string(MINIMUM_RSA_KEY_BITS_OF_SECURE) + " bits.");

                    /* Check if exponent is 0x010001 */
                    const BIGNUM* n = nullptr;  const BIGNUM* e = nullptr;  const BIGNUM* d = nullptr;
                    RSA_get0_key(rsa.get(), &n, &e, &d);
                    auto* hexChars = BN_bn2hex(e);
                    if (memcmp(hexChars, "010001", 6) != 0)
                    {
                        free(hexChars);
                        throw ConfigurationException(
                                "value of 'server.authorized_keys', the exponent of the key must be 0x010001.");
                    }
                    free(hexChars);

                    rsa.reset();
                }
                catch (OpensslWrap::Exceptions::PemStringToRsaFailedException& e)
                {
                    throw ConfigurationException("property 'server.authorized_keys' contains invalid PEM format key.");
                }
                catch (OpensslWrap::Exceptions::NotRSAKeyException& e)
                {
                    throw ConfigurationException("property 'server.authorized_keys' contains non-RSA key.");
                }
            }
        }
    }
}

void Configuration::propertyServerPrivatekey(const Json::Value& server)
{
	if (server["private_key"].isNull())
		throw ConfigurationException("property 'server.private_key' not found.");
	
	else if (!server["private_key"].isString())
		throw ConfigurationException("value of 'server.private_key' must be a string.");
	
	else
	{
		std::string key = server["private_key"].asString();
		try /* Check if 'server.private_key' is valid */
		{
			std::shared_ptr<RSA> rsa = nullptr;
			if (OpensslWrap::PEM::MightBeEncrypted(key)) /* Key is encrypted */
			{
				propertyServerPrivatekeypassphrase(server);
				std::string passphrase = server["private_key_passphrase"].asString();
				rsa = OpensslWrap::PEM::ToRsa(key, passphrase);
			}
			else    /* Key is not encrypted */
			{
				rsa = OpensslWrap::PEM::ToRsa(key);
				if (!OpensslWrap::PEM::IsPrivateKey(key))
					throw ConfigurationException("value of 'server.private_key' is not a private key.");
			}
			if (OpensslWrap::AsymmetricRSA::KeyBits(rsa) < MINIMUM_RSA_KEY_BITS_OF_SECURE)
				throw ConfigurationException("value of 'server.private_key', key's size should be at least " + std::to_string(MINIMUM_RSA_KEY_BITS_OF_SECURE) + " bits.");
			
			/* Check if exponent is 0x010001 */
			const BIGNUM* n = nullptr;  const BIGNUM* e = nullptr;  const BIGNUM* d = nullptr;
			RSA_get0_key(rsa.get(), &n, &e, &d);
			auto* hexChars = BN_bn2hex(e);
			if (memcmp(hexChars, "010001", 6) != 0)
			{
				free(hexChars);
				throw ConfigurationException(
						"value of 'server.private_key', the exponent of the key must be 0x010001.");
			}
			free(hexChars);
				
			rsa.reset();
		}
		catch (OpensslWrap::Exceptions::PemStringToRsaFailedException& e)
		{
			throw ConfigurationException("value of 'server.private_key', " + std::string(e.what()));
		}
		catch (OpensslWrap::Exceptions::NotRSAKeyException& e)
		{
			throw ConfigurationException("value of 'server.private_key', " + std::string(e.what()));
		}
	}
}

void Configuration::propertyServerPrivatekeypassphrase(const Json::Value& server)
{
	if (!server["private_key_passphrase"].isNull() and !server["private_key_passphrase"].isString())
		throw ConfigurationException("value of 'server.private_key_passphrase' must be a string.");
}

void Configuration::propertyServerAcme(const Json::Value& server)
{
	if (server["acme"].isNull())
		throw ConfigurationException("property 'server.acme' not found.");
	else
	{
		propertyServerAcmeMailto(server["acme"]);
		propertyServerAcmeCA(server["acme"]);
		propertyServerAcmeDomains(server["acme"]);
		propertyServerAcmeChallenge(server["acme"]);
		propertyServerAcmeSavedir(server["acme"]);
		propertyServerAcmeCronexpression(server["acme"]);
		propertyServerAcmeShellcommand(server["acme"]);
	}
}

void Configuration::propertyServerAcmeMailto(const Json::Value& acme)
{
	if (acme["mailto"].isNull())
		throw ConfigurationException("property 'server.acme.mailto' not found.");
	
	else if (!acme["mailto"].isArray())
		throw ConfigurationException("value of 'server.acme.mailto' must be an array.");
	
	else if (acme["mailto"].empty())
		throw ConfigurationException("value of 'server.acme.mailto', array cannot be empty.");
	
	for (const auto& email : acme["mailto"])
	{
		if (!Utils::EmailIsValid(email.asString()))
			throw ConfigurationException("value of 'server.acme.mailto' contains invalid email: " + email.asString());
	}
}

void Configuration::propertyServerAcmeCA(const Json::Value& acme)
{
	if (acme["ca"].isNull())
		throw ConfigurationException("property 'server.acme.ca' not found.");
	
	else if (!acme["ca"].isString())
		throw ConfigurationException("value of 'server.acme.ca' must be a string.");
	
	else if (!Acme::CAIsSupported(acme["ca"].asString()))
		throw ConfigurationException("value of 'server.acme.ca', not supported certificate authority.");
}

void Configuration::propertyServerAcmeDomains(const Json::Value& acme)
{
	if (acme["domains"].isNull())
		throw ConfigurationException("property 'server.acme.domains' not found.");
	
	else if (!acme["domains"].isArray())
		throw ConfigurationException("value of 'server.acme.domains' must be an array.");
	
	else if (acme["domains"].empty())
		throw ConfigurationException("value of 'server.acme.domains', array cannot be empty.");
	
	/* Check if domain names are valid and have the same base domain. */
	for (const auto& domain : acme["domains"])
	{
		if (!Utils::Domain::IsValid(domain.asString(), true))
			throw ConfigurationException("value of 'server.acme.domains' contains invalid domain: " + domain.asString() + ".");
		std::string base = Utils::Domain::ExtractBaseDomain(acme["domains"][0].asString());
		for (unsigned long i = 1; i < acme["domains"].size(); ++i)
		{
			std::string loopItem = acme["domains"][(int)i].asString();
			std::string loopItemBase = Utils::Domain::ExtractBaseDomain(loopItem);
			if (loopItemBase != base)
				throw ConfigurationException("value of 'server.acme.domains', domains has different base domain: " + base.append(" conflicts ") + loopItemBase);
		}
	}
	
	/* Check if wildcard domain name have at least one non-wildcard parent */
	// TODO: Optimize this O(n^2) shit work!!!!!!
	for (const auto& domain : acme["domains"])
	{
		if (!Utils::Domain::IsWildcard(domain.asString()))
			continue;
		std::string parent = Utils::Domain::RemoveLowestLevelSub(domain.asString(), false);
		std::string parentToPrint = parent;
		std::string grandmaToPrint = Utils::Domain::RemoveLowestLevelSub(parent, false);
		while (!parent.empty())
		{
			unsigned int count = 0;
			for (const auto& compare : acme["domains"])
			{
				if (compare == parent)
					break;
				count++;
			}
			if (count != acme["domains"].size())   /* Parent found */
				break;
			parent = Utils::Domain::RemoveLowestLevelSub(parent, false);
		}
		if (parent.empty())
		{
			throw ConfigurationException( "array of 'server.acme.domains', for wildcard domain name '" + domain.asString() +
			                             "', must have a non-wildcard parent domain name like '" + parentToPrint + "'" +
			                             (grandmaToPrint.empty() ? "" : " or '" + Utils::Domain::ExtractBaseDomain(domain.asString()) +
			                             "' in this array.") );
		}
	}
}

void Configuration::propertyServerAcmeChallenge(const Json::Value& acme)
{
	if (acme["challenge"].isNull())
		throw ConfigurationException("property 'server.acme.challenge' not found.");
	else
		propertyServerAcmeChallengeType(acme["challenge"]);
}

void Configuration::propertyServerAcmeChallengeType(const Json::Value& method)
{
	if (method["type"].isNull())
		throw ConfigurationException("property 'server.acme.method.type' not found.");
	
	else if (!method["type"].isString())
		throw ConfigurationException("value of 'server.acme.method.type' must be a string.");
	
	else if (!Acme::ChallengeTypeIsSupported(method["type"].asString()))
		throw ConfigurationException("value of 'server.acme.method.type', not supported acme method.");
	
	else
		propertyServerAcmeChallengeDnssettings(method);
}

void Configuration::propertyServerAcmeChallengeDnssettings(const Json::Value& method)
{
	if (method["dns_settings"].isNull())
		throw ConfigurationException("property 'server.acme.method.dns_settings' not found.");
	
	else
		propertyServerAcmeChallengeDnssettingsProvider(method["dns_settings"]);
}

void Configuration::propertyServerAcmeChallengeDnssettingsProvider(const Json::Value& dnsSettings)
{
	if (dnsSettings["provider"].isNull())
		throw ConfigurationException("property 'server.acme.method.dns_settings.provider' not found.");
	
	else if (!dnsSettings["provider"].isString())
		throw ConfigurationException("value of 'server.acme.method.dns_settings.provider' must be a string.");
	
	else if (!DNS::ProviderIsSupported(dnsSettings["provider"].asString()))
		throw ConfigurationException(
				"value of 'server.acme.method.dns_settings.provider', not supported DNS provider.");
	
	else if (dnsSettings["provider"].asString() == "cloudflare")
		propertiesOfCloudflareProvider(dnsSettings);
}

void Configuration::propertiesOfCloudflareProvider(const Json::Value& dnsSettings)
{
	if (dnsSettings["email"].isNull())
		throw ConfigurationException("property 'server.acme.method.dns_settings.email' not found.");
	
	else if (!dnsSettings["email"].isString())
		throw ConfigurationException("value of 'server.acme.method.dns_settings.email' must be a string.");
	
	else if (!Utils::EmailIsValid(dnsSettings["email"].asString()))
		throw ConfigurationException("value of 'server.acme.method.dns_settings.email', " + dnsSettings["email"].asString() + " is not a valid email.");
	
	else if (dnsSettings["zone_id"].isNull())
		throw ConfigurationException("property 'server.acme.method.dns_settings.zone_id' not found.");
	
	else if (!dnsSettings["zone_id"].isString())
		throw ConfigurationException("value of 'server.acme.method.dns_settings.zone_id' must be a string.");
	
	else if (dnsSettings["global_api_key"].isNull())
		throw ConfigurationException("property 'server.acme.method.dns_settings.global_api_key' not found.");
	
	else if (!dnsSettings["global_api_key"].isString())
		throw ConfigurationException("value of 'server.acme.method.dns_settings.global_api_key' must be a string.");
}

void Configuration::propertyServerAcmeSavedir(const Json::Value& acme)
{
	if (acme["save_dir"].isNull())
		throw ConfigurationException("property 'server.acme.save_dir' not found.");
	
	else if (!acme["save_dir"].isString())
		throw ConfigurationException("value of 'server.acme.save_dir' must be a string.");
	
	else if (access(acme["save_dir"].asCString(), W_OK) == -1)   /* Check if cert files' save location accessible. */
		throw ConfigurationException(
				"value of 'server.acme.save_dir', The location where the new certificate is saved is inaccessible.");
}

void Configuration::propertyServerAcmeCronexpression(const Json::Value& acme)
{
	if (acme["cron_expression"].isNull())
		throw ConfigurationException("property 'server.acme.cron_expression' not found.");
	
	else if (!acme["cron_expression"].isString())
		throw ConfigurationException("value of 'server.acme.cron_expression' must be a string.");
	
	else
	{
		std::string cronExpression = acme["cron_expression"].asString();
		try
		{
			cron::make_cron(cronExpression);
		}
		catch (cron::bad_cronexpr const& ex)
		{
			throw ConfigurationException("value of 'server.acme.cron_expression', not a valid cron expression.");
		}
	}
}

void Configuration::propertyServerAcmeShellcommand(const Json::Value& acme)
{
	if (!acme["shell_command"].isNull() and !acme["shell_command"].isString())
		throw ConfigurationException("value of 'server.acme.shell_command' must be a string.");
}


void Configuration::propertyClient()
{
	if (configs["client"].isNull())
		throw ConfigurationException("property 'client' not found.");
	else
	{
		propertyClientHost(configs["client"]);
		propertyClientPort(configs["client"]);
		propertyClientServerpublickey(configs["client"]);
		propertyClientPrivatekey(configs["client"]);
		propertyClientPrivatekeypassphrase(configs["client"]);
		propertyClientDistribution(configs["client"]);
	}
}

void Configuration::propertyClientHost(const Json::Value& client)
{
	if (client["host"].isNull())
		throw ConfigurationException("property 'client.host' not found.");
	
	else if (!client["host"].isString())
		throw ConfigurationException("value of 'client.host' must be a string.");
}

void Configuration::propertyClientPort(const Json::Value& client)
{
	if (client["port"].isNull())
		throw ConfigurationException("property 'client.port' not found.");
	
	else if (!client["port"].isNumeric())
		throw ConfigurationException("value of 'client.port' must be a number.");
	
	else if (!client["port"].isIntegral())
		throw ConfigurationException("value of 'client.port' must be an integer.");
	
	else if (client["port"].asInt() <= 0 || client["port"].asInt() > 65535)
		throw ConfigurationException("value of 'client.port', port number out of range.");
}

void Configuration::propertyClientServerpublickey(const Json::Value& client)
{
	if (client["server_public_key"].isNull())
		throw ConfigurationException("property 'client.server_public_key' not found.");
	
	else if (!client["server_public_key"].isString())
		throw ConfigurationException("value of 'client.server_public_key' must be a string.");
	
	else
	{
		std::string key = client["server_public_key"].asString();
		try    /* Check if the key is a valid rsa key */
		{
			std::shared_ptr<RSA> rsa = OpensslWrap::PEM::ToRsa(key);
			if (OpensslWrap::AsymmetricRSA::KeyBits(rsa) < MINIMUM_RSA_KEY_BITS_OF_SECURE)
				throw ConfigurationException("value of 'client.server_public_key', key's size should be at least " + std::to_string(MINIMUM_RSA_KEY_BITS_OF_SECURE) + " bits.");
			
			/* Check if exponent is 0x010001 */
			const BIGNUM* n = nullptr;  const BIGNUM* e = nullptr;  const BIGNUM* d = nullptr;
			RSA_get0_key(rsa.get(), &n, &e, &d);
			auto* hexChars = BN_bn2hex(e);
			if (memcmp(hexChars, "010001", 6) != 0)
			{
				free(hexChars);
				throw ConfigurationException(
						"value of 'client.server_public_key', the exponent of the key must be 0x010001.");
			}
			free(hexChars);
			
			rsa.reset();
		}
		catch (OpensslWrap::Exceptions::PemStringToRsaFailedException& e)
		{
			throw ConfigurationException("value of 'client.server_public_key', invalid PEM format key.");
		}
		catch (OpensslWrap::Exceptions::NotRSAKeyException& e)
		{
			throw ConfigurationException("value of 'client.server_public_key', not an RSA key.");
		}
		if (!OpensslWrap::PEM::IsPublicKey(key))
			throw ConfigurationException("value of 'client.server_public_key' is not a public key.");
	}
}

void Configuration::propertyClientPrivatekey(const Json::Value& client)
{
	if (client["private_key"].isNull())
		throw ConfigurationException("property 'client.private_key' not found.");
	
	else if (!client["private_key"].isString())
		throw ConfigurationException("value of 'client.private_key' must be a string.");
	
	else
	{
		std::string key = client["private_key"].asString();
		try     /* Check if 'client.private_key' is valid */
		{
			std::shared_ptr<RSA> rsa = nullptr;
			if (OpensslWrap::PEM::MightBeEncrypted(key)) /* If 'client.private_key' is encrypted */
			{
				propertyClientPrivatekeypassphrase(client);
				std::string passphrase = client["private_key_passphrase"].asString();
				rsa = OpensslWrap::PEM::ToRsa(key, passphrase);
			}
			else    /* 'client.private_key' is not encrypted */
			{
				rsa = OpensslWrap::PEM::ToRsa(key);
				if (!OpensslWrap::PEM::IsPrivateKey(key))
					throw ConfigurationException("value of 'client.private_key' is not a private key.");
			}
			if (OpensslWrap::AsymmetricRSA::KeyBits(rsa) < MINIMUM_RSA_KEY_BITS_OF_SECURE)
				throw ConfigurationException("value of 'client.private_key', key's size should be at least " + std::to_string(MINIMUM_RSA_KEY_BITS_OF_SECURE) + " bits.");
			
			/* Check if exponent is 0x010001 */
			const BIGNUM* n = nullptr;  const BIGNUM* e = nullptr;  const BIGNUM* d = nullptr;
			RSA_get0_key(rsa.get(), &n, &e, &d);
			auto* hexChars = BN_bn2hex(e);
			if (memcmp(hexChars, "010001", 6) != 0)
			{
				free(hexChars);
				throw ConfigurationException(
						"value of 'client.private_key', exponent of the key must be 0x010001.");
			}
			free(hexChars);
			
			rsa.reset();
		}
		catch (OpensslWrap::Exceptions::PemStringToRsaFailedException& e)
		{
			throw ConfigurationException("value of 'client.private_key', " + std::string(e.what()));
		}
		catch (OpensslWrap::Exceptions::NotRSAKeyException& e)
		{
			throw ConfigurationException("value of 'client.private_key', " + std::string(e.what()));
		}
	}
}

void Configuration::propertyClientPrivatekeypassphrase(const Json::Value& client)
{
	if (!client["private_key_passphrase"].isNull() and !client["private_key_passphrase"].isString())
		throw ConfigurationException("property 'client.private_key_passphrase' not found.");
}

void Configuration::propertyClientDistribution(const Json::Value& client)
{
	if (client["distribution"].isNull())
		throw ConfigurationException("property 'client.distribution' not found.");
	
	else
	{
		propertyClientDistributionSavedir(client["distribution"]);
		propertyClientDistributionCronexpression(client["distribution"]);
		propertyClientDistributionShellcommand(client["distribution"]);
	}
}

void Configuration::propertyClientDistributionSavedir(const Json::Value& distribution)
{
	if (distribution["save_dir"].isNull())
		throw ConfigurationException("property 'client.distribution.save_dir' not found.");
	
	else if (!distribution["save_dir"].isString())
		throw ConfigurationException("value of 'client.distribution.save_dir' must be a string.");
	
	else if (access(distribution["save_dir"].asCString(), W_OK) == -1)
		throw ConfigurationException(
				"value of 'client.distribution.save_dir', The location where the new certificate is saved is inaccessible.");
}

void Configuration::propertyClientDistributionCronexpression(const Json::Value& distribution)
{
	if (distribution["cron_expression"].isNull())
		throw ConfigurationException("property 'client.distribution.cron_expression' not found.");
	
	else if (!distribution["cron_expression"].isString())
		throw ConfigurationException("value of 'client.distribution.cron_expression' must be a string.");
	
	else
	{
		try /* Check if cron expression is valid */
		{
			cron::make_cron(distribution["cron_expression"].asString());
		}
		catch (cron::bad_cronexpr const& e)
		{
			throw ConfigurationException(
					"value of 'client.distribution.cron_expression', invalid expression: " + std::string(e.what()) + ".");
		}
	}
}

void Configuration::propertyClientDistributionShellcommand(const Json::Value& distribution)
{
	if (!distribution["shell_command"].isNull() and !distribution["shell_command"].isString())
		throw ConfigurationException("value of 'client.distribution.shell_command' must be a string.");
}
