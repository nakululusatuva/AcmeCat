//
// Created by nova on 8/2/20.
//

#include "Acme.h"

#include <memory>

const std::vector<std::string>& Acme::SupportedChallengeTypes()
{
	static std::vector<std::string> methods
	{
		"dns-01"
	};
	return methods;
}

bool Acme::ChallengeTypeIsSupported(const std::string& method)
{
	std::string lowerCase = Utils::StringProcess::ToLowerCase(method);
	for (const auto& name : SupportedChallengeTypes())
	{
		if (name == lowerCase)
			return true;
	}
	return false;
}

const std::map<std::string, std::string>& Acme::SupportedCAList()
{
	static std::map<std::string, std::string> caAndAPI
	{
		{"letsencrypt", "acme-v02.api.letsencrypt.org"},
		{"letsencrypt-staging", "acme-staging-v02.api.letsencrypt.org"},
	//	{"digicert", "acme.digicert.com"},
	};
	return caAndAPI;
}

bool Acme::CAIsSupported(const std::string &caName)
{
	std::string lowerCase = Utils::StringProcess::ToLowerCase(caName);
	for (const auto& nameAndUri : SupportedCAList())
	{
		if (nameAndUri.first == lowerCase)
			return true;
	}
	return false;
}

const std::map<std::string, std::string>& Acme::CADirectoryPath()
{
	static std::map<std::string, std::string> caAndDirectory
	{
		{"letsencrypt", "/directory"},
		{"letsencrypt-staging", "/directory"},
		//	{"digicert", "/v2/acme/directory"},
	};
	return caAndDirectory;
}

Acme::API::API(const Json::Value& globalConfigs)
{
	caName = globalConfigs["server"]["acme"]["ca"].asString();
	if (!CAIsSupported(caName))
		throw CertificateAuthorityNotSupportedException("not supported certificate authority");
	else
	{
		this->globalConfigs = globalConfigs;
		baseDomainName = Utils::Domain::ExtractBaseDomain(globalConfigs["server"]["acme"]["domains"][0].asString());
		
		challengeType = globalConfigs["server"]["acme"]["challenge"]["type"].asString();
		accountPrivateKey = OpensslWrap::PEM::ToRsa(globalConfigs["server"]["private_key"].asString());
		for (const auto& email : globalConfigs["server"]["acme"]["mailto"])
			accountContacts.push_back(email.asString());
		for (const auto& email : globalConfigs["server"]["acme"]["domains"])
			domains.push_back(email.asString());
		
		uri = SupportedCAList().find(caName)->second;
		pathDirectory = CADirectoryPath().find(caName)->second;
		cli = std::make_unique<httplib::SSLClient>(uri, 443);
#ifdef __linux__
		cli->set_ca_cert_path("/etc/ssl/certs/ca-certificates.crt");
#endif
		cli->enable_server_certificate_verification(true);
		cli->set_connection_timeout(8, 0); // 8 seconds
		defaultHeader = httplib::Headers {
			{"Host", uri},
			{"Content-Type", "application/jose+json"}
		};
		directory();
	}
}

std::string Acme::API::createPostBody(const std::string& protectedB64Url, const std::string& payloadB64Url, const std::string& signatureB64Url)
{
	Json::Value body;
	body["protected"] = protectedB64Url;
	body["payload"]   = payloadB64Url;
	body["signature"] = signatureB64Url;
	return body.toStyledString();
}

std::string Acme::API::createProtectedMessage(const std::string& kidPart, const std::string& nonce, const std::string& urlPart)
{
	char buffer[768];
	int len = sprintf(buffer,
	                  "{\n"
	                  "   \"alg\": \"RS256\",\n"
	                  "   \"kid\": \"https://%s%s\",\n"
	                  "   \"nonce\": \"%s\",\n"
	                  "   \"url\": \"https://%s%s\"\n"
	                  "}", uri.c_str(), kidPart.c_str(), nonce.c_str(), uri.c_str(), urlPart.c_str());
	return std::string(buffer, buffer+len);
}

void Acme::API::directory()
{
	/* Request */
	auto response = cli->Get(pathDirectory.c_str(), defaultHeader);
	if (response == nullptr)
		throw Utils::APINoResponseException("API did not response.");
	else if (response->status == 200)
	{
		auto bodyStr = response->body;
		Json::CharReaderBuilder builder;
		Json::CharReader* reader = builder.newCharReader();
		std::string jsonParseErrors;
		Json::Value jsonResult;
		auto jsonParseOk = reader->parse(bodyStr.c_str(), bodyStr.c_str() + bodyStr.size(), &jsonResult, &jsonParseErrors);
		delete reader;
		if (!jsonParseOk)
			throw Utils::APIRequestException("error(s) while parsing json string from api's response, " + jsonParseErrors);
		
		std::string newAccount = jsonResult["newAccount"].asString();
		std::string newNonce = jsonResult["newNonce"].asString();
		std::string newOrder = jsonResult["newOrder"].asString();
		std::string revokeCert = jsonResult["revokeCert"].asString();
		std::string keyChange = jsonResult["keyChange"].asString();
		rootDirectory["newAccount"] = std::regex_replace(newAccount, std::regex("https://" + uri), "");
		rootDirectory["newNonce"] = std::regex_replace(newNonce, std::regex("https://" + uri), "");
		rootDirectory["newOrder"] = std::regex_replace(newOrder, std::regex("https://" + uri), "");
		rootDirectory["revokeCert"] = std::regex_replace(revokeCert, std::regex("https://" + uri), "");
		rootDirectory["keyChange"] = std::regex_replace(keyChange, std::regex("https://" + uri), "");
	}
	else throw Utils::APIRequestException("API returns http code " + std::to_string(response->status) + "\n" + response->body);
}

std::string Acme::API::newNonce()
{
	/* Request */
	auto response = cli->Head(rootDirectory["newNonce"].asString().c_str(), defaultHeader);
	if (response == nullptr)
		throw Utils::APINoResponseException("Fetching replay-nonce but API doesn't respond.");
	else if (response->status == 200)
	{
		auto mapPair = response->headers.find("Replay-Nonce");
		if (mapPair != response->headers.end())
			return mapPair->second;
		else throw Utils::APIRequestException("Get replay-nonce failed, API returns correct http code " + std::to_string(response->status) +
										" but no \"Replay-Nonce\" in response header.");
	}
	else throw Utils::APIRequestException("Get Replay-Nonce failed, API returns http code " + std::to_string(response->status) + ": " + std::regex_replace(response->body, std::regex("\n"), ""));
}

std::string Acme::API::newAccount(const std::vector<std::string>& contacts)
{
	/* Get nonce */
	std::string nonce = newNonce();
	
	/* Get e, n from public key */
	auto publicKey = OpensslWrap::AsymmetricRSA::DumpPublicKey(accountPrivateKey);
	const BIGNUM* n = nullptr;  const BIGNUM* e = nullptr;  const BIGNUM* d = nullptr;
	RSA_get0_key(publicKey.get(), &n, &e, &d);
	
	/* e, n to std::string */
	auto* nRaw = (unsigned char*)malloc(BN_num_bytes(n));
	if (!nRaw)
		throw Utils::AllocateMemoryFailed("Allocate memory failed");
	auto* eRaw = (unsigned char*)malloc(BN_num_bytes(e));
	if (!eRaw)
	{
		free(nRaw);
		throw Utils::AllocateMemoryFailed("Allocate memory failed");
	}
	BN_bn2bin(n, nRaw);
	BN_bn2bin(e, eRaw);
	std::string nStr = Utils::Codec::Base64UrlEncode(
		std::make_shared<std::vector<std::byte>>((std::byte*)nRaw, (std::byte*)nRaw+BN_num_bytes(n))
	);
	std::string eStr = Utils::Codec::Base64UrlEncode(
		std::make_shared<std::vector<std::byte>>((std::byte*)eRaw, (std::byte*)eRaw+BN_num_bytes(e))
	);
	free(nRaw);
	free(eRaw);
	
	/* Base64url encoded 'protected' */
	std::string protectedStr =
		"{\n"
		"    \"nonce\": \"" + nonce + "\",\n"
		"    \"url\": \"" + "https://" + uri + rootDirectory["newAccount"].asString() + "\",\n"
		"    \"alg\": \"RS256\",\n"
		"    \"jwk\": {\n"
		"        \"e\": \"" + eStr + "\",\n"
		"        \"kty\": \"RSA\",\n"
		"        \"n\": \"" + nStr + "\"\n"
		"    }\n"
		"}";
	std::string protectedB64Url = Utils::Codec::Base64UrlEncode(protectedStr);
	
	/* Create mailto */
	std::string mailto;
	for (const auto& email : contacts)
		mailto += ("\"mailto: " + email + "\",");
	mailto.pop_back();     /* Remove a "\n" at the end of string */
	
	/* Base64url encoded 'payload' */
	std::string payloadStr =
		"{\n"
		"    \"contact\": [\n        " +
				mailto +
		"\n    ],\n"
		"    \"termsOfServiceAgreed\": true\n"
		"}";
	std::string payloadB64Url = Utils::Codec::Base64UrlEncode(payloadStr);
	
	/* Perform RS256 */
	auto payload = Utils::StringProcess::StringToByteVec(protectedB64Url + "." + payloadB64Url);
	auto signature = OpensslWrap::AsymmetricRSA::RS256(payload, accountPrivateKey);
	auto sigB64Url = Utils::Codec::Base64UrlEncode(signature);
	
	/* Create post body */
	std::string body = createPostBody(protectedB64Url, payloadB64Url, sigB64Url);
	
	/* Request */
	auto response = cli->Post(rootDirectory["newAccount"].asString().c_str(), defaultHeader, body, "\"application/jose+json\"");
	if (response == nullptr)
		throw Utils::APINoResponseException("API did not response.");
	else if ( response->status == 200 or response->status == 201 )
	{
		auto accountIDPath = response->headers.find("Location")->second;
		accountIDPath = std::regex_replace(accountIDPath, std::regex("https://" + uri), "");
		return accountIDPath;
	}
	else throw Utils::APIRequestException("API returns http code " + std::to_string(response->status) + ": " + std::regex_replace(response->body, std::regex("\n"), ""));
}

Json::Value Acme::API::newOrder(const std::string& accountIDPath, const std::vector<std::string>& domainsList)
{
	/* Get nonce */
	std::string nonce = newNonce();
	
	/* Base64url encoded 'protected' */
	std::string protectedStr = createProtectedMessage(accountIDPath, nonce, rootDirectory["newOrder"].asString());
	std::string protectedB64Url = Utils::Codec::Base64UrlEncode(protectedStr);
	
	/* Create Domain list */
	std::string domainsStr;
	for (const auto& domain : domainsList)
		domainsStr += (R"({"type": "dns", "value": ")" + domain + "\"}, ");
	domainsStr.pop_back();     /* Remove a "\n" at the end of string */
	domainsStr.pop_back();     /* Remove a "," at the end of string */
	
	/* Base64url encoded 'payload' */
	std::string payloadStr =
	"{\n"
	"   \"identifiers\": [\n"
	"       " + domainsStr + "\n"
	"   ]\n"
	"}";
	std::string payloadB64Url = Utils::Codec::Base64UrlEncode(payloadStr);
	
	/* Perform RS256 */
	auto payload = Utils::StringProcess::StringToByteVec(protectedB64Url + "." + payloadB64Url);
	auto signature = OpensslWrap::AsymmetricRSA::RS256(payload, accountPrivateKey);
	auto sigB64Url = Utils::Codec::Base64UrlEncode(signature);
	
	/* Create post body */
	std::string body = createPostBody(protectedB64Url, payloadB64Url, sigB64Url);
	
	/* Request */
	auto response = cli->Post(rootDirectory["newOrder"].asString().c_str(), defaultHeader, body, "\"application/jose+json\"");
	if (response == nullptr)
		throw Utils::APINoResponseException("API did not response.");
	else if (response->status == 201)
	{
		/* Get order ID */
		auto orderIDPath = response->headers.find("Location")->second;
		orderIDPath = std::regex_replace(orderIDPath, std::regex("https://" + uri), "");
		/* Get authz IDs */
		Json::Value jsonResult;
		Utils::StringProcess::StringToJson(response->body, &jsonResult);
		Json::Value ret;
		ret["orderIDPath"] = orderIDPath;
		for (const auto& id : jsonResult["authorizations"])
			ret["authzIDsPath"].append(std::regex_replace(id.asString(), std::regex("https://" + uri), ""));
		ret["orderFinalizePath"] = std::regex_replace(jsonResult["finalize"].asString(), std::regex("https://" + uri), "");
		return ret;
	}
	else throw Utils::APIRequestException("API returns http code " + std::to_string(response->status) + ": " + std::regex_replace(response->body, std::regex("\n"), ""));
}

Json::Value Acme::API::fetchChallenges(const std::string& accountIDPath, const std::vector<std::string>& authzIDsPath)
{
	Json::Value challenges = Json::arrayValue;
	
	for (const auto& authzID : authzIDsPath)
	{
		std::string nonce = newNonce();
		/* Base64url encoded 'protected' */
		std::string protectedStr = createProtectedMessage(accountIDPath, nonce, authzID);
		std::string protectedB64Url = Utils::Codec::Base64UrlEncode(protectedStr);
		/* Sign */
		auto payload = Utils::StringProcess::StringToByteVec(protectedB64Url + ".");
		auto signature = OpensslWrap::AsymmetricRSA::RS256(payload, accountPrivateKey);
		auto sigB64Url = Utils::Codec::Base64UrlEncode(signature);
		
		/* Create post body */
		std::string body = createPostBody(protectedB64Url, "", sigB64Url);
		
		/* Request */
		auto response = cli->Post(authzID.c_str(), defaultHeader, body, "\"application/jose+json\"");
		if (response == nullptr)
			throw Utils::APINoResponseException("API did not response.");
		else if (response->status == 200)
		{
			Json::Value jsonResult;
			Utils::StringProcess::StringToJson(response->body, &jsonResult);
			
			Json::Value challs = jsonResult["challenges"];
			/* Get dns record name */
			std::string baseDomain = Utils::Domain::ExtractBaseDomain(jsonResult["identifier"]["value"].asString());
			std::string recordName = jsonResult["identifier"]["value"].asString();
			if (recordName == baseDomain)     /* If it doesn't have third-level domain */
				recordName = "_acme-challenge";
			else    /* Has third-level domain */
			{
				recordName = std::regex_replace(recordName, std::regex(baseDomain), "");
				recordName.pop_back();  /* Remove '.' at the end of the domain part */
				recordName = std::string("_acme-challenge.").append(recordName);
			}
			for (auto chall : challs)
			{
				if (chall["type"].asString() != challengeType)
					continue;
				/* Get challenge id path */
				std::string challIDPath = chall["url"].asString();
				challIDPath = std::regex_replace(challIDPath, std::regex("https://" + uri), "");
				/* Get keyAuthorization: token + '.' + base64url(Thumbprint(accountKey)) */
				std::string token = chall["token"].asString();
				std::string finalToken = getFinalToken(token);
				Json::Value item;
				item["challIDPath"] = challIDPath;
				item["finalToken"] = finalToken;
				item["dnsRecordName"] = recordName;
				challenges.append(item);
				break;
			}
		}
		else throw Utils::APIRequestException("API returns http code " + std::to_string(response->status) + ": " + std::regex_replace(response->body, std::regex("\n"), ""));
	}
	return challenges;
}

std::vector<std::string> Acme::API::updateTXTsRecord(const std::shared_ptr<DNS::API>& dnsAPI, const Json::Value& challs)
{
	std::vector<std::string> dnsRecordIDs;
	try
	{
		for (const auto& chall : challs)
		{
			std::string id = dnsAPI->addTxtRecord(chall["dnsRecordName"].asString(), chall["finalToken"].asString());
			dnsRecordIDs.push_back(id);
		}
	}
	catch (Utils::APIRequestException& e)
	{
		deleteTXTsRecord(dnsAPI, dnsRecordIDs, true);
		throw Utils::APIRequestException("Errors while updating DNS record");
	}
	return dnsRecordIDs;
}

void Acme::API::deleteTXTsRecord(const std::shared_ptr<DNS::API>& dnsAPI, const std::vector<std::string>& ids, bool throwException)
{
	try
	{
		for (const auto& id : ids)
			dnsAPI->deleteRecord(id);
	}
	catch (Utils::APIRequestException& e)
	{
		if (throwException)
			throw Utils::APIRequestException("Errors while clean up DNS record, manually deletion may be required.");
	}
	catch (Utils::APINoResponseException& e)
	{
		if (throwException)
			throw Utils::APIRequestException("Errors while clean up DNS record, API doesn't respond.");
	}
}

void Acme::API::respondChallenges(const std::string& accountIDPath, const Json::Value& challs)
{
	for (const auto& chall : challs)
	{
		std::string nonce = newNonce();
		/* Base64url encoded 'protected' */
		std::string protectedStr = createProtectedMessage(accountIDPath, nonce, chall["challIDPath"].asString());
		std::string protectedB64Url = Utils::Codec::Base64UrlEncode(protectedStr);
		/* Base64Url encoded 'payload' */
		std::string payloadB64Url = Utils::Codec::Base64UrlEncode("{}");
		/* Perform RS256 */
		auto payload = Utils::StringProcess::StringToByteVec(protectedB64Url + "." + payloadB64Url);
		auto signature = OpensslWrap::AsymmetricRSA::RS256(payload, accountPrivateKey);
		auto sigB64Url = Utils::Codec::Base64UrlEncode(signature);
		
		/* Create post body */
		std::string body = createPostBody(protectedB64Url, payloadB64Url, sigB64Url);
		
		/* Request */
		auto response = cli->Post(chall["challIDPath"].asString().c_str(), defaultHeader, body, "\"application/jose+json\"");
		if (response == nullptr)
			throw Utils::APINoResponseException("API did not response.");
		else if (response->status != 200)
			throw Utils::APIRequestException("API returns http code " + std::to_string(response->status) + ": " + std::regex_replace(response->body, std::regex("\n"), ""));
	}
}

std::string Acme::API::getOrderStatus(const std::string& accountIDPath, const std::string& orderIDPath)
{
	std::string nonce = newNonce();
	/* Base64url encoded 'protected' */
	std::string protectedStr = createProtectedMessage(accountIDPath, nonce, orderIDPath);
	std::string protectedB64Url = Utils::Codec::Base64UrlEncode(protectedStr);
	/* Perform RS256 */
	auto payload = Utils::StringProcess::StringToByteVec(protectedB64Url + ".");
	auto signature = OpensslWrap::AsymmetricRSA::RS256(payload, accountPrivateKey);
	auto sigB64Url = Utils::Codec::Base64UrlEncode(signature);
	
	/* Create post body */
	std::string body = createPostBody(protectedB64Url, "", sigB64Url);
	
	/* Request */
	auto response = cli->Post(orderIDPath.c_str(), defaultHeader, body, "\"application/jose+json\"");
	if (response == nullptr)
		throw Utils::APINoResponseException("API did not response.");
	else if (response->status == 200)
	{
		Json::Value jsonResult;
		Utils::StringProcess::StringToJson(response->body, &jsonResult);
		std::string status = jsonResult["status"].asString();
		return status;
	}
	else throw Utils::APIRequestException("API returns http code " + std::to_string(response->status) + ": " + std::regex_replace(response->body, std::regex("\n"), ""));
}

std::string Acme::API::getAuthzStatus(const std::string& accountIDPath, const std::string& authzIDPath)
{
	std::string nonce = newNonce();
	/* Base64url encoded 'protected' */
	std::string protectedStr = createProtectedMessage(accountIDPath, nonce, authzIDPath);
	std::string protectedB64Url = Utils::Codec::Base64UrlEncode(protectedStr);
	/* Perform RS256 */
	auto payload = Utils::StringProcess::StringToByteVec(protectedB64Url + ".");
	auto signature = OpensslWrap::AsymmetricRSA::RS256(payload, accountPrivateKey);
	auto sigB64Url = Utils::Codec::Base64UrlEncode(signature);
	
	/* Create post body */
	std::string body = createPostBody(protectedB64Url, "", sigB64Url);
	
	/* Request */
	auto response = cli->Post(authzIDPath.c_str(), defaultHeader, body, "\"application/jose+json\"");
	if (response == nullptr)
		throw Utils::APINoResponseException("API did not response.");
	else if (response->status == 200)
	{
		Json::Value jsonResult;
		Utils::StringProcess::StringToJson(response->body, &jsonResult);
		std::string status = jsonResult["status"].asString();
		return status;
	}
	else throw Utils::APIRequestException("API returns http code " + std::to_string(response->status) + ": " + std::regex_replace(response->body, std::regex("\n"), ""));
}

std::string Acme::API::getFinalToken(const std::string& challengeToken)
{
	/* Get e, n from public key */
	auto publicKey = OpensslWrap::AsymmetricRSA::DumpPublicKey(accountPrivateKey);
	const BIGNUM* n = nullptr;  const BIGNUM* e = nullptr;  const BIGNUM* d = nullptr;
	RSA_get0_key(publicKey.get(), &n, &e, &d);
	
	/* e, n to std::string */
	auto* nRaw = (unsigned char*)malloc(BN_num_bytes(n));
	if (!nRaw)
		throw Utils::AllocateMemoryFailed("Allocate memory failed");
	auto* eRaw = (unsigned char*)malloc(BN_num_bytes(e));
	if (!eRaw)
	{
		free(nRaw);
		throw Utils::AllocateMemoryFailed("Allocate memory failed");
	}
	BN_bn2bin(n, nRaw);
	BN_bn2bin(e, eRaw);
	std::string nStr = Utils::Codec::Base64UrlEncode(
			std::make_shared<std::vector<std::byte>>((std::byte*)nRaw, (std::byte*)nRaw+BN_num_bytes(n))
	);
	std::string eStr = Utils::Codec::Base64UrlEncode(
			std::make_shared<std::vector<std::byte>>((std::byte*)eRaw, (std::byte*)eRaw+BN_num_bytes(e))
	);
	free(nRaw);
	free(eRaw);
	
	/* Create payload */
	Json::Value payload;
	payload["e"] = eStr;
	payload["kty"] = "RSA";
	payload["n"] = nStr;
	std::string payloadStr = payload.toStyledString();
	payloadStr = std::regex_replace(payloadStr, std::regex("\n"), "");
	payloadStr = std::regex_replace(payloadStr, std::regex("\\s"), "");
	payloadStr = std::regex_replace(payloadStr, std::regex("\t"), "");
	
	/* Create accountKey thumbprint */
	auto thumbprint = OpensslWrap::Digest::SHA256(Utils::StringProcess::StringToByteVec(payloadStr));
	auto thumbprintB64Url = Utils::Codec::Base64UrlEncode(thumbprint);
	
	/* Create final token */
	std::string concatenated = challengeToken + "." + thumbprintB64Url;
	auto digest = OpensslWrap::Digest::SHA256(Utils::StringProcess::StringToByteVec(concatenated));
	std::string finalToken = Utils::Codec::Base64UrlEncode(digest);
	
	return finalToken;
}
std::string Acme::API::finalizeOrder(const std::string& accountIDPath, const std::string& orderFinalizePath,
                                     const std::string& csrPEMString
)
{
	std::string nonce = newNonce();
	/* Base64url encoded 'protected' */
	std::string protectedStr = createProtectedMessage(accountIDPath, nonce, orderFinalizePath);
	std::string protectedB64Url = Utils::Codec::Base64UrlEncode(protectedStr);
	/* Base64Url encoded 'payload' */
	std::string payloadStr = R"({"csr": ")" + csrPEMString + "\"}";
	std::string payloadB64Url = Utils::Codec::Base64UrlEncode(payloadStr);
	
	/* Perform RS256 */
	auto payload = Utils::StringProcess::StringToByteVec(protectedB64Url + "." + payloadB64Url);
	auto signature = OpensslWrap::AsymmetricRSA::RS256(payload, accountPrivateKey);
	auto sigB64Url = Utils::Codec::Base64UrlEncode(signature);
	
	/* Create post body */
	std::string body = createPostBody(protectedB64Url, payloadB64Url, sigB64Url);
	
	/* Request */
	auto response = cli->Post(orderFinalizePath.c_str(), defaultHeader, body, "\"application/jose+json\"");
	if (response == nullptr)
		throw Utils::APINoResponseException("API did not response.");
	else if (response->status == 200)
	{
		Json::Value jsonResult;
		Utils::StringProcess::StringToJson(response->body, &jsonResult);
		std::string certificateIDPath = jsonResult["certificate"].asString();
		certificateIDPath = std::regex_replace(certificateIDPath, std::regex("https://" + uri), "");
		return certificateIDPath;
	}
	else throw Utils::APIRequestException("API returns http code " + std::to_string(response->status) + ": " + std::regex_replace(response->body, std::regex("\n"), ""));
}

std::string Acme::API::downloadCertificate(const std::string& accountIDPath, const std::string& certificateIDPath)
{
	std::string nonce = newNonce();
	/* Base64url encoded 'protected' */
	std::string protectedStr = createProtectedMessage(accountIDPath, nonce, certificateIDPath);
	std::string protectedB64Url = Utils::Codec::Base64UrlEncode(protectedStr);
	/* Perform RS256 */
	auto payload = Utils::StringProcess::StringToByteVec(protectedB64Url + ".");
	auto signature = OpensslWrap::AsymmetricRSA::RS256(payload, accountPrivateKey);
	auto sigB64Url = Utils::Codec::Base64UrlEncode(signature);
	
	/* Create post body */
	std::string body = createPostBody(protectedB64Url, "", sigB64Url);
	
	/* Request */
	auto response = cli->Post(certificateIDPath.c_str(), defaultHeader, body, "\"application/jose+json\"");
	if (response == nullptr)
		throw Utils::APINoResponseException("API did not response.");
	else if (response->status == 200)
	{
		return response->body;
	}
	else throw Utils::APIRequestException("API returns http code " + std::to_string(response->status) + ": " + std::regex_replace(response->body, std::regex("\n"), ""));
}

std::tuple<std::string, std::string, std::string> Acme::API::issueCertificate()
{
#define MAX_ATTEMPT_NUMBER 5
#define AWAITING_SECONDS 5
	int attempts = 0;
	std::string fullchainPEM;
	std::shared_ptr<RSA> certPrivateKey = nullptr;
	std::vector<std::string> dnsRecordIDs;
	std::shared_ptr<DNS::API> dnsAPI = nullptr;
	std::exception_ptr exceptionPtr;
	try
	{
		/* Step 1: Get directory */
		LOG(INFO) << "ACME - Getting acme directory.";
		directory();
		
		/* Step 2: Create an acme account */
		LOG(INFO) << "ACME - Creating account.";
		std::string accountIDPath = newAccount(accountContacts);
		LOG(INFO) << "ACME - Account path is " << accountIDPath << ".";
		
		/* Step 3: Create an order */
		LOG(INFO) << "ACME - Creating order.";
		Json::Value newOrderRet = newOrder(accountIDPath, domains);
		std::string orderIDPath = newOrderRet["orderIDPath"].asString();
		LOG(INFO) << "ACME - Order path is " << orderIDPath << ".";
		std::string orderFinalizePath = newOrderRet["orderFinalizePath"].asString();
		LOG(INFO) << "ACME - Order finalize path is " << orderIDPath << ".";
		std::vector<std::string> authzIDsPaths;
		for (const auto& id : newOrderRet["authzIDsPath"])
			authzIDsPaths.push_back(id.asString());
		
		/* Step 4: Fetch challenges */
		LOG(INFO) << "ACME - Fetching challenges.";
		Json::Value challenges = fetchChallenges(accountIDPath, authzIDsPaths);
		LOG(INFO) << "ACME - Final tokens of challenges are ready.";
		
		if (challengeType == "dns-01")
		{
			LOG(INFO) << "ACME - Using dns-01 challenge type.";
			Json::Value apiParams;
			apiParams["email"] = globalConfigs["server"]["acme"]["challenge"]["dns_settings"]["email"];
			apiParams["zoneID"] = globalConfigs["server"]["acme"]["challenge"]["dns_settings"]["zone_id"];
			apiParams["globalApiKey"] = globalConfigs["server"]["acme"]["challenge"]["dns_settings"]["global_api_key"];
			dnsAPI = DNS::API::create(
					globalConfigs["server"]["acme"]["challenge"]["dns_settings"]["provider"].asString(), apiParams);
			LOG(INFO) << "ACME - Updating DNS txt record to " << dnsAPI->providerName << ".";
			dnsRecordIDs = updateTXTsRecord(dnsAPI, challenges);
			LOG(INFO) << "ACME - DNS records updated, wait " << AWAITING_SECONDS << " seconds for DNS cache refresh.";
			sleep(AWAITING_SECONDS);
		}
		
		/* Step 5: Tell the acme server it's ok to validate */
		LOG(INFO) << "ACME - Requesting acme server to validate challenges.";
		respondChallenges(accountIDPath, challenges);
		LOG(INFO) << "ACME - Validate request was received by acme server, wait " << AWAITING_SECONDS
		          << " seconds for validation.";
		sleep(AWAITING_SECONDS);
		
		/* Step 6: Poll if order status is ready (challenges accepted by acme server) */
		for (attempts = 0; attempts < MAX_ATTEMPT_NUMBER; attempts++)
		{
			LOG(INFO) << "ACME - Attempt to fetch order status for " << std::to_string(attempts + 1) << " time(s).";
			std::string status = getOrderStatus(accountIDPath, orderIDPath);
			if (status == "ready")
			{
				LOG(INFO) << "ACME - Order status is " << status << ", challenges validated.";
				break;
			}
			else if (status == "pending")
			{
				LOG(INFO) << "ACME - Order status is " << status << ", wait " << AWAITING_SECONDS
				          << " seconds for the next attempt.";
				sleep(AWAITING_SECONDS);
				continue;
			}
			else if (status == "invalid")
				throw Utils::APIRequestException("ACME - Order status is " + status + ", challenges not accepted, new certificate request failed.");
		}
		if (attempts == MAX_ATTEMPT_NUMBER)
			throw Utils::APIRequestException("ACME - Maximum number of attempt reached, challenges still not validated by the acme server, new certificate request failed.");
		else if (challengeType == "dns-01")
		{
			LOG(INFO) << "ACME - Cleaning up DNS records.";
			deleteTXTsRecord(dnsAPI, dnsRecordIDs, true);
		}
		
		/* Step 7: Finalize order */
		LOG(INFO) << "ACME - Creating RSA key for new certificate.";
		certPrivateKey = OpensslWrap::AsymmetricRSA::Create(4096);
		LOG(INFO) << "ACME - Creating X509 CSR.";
		auto x509req = OpensslWrap::CreateSANCertificateSigningRequest(baseDomainName, domains, certPrivateKey);
		auto csrDER = OpensslWrap::X509reqToDER(x509req);
		LOG(INFO) << "ACME - Requesting order finalization.";
		std::string certificateIDPath = finalizeOrder(accountIDPath, orderFinalizePath, Utils::Codec::Base64UrlEncode(csrDER));
		LOG(INFO) << "ACME - Order finalize request was received by the acme server.";
		
		/* Step 8: Poll if order status is valid (ready to download new certificate) */
		for (attempts = 0; attempts < MAX_ATTEMPT_NUMBER; attempts++)
		{
			LOG(INFO) << "ACME - Attempt to fetch order status for " << std::to_string(attempts + 1) << " time(s).";
			std::string status = getOrderStatus(accountIDPath, orderIDPath);
			if (status == "valid")
			{
				LOG(INFO) << "ACME - Order status is " << status << " ,certificate is being issued.";
				break;
			}
			else if (status == "processing")
			{
				LOG(INFO) << "ACME - Order status is " << status << ", wait " << AWAITING_SECONDS
				          << " seconds for the next attempt.";
				sleep(AWAITING_SECONDS);
				continue;
			}
			else if (status == "invalid")
				throw Utils::APIRequestException("ACME - Order status is " + status + ", new certificate request failed.");
		}
		if (attempts == MAX_ATTEMPT_NUMBER)
			throw Utils::APIRequestException("ACME - Maximum number of attempt reached, certificate still not be issued, new certificate request failed.");
		
		/* Step 9: Download certificates */
		LOG(INFO) << "ACME - Downloading certificates.";
		fullchainPEM = downloadCertificate(accountIDPath, certificateIDPath);
		LOG(INFO) << "ACME - Successfully downloaded.";
	}
	catch (Utils::AllocateMemoryFailed& e)
	{
		LOG(ERROR) << "ACME - " << e.what();
		if (!dnsRecordIDs.empty()) { deleteTXTsRecord(dnsAPI, dnsRecordIDs, false); }
		throw IssueCertificateFailed();
	}
	catch (Utils::APINoResponseException& e)
	{
		LOG(ERROR) << "ACME - " << e.what();
		if (!dnsRecordIDs.empty()) { deleteTXTsRecord(dnsAPI, dnsRecordIDs, false); }
		throw IssueCertificateFailed();
	}
	catch (Utils::APIRequestException& e)
	{
		LOG(ERROR) << "ACME - " << e.what();
		if (!dnsRecordIDs.empty()) { deleteTXTsRecord(dnsAPI, dnsRecordIDs, false); }
		throw IssueCertificateFailed();
	}
	auto parts = Utils::StringProcess::SplitString(fullchainPEM,"\n\n");
	auto certPrivateKeyPKCS8 = OpensslWrap::AsymmetricRSA::PrivateKeyToPKCS8(certPrivateKey);
	
	return std::make_tuple(parts.at(0), parts.at(1), certPrivateKeyPKCS8);
}
