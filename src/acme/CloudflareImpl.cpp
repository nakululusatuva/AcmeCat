//
// Created by nova on 9/4/20.
//

#include "CloudflareImpl.h"

DNS::CloudflareImpl::CloudflareImpl(const Json::Value& apiParams)
{
	providerName = "Cloudflare";
	email = apiParams["email"].asString();
	zoneId = apiParams["zoneID"].asString();
	globalApiKey = apiParams["globalApiKey"].asString();

#ifdef __linux__
	client.set_ca_cert_path("/etc/ssl/certs/ca-certificates.crt");
#endif
	client.enable_server_certificate_verification(true);
	client.set_read_timeout(20, 0); // 20 seconds
	client.set_write_timeout(20, 0); // 20 seconds
	
	defaultHeader = httplib::Headers
			{
					{"X-Auth-Email", email},
					{"X-Auth-Key", globalApiKey},
					{"Content-Type", "application/json"}
			};
}

Json::Value DNS::CloudflareImpl::getAllRecords()
{
	/* Append parameters to path */
	std::string path = std::regex_replace(urlPath, std::regex("\\?"), zoneId) + "/?per_page=" + std::to_string(recordsPerPage);
	
	/* Request */
	auto response = client.Get(path.c_str(), defaultHeader);
	if (response == nullptr)
		throw Utils::APINoResponseException("DNS provider's API called but did not respond.");
	
	Json::CharReaderBuilder builder;
	Json::CharReader* reader = builder.newCharReader();
	Json::Value jsonResult;
	std::string jsonParseErrors;
	auto jsonParseOk = reader->parse(response->body.c_str(), response->body.c_str() + response->body.size(), &jsonResult, &jsonParseErrors);
	delete reader;
	if (!jsonParseOk)
		throw Utils::APIRequestException("error(s) while parsing json string from api's response, " + jsonParseErrors);
	
	else if (!jsonResult["success"].asBool())    /* If api response success code */
		throw Utils::APIRequestException("DNS provider's API response error.");
	
	/* Every thing is ok, get records from all pages */
	Json::Value ret = apiResponseReformat(jsonResult);  /* Cache the first page */
	int totalPageCount = jsonResult["result_info"]["total_pages"].asInt();
	if (totalPageCount > 1)
	{
		for (int i = 2; i <= totalPageCount; ++i)   /* Start from the second page */
		{
			Json::Value pageRecord = getRecordsAtPage(i);
			for (const auto& r : pageRecord["records"])
				ret["records"].append(r);
		}
	}
	return ret;
}

Json::Value DNS::CloudflareImpl::getRecordsAtPage(int pageNum)
{
	/* Append parameters to path */
	std::string path = std::regex_replace(urlPath, std::regex("\\?"), zoneId) + "/?page=" + std::to_string(pageNum) + "&per_page=" + std::to_string(recordsPerPage);
	
	/* requestCert */
	auto response = client.Get(path.c_str(), defaultHeader);
	if (response == nullptr)
		throw Utils::APINoResponseException("DNS provider's API called but did not respond.");
	
	Json::CharReaderBuilder builder;
	Json::CharReader* reader = builder.newCharReader();
	Json::Value jsonResult;
	std::string jsonParseErrors;
	auto jsonParseOk = reader->parse(response->body.c_str(), response->body.c_str() + response->body.size(), &jsonResult, &jsonParseErrors);
	delete reader;
	if (jsonParseOk)    /* If response parse to json successfully */
	{
		if (!jsonResult["success"].asBool())    /* If api response success code */
			throw Utils::APIRequestException("DNS provider's API response error.");
		else return apiResponseReformat(jsonResult); /* Every thing is ok, return */
	}
	else throw Utils::APIRequestException("error(s) while parsing json string from api's response, " + jsonParseErrors);
}

Json::Value DNS::CloudflareImpl::apiResponseReformat(const Json::Value& response)
{
	Json::Value formatted;
	formatted["records"] = Json::arrayValue;
	for (const auto& record : response["result"])
	{
		Json::Value item;
		item["id"] = record["id"];
		item["type"] = record["type"];
		item["name"] = record["name"];
		item["content"] = record["content"];
		item["ttl"] = record["ttl"];
		formatted["records"].append(item);
	}
	return formatted;
}

std::string DNS::CloudflareImpl::addTxtRecord(const std::string& name, const std::string& content)
{
	/* Append parameters to path */
	std::string path = std::regex_replace(urlPath, std::regex("\\?"), zoneId);
	
	/* Create body */
	std::string body = R"({"type": "txt", "name": ")" + name + R"(", "content": ")" + content + R"(", "ttl": 120})";
	
	/* requestCert */
	auto response = client.Post(path.c_str(), defaultHeader, body, "application/json");
	if (response == nullptr)
		throw Utils::APINoResponseException("DNS provider's API called but did not respond.");
	
	Json::CharReaderBuilder builder;
	Json::CharReader* reader = builder.newCharReader();
	Json::Value jsonResult;
	std::string errs;
	auto jsonParseOk = reader->parse(response->body.c_str(), response->body.c_str() + response->body.size(), &jsonResult, &errs);
	delete reader;
	if (jsonParseOk)    /* If response parse to json successfully */
	{
		if (!jsonResult["success"].asBool())    /* If api response success code */
			throw Utils::APIRequestException("DNS provider's API response error.");
		else return jsonResult["result"]["id"].asString();
	}
	else throw Utils::APIRequestException("error(s) while parsing json string from api's response.");
}

void DNS::CloudflareImpl::deleteRecord(const std::string &recordId)
{
	/* Append parameters to path */
	std::string path = std::regex_replace(urlPath, std::regex("\\?"), zoneId) + "/" + recordId;
	
	/* requestCert */
	auto response = client.Delete(path.c_str(), defaultHeader);
	if (response == nullptr)
		throw Utils::APINoResponseException("DNS provider's API called but did not respond.");
	
	Json::CharReaderBuilder builder;
	Json::CharReader* reader = builder.newCharReader();
	Json::Value jsonResult;
	std::string errs;
	auto jsonParseOk = reader->parse(response->body.c_str(), response->body.c_str() + response->body.size(), &jsonResult, &errs);
	delete reader;
	if (jsonParseOk)    /* If response parse to json successfully */
	{
		if (!jsonResult["success"].asBool())    /* If api response success code */
			throw Utils::APIRequestException("DNS provider's API response error.");
	}
	else throw Utils::APIRequestException("error(s) while parsing json string from api's response.");
}

void DNS::CloudflareImpl::updateRecord(const std::string& recordId, const std::string& newName, const std::string& newType, const std::string &newContent)
{
	/* Append parameters to path */
	std::string path = std::regex_replace(urlPath, std::regex("\\?"), zoneId) + "/" + recordId;
	
	/* Create body */
	std::string body = R"({"type": ")" + newType + R"(" , "name": ")" + newName + R"(", "content": ")" + newContent + R"(", "ttl": 120})";
	
	/* requestCert */
	auto response = client.Put(path.c_str(), defaultHeader, body, "application/json");
	if (response == nullptr)
		throw Utils::APINoResponseException("DNS provider's API called but did not respond.");
	
	Json::CharReaderBuilder builder;
	Json::CharReader* reader = builder.newCharReader();
	Json::Value jsonResult;
	std::string errs;
	auto jsonParseOk = reader->parse(response->body.c_str(), response->body.c_str() + response->body.size(), &jsonResult, &errs);
	delete reader;
	if (jsonParseOk)    /* If response parse to json successfully */
	{
		if (!jsonResult["success"].asBool())    /* If api response success code */
			throw Utils::APIRequestException("DNS provider's API response error.");
	}
	else throw Utils::APIRequestException("error(s) while parsing json string from api's response.");
}