//
// Created by nova on 8/2/20.
//

#ifndef ACMED_DNS_H
#define ACMED_DNS_H

#include <map>
#include <string>
#include <utility>
#include <vector>
#include <algorithm>
#include <iostream>
#include "../utils/Utils.h"
#include "../utils/jsoncpp/include/json/json.h"
#include "../utils/cpp-httplib/httplib.h"

namespace DNS
{
	/* Supported DNS providers */
	bool ProviderIsSupported(const std::string& providerName);
	const std::vector<std::string>& SupportedProviders();
	
	/* Base class of all providers */
	class API
	{
	public:
		/* Order and meaning of API's parameters:
		 * Cloudflare: <email, zoneId, globalApiKey> */
		static std::shared_ptr<DNS::API> create(const std::string& providerName, const Json::Value& apiParams);
		
		/* Exceptions: APIRequestException()
		 *             APINoResponseException()
		 * Returned JSON format:
		 * { "records": [ {"id": "", "type": "", "name": "", "content": "", "ttl": 0}, ... ] }*/
		virtual Json::Value getAllRecords() = 0;
		
		/* Exceptions: APIRequestException()
		 *             APINoResponseException()
		 * Return: New record's ID */
		virtual std::string addTxtRecord(const std::string& name, const std::string& content) = 0;
		
		/* Exceptions: APIRequestException()
		 *             APINoResponseException() */
		virtual void deleteRecord(const std::string& recordId) = 0;
		
		/* Exceptions: APIRequestException()
		 *             APINoResponseException() */
		virtual void updateRecord(const std::string &recordId, const std::string& newName, const std::string& newType, const std::string& newContent) = 0;
	
		std::string providerName;
	};
	
	class ProviderNotSupportedException : std::exception
	{
	public:
		ProviderNotSupportedException() = default;
		explicit ProviderNotSupportedException(std::string str) : message(std::move(str)) {}
		~ProviderNotSupportedException() noexcept override = default;;
		[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
	
	private:
		std::string message;
	};
}

#endif //ACMED_DNS_H
