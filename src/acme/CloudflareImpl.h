//
// Created by nova on 9/4/20.
//

#ifndef ACMECAT_CLOUDFLAREIMPL_H
#define ACMECAT_CLOUDFLAREIMPL_H

#include "DNS.h"

namespace DNS
{
	/* Implementation of cloudflare's API */
	class CloudflareImpl : public DNS::API
	{
	public:
		/* Structure of 'apiParams':
		 * {
		 *     "email": "",
		 *     "zoneId": "",
		 *     "globalApiKey": ""
		 * } */
		explicit CloudflareImpl(const Json::Value& apiParams);
		~CloudflareImpl() = default;
		
		/* Exceptions: APIRequestException()
		 *             APINoResponseException() */
		Json::Value getAllRecords() override;
		/* Exceptions: APIRequestException()
		 *             APINoResponseException() */
		std::string addTxtRecord(const std::string& name, const std::string& content) override;
		/* Exceptions: APIRequestException()
		 *             APINoResponseException() */
		void deleteRecord(const std::string& recordId) override;
		/* Exceptions: APIRequestException()
		 *             APINoResponseException() */
		void updateRecord(const std::string &recordId, const std::string& newName, const std::string& newType, const std::string& newContent) override;
	
	private:
		unsigned short recordsPerPage = 100;
		/* Exceptions: APIRequestException()
		 *             APINoResponseException() */
		Json::Value getRecordsAtPage(int pageNum);
		static Json::Value apiResponseReformat(const Json::Value& response);
		
		std::string email;
		std::string zoneId;
		std::string globalApiKey;
		
		const std::string urlBase = "api.cloudflare.com";
		const std::string urlPath = "/client/v4/zones/?/dns_records";
		httplib::SSLClient client = httplib::SSLClient(urlBase, 443);
		httplib::Headers defaultHeader;
	};
}

#endif //ACMECAT_CLOUDFLAREIMPL_H
