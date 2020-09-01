//
// Created by nova on 8/2/20.
//

#ifndef ACMED_ACME_H
#define ACMED_ACME_H

#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <openssl/bn.h>
#include "DNS.h"
#include "CertCache.h"
#include "../utils/OpensslWrap.h"
#include "../utils/Codes.h"
#include "../utils/jsoncpp/include/json/json.h"
#include "../utils/cpp-httplib/httplib.h"
#include "../utils/easyloggingpp/src/easylogging++.h"

namespace Acme
{
	/* Supported Acme challenge types */
	bool ChallengeTypeIsSupported(const std::string& method);
	const std::vector<std::string>& SupportedChallengeTypes();
	
	/* Supported CA */
	bool CAIsSupported(const std::string& caName);
	const std::map<std::string, std::string>& SupportedCAList();    /* Returns <caName, api> */
	const std::map<std::string, std::string>& CADirectoryPath();    /* Returns <caName, directory path> */
	
	class API
	{
	public:
		/* Exceptions: CertificateAuthorityNotSupportedException() */
		explicit API(const Json::Value& globalConfigs);
		~API() = default;
		/* Return tuple: endEntityCertPEM, issuerCertPEM, privateKeyPKCS8
		 * Exceptions: IssueCertificateFailed() */
		[[nodiscard]] std::tuple<std::string, std::string, std::string> issueCertificate();
		
	private:
		/*
		 * Request sequences
		 */
		void directory();   /* Exceptions: APINoResponseExceptions() */
		std::string newNonce();     /* Exceptions: APINoResponseExceptions() */
		/* Returns: Account ID path
		 * Example: /acme/acct/{id}
		 * Exceptions: Utils::AllocateMemoryFailed()
		 *             APIRequestException()
		 *             APINoResponseExceptions() */
		std::string newAccount(const std::vector<std::string>& contacts);
		/* Returns Json format:
		 * {
		 *    "orderIDPath": "/acme/order/{accountID}/{orderID}",
		 *    "authzIDsPath": [ "/acme/authz/{authzID}", "/acme/authz/{authzID}" ],
		 *    "orderFinalizePath": "/acme/finalize/{accountID}/{orderID}"
		 * }
		 * Exceptions: APIRequestException()
		 *             APINoResponseExceptions() */
		Json::Value newOrder(const std::string& accountIDPath, const std::vector<std::string>& domainsList);
		/* Returns challenge ID and tokens
		 * Example:
		 * [
		 *     {
		 *         "challIDPath": "/acme/chall-v3/authzID/challID",
		 *         "dnsRecordName": "_acme_challenge.example",
		 *         "finalToken": "{finalToken}",
		 *     }
		 * ]
		 * Exceptions: APIRequestException()
		 *             APINoResponseExceptions() */
		Json::Value fetchChallenges(const std::string& accountIDPath, const std::vector<std::string>& authzIDsPath);
		std::string getFinalToken(const std::string& token);    /* Exceptions: Utils::AllocateMemoryFailed() */
		/* Only used with dns-01 type
		 * Returns dns record id
		 * Exceptions: APIRequestException()
		 *             APINoResponseExceptions() */
		std::vector<std::string> updateTXTsRecord(const std::shared_ptr<DNS::API>& dnsAPI, const Json::Value& challs);
		/* Only used with dns-01 type
		 * Returns dns record id
		 * Exceptions: APIRequestException()
		 *             APINoResponseExceptions() */
		void deleteTXTsRecord(const std::shared_ptr<DNS::API>& dnsAPI, const std::vector<std::string>& ids, bool throwException);
		/* Returns false if on of the challenge not verified by acme server.
		 * Exceptions: APIRequestException()
		 *             APINoResponseExceptions() */
		void respondChallenges(const std::string& accountIDPath, const Json::Value& challs);
		std::string getOrderStatus(const std::string& accountIDPath, const std::string& orderIDPath);
		[[maybe_unused]] std::string getAuthzStatus(const std::string& accountIDPath, const std::string& authzIDPath);
		std::string finalizeOrder(const std::string& accountIDPath, const std::string& orderFinalizePath, const std::string& csrPEMString);
		std::string downloadCertificate(const std::string& accountIDPath, const std::string& certificateIDPath);
		/* Components of API urls */
		std::string uri;
		Json::Value rootDirectory;
		std::string pathDirectory;
		/* Common variables */
		Json::Value globalConfigs;
		std::string baseDomainName;
		std::string caName;
		std::string challengeType;
		std::shared_ptr<RSA> accountPrivateKey;
		std::vector<std::string> accountContacts;
		std::vector<std::string> domains;
		/* https */
		httplib::Headers defaultHeader;
		std::unique_ptr<httplib::SSLClient> cli;
		/* Duplicated code generator */
		std::string createProtectedMessage(const std::string& kidPart, const std::string& nonce, const std::string& urlPart);
		std::string createPostBody(const std::string& protectedB64Url, const std::string& payloadB64Url, const std::string& signatureB64Url);
	};
	
	class IssueCertificateFailed : std::exception {};
	
	class CertificateAuthorityNotSupportedException : std::exception
	{
	public:
		CertificateAuthorityNotSupportedException() = default;
		explicit CertificateAuthorityNotSupportedException(std::string str) : message(std::move(str)) {}
		~CertificateAuthorityNotSupportedException() noexcept override = default;;
		[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
	
	private:
		std::string message;
	};
};

#endif //ACMED_ACME_H
