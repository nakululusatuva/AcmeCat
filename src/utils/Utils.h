//
// Created by nova on 8/19/20.
//

#ifndef ACMECAT_UTILS_H
#define ACMECAT_UTILS_H

#include <iostream>
#include <string>
#include <memory>
#include <algorithm>
#include <chrono>
#include <regex>
#include <filesystem>
#include "jsoncpp/include/json/json.h"

namespace Utils
{
	static const union { char c[4]; unsigned long l; }endian_test = { { 'L', '?', '?', 'B' } };
	inline char Endianness() { return (char)Utils::endian_test.l; }
	
	bool EmailIsValid(const std::string& email);
	int ExecuteShell(const std::string& command);
	std::vector<std::string> getSubDirsName(const std::string& dir);
	
	/* 1 - Struct types in openssl such as RSA(rsa_st) contain pointers that point to another heap memory
	 * and have their own delete function like RSA_free(RSA* ptr).
	 * 2 - Smart pointer created with bare pointer also needs a custom deleter. */
	template<auto FreeFunc> struct Deleter { template<class T> void operator()(T* ptr) { FreeFunc(ptr); } };
	
	namespace Time
	{
		/* UTC time zone range: -12 ~ +14 */
		std::string UnixTimeToRFC3339(long utcTime, int timeZone);
		/* Return time zone offset, from -12 to +14 */
		int localTimeZoneUTC();
	}
	
	namespace StringProcess
	{
		std::string ToLowerCase(const std::string& str);
		std::shared_ptr<std::vector<std::byte>> StringToByteVec(const std::string& str);
		std::string ByteVecToString(const std::shared_ptr<const std::vector<std::byte>>& vec);
		std::vector<std::string> SplitString(const std::string& s, char delimiter);
		std::vector<std::string> SplitString(const std::string& s, const std::string& delimiter);
		std::string StringToJson(const std::string& jString, Json::Value* json);
	}
	
	namespace Codec
	{
		const char base64UrlTable[] =
		{
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
		};
		std::string Base64UrlEncode(const std::string& in);
		std::string Base64UrlDecode(const std::string& in);
		std::string Base64UrlEncode(const std::shared_ptr<const std::vector<std::byte>>& in);
		std::string Base64UrlDecode(const std::shared_ptr<const std::vector<std::byte>>& in);
	}
	
	namespace Domain
	{
		bool RootZoneIsValid(const std::string& zone);
		const std::vector<std::string>& RootZones();
		std::string ExtractBaseDomain(const std::string& domain);   /* Return base like 'example.com' */
		bool IsValid(const std::string& domain, bool enableWildcard);
		/* "www.example.com" to "example.com"
		 * If ignoreWildcardAsterisk is false, wildcard asterisk will also be considered as a domain.
		 * If ignoreWildcardAsterisk is true,
		 * only the domain behind the wildcard asterisk will be considered as lowest domain,
		 * for example: "*.test.example.com" to "example.com" */
		std::string RemoveLowestLevelSub(const std::string& domainName, bool ignoreWildcardAsterisk);
		bool IsWildcard(const std::string& domainName);
	}
	
	class AllocateMemoryFailed : std::exception
	{
	public:
		AllocateMemoryFailed() = default;
		explicit AllocateMemoryFailed(std::string str) : message(std::move(str)) {}
		~AllocateMemoryFailed() noexcept override = default;;
		[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
	
	private:
		std::string message;
	};
	
	class APIRequestException : std::exception
	{
	public:
		APIRequestException() = default;
		explicit APIRequestException(std::string str) : message(std::move(str)) {}
		~APIRequestException() noexcept override = default;;
		[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
	
	private:
		std::string message;
	};
	
	class APINoResponseException : std::exception
	{
	public:
		APINoResponseException() = default;
		explicit APINoResponseException(std::string str) : message(std::move(str)) {}
		~APINoResponseException() noexcept override = default;;
		[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
	
	private:
		std::string message;
	};
}

#endif //ACMECAT_UTILS_H
