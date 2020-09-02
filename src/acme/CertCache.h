//
// Created by nova on 8/17/20.
//

#ifndef ACMED_CERTIFICATION_H
#define ACMED_CERTIFICATION_H

#include <string>
#include <memory>
#include <utility>
#include <fstream>
#include <unistd.h>
#include <shared_mutex>
#include <openssl/x509.h>
#include "../utils/Utils.h"

class CertCache     /* Thread safe */
{
public:
	CertCache()
	{
		cached = false;
		cert = "";
		issuerCert = "";
		privateKey = "";
	}
	explicit CertCache(const std::shared_ptr<const std::vector<std::byte>>& bytes)
	{
		auto bytesCopy = std::make_shared<std::vector<std::byte>>((std::byte*)bytes.get(), (std::byte*)bytes.get()+bytes->size()-1);
		auto jsonObjectString = Utils::StringProcess::ByteVecToString(bytesCopy);
		Json::Value jsonObject;
		std::string parseErrors = Utils::StringProcess::StringToJson(jsonObjectString, &jsonObject);
		if (!parseErrors.empty())
		{
			cached = false;
			cert = "";
			issuerCert = "";
			privateKey = "";
		}
		else
		{
			cached = true;
			cert = jsonObject["cert"].asString();
			issuerCert = jsonObject["issuerCert"].asString();
			privateKey = jsonObject["privateKey"].asString();
		}
	}
	~CertCache() = default;
	
	bool isCached() { std::shared_lock<std::shared_mutex> readLock(mutex); return cached; }
	
	void update(const std::string& endEntityCertPEM, const std::string& issuerCertPEM, const std::string& privateKeyPKCS8)
	{
		std::unique_lock<std::shared_mutex> writeLock(mutex);
		
		cert = endEntityCertPEM;
		issuerCert = issuerCertPEM;
		privateKey = privateKeyPKCS8;
		cached = true;
	}
	
	Json::Value toJson()
	{
		std::shared_lock<std::shared_mutex> readLock(mutex);
		
		Json::Value jsonObject;
		jsonObject["cert"] = cert;
		jsonObject["issuerCert"] = issuerCert;
		jsonObject["privateKey"] = privateKey;

		return jsonObject;
	}
	
	void toFile(const std::string& dirPath)
	{
		std::shared_lock<std::shared_mutex> readLock(mutex);
		
		std::ofstream certFile(dirPath + "/cert.pem");
		certFile << cert << std::endl << std::endl;
		
		std::ofstream fullchainFile(dirPath + "/fullchain.pem");
		fullchainFile << cert << "\n\n" << issuerCert << std::endl;
		
		std::ofstream privateKeyFile(dirPath + "/private.pem");
		privateKeyFile << privateKey << std::endl;
	}   // TODO: Add old cert archive feature
	
	/* Try to load the certificate that cached on disk, no guarantee of success */
	void tryLoadFromFile(const std::string& dirPath)
	{
		std::string certPath = dirPath+"/cert.pem";
		std::string fullchainPath = dirPath+"/fullchain.pem";
		std::string privatePath = dirPath+"/private.pem";
		
		if (access(certPath.c_str(), R_OK) == 0 and access(fullchainPath.c_str(), R_OK) == 0 and access(privatePath.c_str(), R_OK) == 0)
		{
			std::ifstream certFile(certPath), fullchainFile(fullchainPath), privateFile(privatePath);
			
			std::string certBuffer((std::istreambuf_iterator<char>(certFile)), std::istreambuf_iterator<char>());
			std::string fullchainBuffer((std::istreambuf_iterator<char>(fullchainFile)), std::istreambuf_iterator<char>());
			std::string privateBuffer((std::istreambuf_iterator<char>(privateFile)), std::istreambuf_iterator<char>());
			
			std::unique_lock<std::shared_mutex> writeLock(mutex);
			cert = certBuffer;
			issuerCert = Utils::StringProcess::SplitString(fullchainBuffer, "\n\n").at(1);
			privateKey = privateBuffer;
			cached = true;
		}
	}
	
private:
	mutable std::shared_mutex mutex;
	bool cached;
	std::string cert;
	std::string issuerCert;
	std::string privateKey;
};


#endif //ACMED_CERTIFICATION_H
