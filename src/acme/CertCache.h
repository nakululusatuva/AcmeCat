//
// Created by nova on 8/17/20.
//

#ifndef ACMED_CERTIFICATION_H
#define ACMED_CERTIFICATION_H

#include <sys/stat.h>
#include <fcntl.h>
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
	static const int NO_READ_PRIVILEGE = -1;
	static const int NO_WRITE_PRIVILEGE = -2;
	static const int IO_ERROR = -3;
    static const int FAILED_TO_ARCHIVE_OLD_CERT = -4;
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
	
	/* Returns: IO_ERROR, FAILED_TO_ARCHIVE_OLD_CERT, NO_WRITE_PRIVILEGE */
	int toFile(const std::string& dirPath)
	{
		std::shared_lock<std::shared_mutex> readLock(mutex);
		
		if (access(dirPath.c_str(), W_OK) != 0)
			return NO_WRITE_PRIVILEGE;
		try
		{
			auto archiveRet = tryArchiveOldCert(dirPath);
			if (archiveRet != 0)
				return FAILED_TO_ARCHIVE_OLD_CERT;
			
			std::ofstream certFile(dirPath + "/" + certFilename);
			certFile << cert << std::endl << std::endl;
			
			std::ofstream fullchainFile(dirPath + "/" + fullchainFilename);
			fullchainFile << cert << "\n" << issuerCert << std::endl;
			
			std::ofstream privateKeyFile(dirPath + "/" + privateKeyFilename);
			privateKeyFile << privateKey << std::endl;
			
			return 0;
		}
		catch (...) { return IO_ERROR; }
	}
	
	/* Try to load the certificate that cached on disk, no guarantee of success
	 * Returns: IO_ERROR, NO_READ_PRIVILEGE */
	int tryLoadFromFile(const std::string& dirPath)
	{
		std::string certPath = dirPath+"/"+certFilename;
		std::string fullchainPath = dirPath+"/"+fullchainFilename;
		std::string privatePath = dirPath+"/"+privateKeyFilename;
		
		if (access(certPath.c_str(), R_OK) == 0 and access(fullchainPath.c_str(), R_OK) == 0 and access(privatePath.c_str(), R_OK) == 0)
		{
			try
			{
				std::ifstream certFile(certPath), fullchainFile(fullchainPath), privateFile(privatePath);
				
				std::string certBuffer((std::istreambuf_iterator<char>(certFile)), std::istreambuf_iterator<char>());
				std::string fullchainBuffer((std::istreambuf_iterator<char>(fullchainFile)),
				                            std::istreambuf_iterator<char>());
				std::string privateBuffer((std::istreambuf_iterator<char>(privateFile)),
				                          std::istreambuf_iterator<char>());
				
				std::unique_lock<std::shared_mutex> writeLock(mutex);
				cert = certBuffer;
				issuerCert = Utils::StringProcess::SplitString(fullchainBuffer, "\n\n").at(1);
				privateKey = privateBuffer;
				cached = true;
				return 0;
			}
			catch (...) { return IO_ERROR; }
		}
		else return NO_READ_PRIVILEGE;
	}
	
private:
	mutable std::shared_mutex mutex;
	bool cached;
	std::string cert;
	std::string issuerCert;
	std::string privateKey;
	const std::string certFilename = "cert.pem";
	const std::string fullchainFilename = "fullchain.pem";
	const std::string privateKeyFilename = "private.pem";
	const std::string archiveDirNameCommonPart = "old_cert.";
	
	/* MOVE the latest files to the archive dir.
	 * Returns: IO_ERROR, NO_READ_PRIVILEGE, NO_WRITE_PRIVILEGE */
	int tryArchiveOldCert(const std::string& dirPath)
	{
		if (access(dirPath.c_str(), W_OK) != 0)
			return NO_WRITE_PRIVILEGE;
		else if (access((dirPath+"/"+certFilename).c_str(), F_OK) != 0 or
		         access((dirPath+"/"+fullchainFilename).c_str(), F_OK) != 0 or
		         access((dirPath+"/"+privateKeyFilename).c_str(), F_OK) != 0)
		    return 0;
		else if (access((dirPath+"/"+certFilename).c_str(), R_OK) != 0 or
		         access((dirPath+"/"+fullchainFilename).c_str(), R_OK) != 0 or
		         access((dirPath+"/"+privateKeyFilename).c_str(), R_OK) != 0)
		    return NO_READ_PRIVILEGE;
		else
		{
			try
			{
				auto subDirs = Utils::getSubDirsName(dirPath);
				int biggest = -1;
				for (const auto& dir : subDirs)
				{
					if (dir.find(archiveDirNameCommonPart, 0) == std::string::npos)
						continue;
					int suffix = 0;
					try
					{
						suffix = std::stoi(std::regex_replace(dir, std::regex(archiveDirNameCommonPart), ""));
					}
					catch (std::invalid_argument& e)
					{
						return IO_ERROR;
					}
					catch (std::out_of_range& e)
					{
						return IO_ERROR;
					}
					if (suffix > biggest)
						biggest = suffix;
				}
				std::string archiveDir = dirPath + "/" + archiveDirNameCommonPart + std::to_string(biggest + 1);
				mkdir(archiveDir.c_str(), S_IRWXU);
				rename((dirPath + "/" + certFilename).c_str(), (archiveDir + "/" + certFilename).c_str());
				rename((dirPath + "/" + fullchainFilename).c_str(), (archiveDir + "/" + fullchainFilename).c_str());
				rename((dirPath + "/" + privateKeyFilename).c_str(), (archiveDir + "/" + privateKeyFilename).c_str());
				return 0;
			}
			catch (...) { return IO_ERROR; }
		}
	}
};


#endif //ACMED_CERTIFICATION_H
