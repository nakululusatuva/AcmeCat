//
// Created by nova on 8/29/20.
//

#include "Server.h"

void Server::acmeThread(const std::shared_ptr<CertCache>& cert, const Json::Value& globalConfigs, bool issueImmediately)
{
	Acme::API acme(globalConfigs);
	std::time_t nextTimePoint = 0;
	std::string saveDir = globalConfigs["server"]["acme"]["save_dir"].asString();
	std::string cronExpression = globalConfigs["server"]["acme"]["cron_expression"].asString();
	std::string shellCommand;
	Json::Value shellCommandObject = globalConfigs["server"]["acme"]["shell_command"];
	if (!shellCommandObject.isNull() and !shellCommandObject.asString().empty())
		shellCommand = shellCommandObject.asString();
	
	std::tuple<std::string, std::string, std::string> certsAndPrivateKey;
	bool firstStartUp = true;
	while (true)
	{
		auto cron = cron::make_cron(cronExpression);
		std::time_t now = std::time(nullptr);
		nextTimePoint = issueImmediately and firstStartUp ? now : cron::cron_next(cron, now);
		if (!issueImmediately or !firstStartUp)
		{
			LOG(INFO) << "ACME - The next request will be at "
			          << Utils::Time::UnixTimeToRFC3339(nextTimePoint, Utils::Time::localTimeZoneUTC());
		}
		firstStartUp = false;
		sleep(nextTimePoint - std::time(nullptr));
		
		try
		{
			certsAndPrivateKey = acme.issueCertificate();
			
			auto[endEntityCertPEM, issuerCertPEM, privateKeyPKCS8] = certsAndPrivateKey;
			LOG(INFO) << "ACME - Caching the new certificate in memory.";
			cert->update(endEntityCertPEM, issuerCertPEM, privateKeyPKCS8);
			cert->toFile(saveDir);
			if (!shellCommand.empty())
			{
				LOG(INFO) << "ACME - Execute shell command \"" << shellCommand << "\"";
				Utils::ExecuteShell(shellCommand);
			}
		}
		catch (Acme::IssueCertificateFailed& e) {}
		catch (cron::bad_cronexpr const & ex)
		{
			std::string errMsg = "ACME - Parsing cron expression failed";
			LOG(ERROR) << errMsg;
			throw ServerFatalException(errMsg);
		}
	}
}

void Server::handlerThread(
		const std::shared_ptr<CertCache>& cert, int fd,
		const std::shared_ptr<RSA>& serverPrivateKey,
		OpensslWrap::AsymmetricRSA::PublicKeyList authorizedKeys)
{
	/* Get client's ip address and port */
	struct sockaddr_in6 clientSA;
	char addrString[INET6_ADDRSTRLEN];
	socklen_t saLen = sizeof(clientSA);
	getpeername(fd, (struct sockaddr*)&clientSA, &saLen);
	const std::string v4padding = "::ffff:";
	std::string address = inet_ntop(AF_INET6, &(clientSA.sin6_addr), addrString, INET6_ADDRSTRLEN);
	bool isPaddedIPV4 = std::regex_match(address, std::regex(R"(::ffff:(\d+\.\d+\.\d+\.\d+)$)"));
	if (isPaddedIPV4)
		// Accept incoming IPv4 connections on an IPv6 socket. Reformat the padded ipv4 address, example: '::ffff:127.0.0.1' to '127.0.0.1'
		address = address.substr(v4padding.size(), address.size()-v4padding.size());
	else
		address = "[" + address + "]";
	std::string port = std::to_string(ntohs(clientSA.sin6_port));
	std::string remoteHostInfo = address + ":" + port;
	
	/* Log remote host's info */
	std::string logPrefix = "Connection " + remoteHostInfo + ", ";
	LOG(INFO) << "Incoming connection from " << remoteHostInfo;
	
	/* Decrypt client hello and get identity */
	std::shared_ptr<RSA> clientPublicKey = nullptr;
	LOG(INFO) << logPrefix << "receiving client's identity hello.";
	auto identityHello = Protocol::Socket::readSerial(fd);
	if (identityHello == nullptr)
	{
		LOG(WARNING) << logPrefix << "Can't read a valid serial from socket.";
		Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(""));
		LOG(INFO) << "Disconnect to " << remoteHostInfo;
		return;
	}
	else if (Protocol::Serialize::IsCloseSocketSignal(identityHello))
	{
		std::string closeMsg = Protocol::Serialize::RemoteHostCloseMessage(identityHello);
		if (closeMsg.empty())
			LOG(WARNING) << logPrefix << "socket closed by remote host.";
		else
			LOG(WARNING) << logPrefix << "socket closed by remote host, reason: " << closeMsg;
		LOG(INFO) << "Disconnect to " << remoteHostInfo;
		return;
	}
	else if (!Protocol::Serialize::ValidateChecksum(identityHello))
	{
		std::string msg = "invalid checksum.";
		LOG(WARNING) << logPrefix << msg;
		Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(msg));
		LOG(INFO) << "Disconnect to " << remoteHostInfo;
		return;
	}
	else
	{
		if (!cert->isCached())
		{
			std::string msg = "certificate not yet been cached.";
			LOG(WARNING) << logPrefix << msg;
			Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(msg));
			LOG(INFO) << "Disconnect to " << remoteHostInfo;
			return;
		}
		auto fingerprint = Protocol::Serialize::DecryptClientIdentify(identityHello, serverPrivateKey);
		if (fingerprint.empty())
		{
			std::string msg = "can not decrypt the identity hello.";
			LOG(WARNING) << logPrefix << msg;
			Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(msg));
			LOG(INFO) << "Disconnect to " << remoteHostInfo;
			return;
		}
		clientPublicKey = authorizedKeys.get(fingerprint);
		if (clientPublicKey == nullptr)
		{
			std::string msg = "client's public key fingerprint not authorized";
			LOG(WARNING) << logPrefix << msg;
			Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(msg));
			LOG(INFO) << "Disconnect to " << remoteHostInfo;
			return;
		}
		else LOG(INFO) << logPrefix << "fingerprint: " << fingerprint << " is authorized";
	}
	
	/* Send a token that encrypted with client's public key */
	auto authorizationToken = Protocol::RandomToken(32);
	auto encryptedToken = Protocol::Serialize::AuthorizeToken(authorizationToken, clientPublicKey);
	Protocol::Socket::writeSerial(fd, encryptedToken);
	LOG(INFO) << logPrefix << "authorization token: " << authorizationToken << " was sent.";
	
	/* Receive decrypted result from client, compare to generated token */
	LOG(INFO) << logPrefix << "receiving client's authorization reply.";
	auto authorizationReply = Protocol::Socket::readSerial(fd);
	if (authorizationReply == nullptr)
	{
		LOG(WARNING) << logPrefix << "Can't read a valid serial from socket.";
		Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(""));
		LOG(INFO) << "Disconnect to " << remoteHostInfo;
		return;
	}
	else if (Protocol::Serialize::IsCloseSocketSignal(authorizationReply))
	{
		std::string closeMsg = Protocol::Serialize::RemoteHostCloseMessage(authorizationReply);
		if (closeMsg.empty())
			LOG(WARNING) << logPrefix << "socket closed by remote host.";
		else
			LOG(WARNING) << logPrefix << "socket closed by remote host, reason: " << closeMsg;
		return;
	}
	else if (!Protocol::Serialize::ValidateChecksum(authorizationReply))
	{
		std::string msg = "invalid checksum.";
		LOG(WARNING) << logPrefix << msg;
		Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(msg));
		LOG(INFO) << "Disconnect to " << remoteHostInfo;
		return;
	}
	else
	{
		auto repliedToken = Protocol::Serialize::DecryptAuthorizeReply(authorizationReply, serverPrivateKey);
		if (repliedToken != authorizationToken)
		{
			std::string msg = "authorization reply does not match the token.";
			LOG(WARNING) << logPrefix << msg;
			Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(msg));
			LOG(INFO) << "Disconnect to " << remoteHostInfo;
			return;
		}
		else LOG(INFO) << logPrefix << "client's identity was confirmed.";
	}
	
	/* Send aes-256-cbc encrypted cert with token as passphrase */
	auto encryptedCert = Protocol::Serialize::CertificateData(cert->toJson(), authorizationToken);
	Protocol::Socket::writeSerial(fd, encryptedCert);
	LOG(INFO) << logPrefix << "certificate data was sent.";
	
	Protocol::Socket::closeWithMessage(fd, nullptr);
	LOG(INFO) << "Disconnect to " << remoteHostInfo;
}

void Server::run()
{
	LOG(INFO) << "========== Start AcmeCat Server ==========";
	/* Get server private key */
	std::shared_ptr<RSA> serverPrivateKey = nullptr;
	Json::Value passphraseObject = globalConfigs["server"]["private_key_passphrase"];
	std::string privateKeyPEM = globalConfigs["server"]["private_key"].asString();
	std::string passphrase;
	if (!passphraseObject.isNull() and !passphraseObject.asString().empty())
	{
		passphrase = passphraseObject.asString();
		serverPrivateKey = OpensslWrap::PEM::ToRsa(privateKeyPEM, passphrase);
	}
	else serverPrivateKey = OpensslWrap::PEM::ToRsa(privateKeyPEM);
	
	/* Get authorized keys */
	std::vector<std::string> pemStrings;
	for (const auto& pem : globalConfigs["server"]["authorized_keys"])
		pemStrings.push_back(pem.asString());
	auto authorizedKeys = OpensslWrap::AsymmetricRSA::PublicKeyList(pemStrings);
	
	/* port, thread num, cron expression, cert cache */
	int port = globalConfigs["server"]["port"].asInt();
	int workersNum = globalConfigs["server"]["workers"].asInt();
	std::string cronExpression = globalConfigs["server"]["acme"]["cron_expression"].asString();
	auto cert = std::make_shared<CertCache>();
	cert->tryLoadFromFile(globalConfigs["server"]["acme"]["save_dir"].asString()); // Try to load the cached cert from disk
	
	/* Create thread pool and start ACME work thread */
	LOG(INFO) << "Creating thread pool with " << std::to_string(workersNum+1)
			  << " threads (" << std::to_string(workersNum) << " handlers + 1 ACME thread).";
	ThreadPool pool(workersNum+1);
	pool.execute(acmeThread, cert, globalConfigs, issueImmediately);
	
	/* Listen for incoming connections and handle */
	int listener = Protocol::Socket::openListener(port);   /* create Server socket */
	if (listener == Protocol::Socket::SOCKET_CANNOT_BIND_PORT or listener == Protocol::Socket::SOCKET_CANNOT_LISTENING)
	{
		LOG(ERROR) << "Can not bind or listening at port " << std::to_string(port);
		pool.destroy();
		throw ServerFatalException();
	}
	else LOG(INFO) << "Listening at port " << port;
	while (true)
	{
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		int fd = accept(listener, (struct sockaddr*)&addr, &len);
		pool.execute(handlerThread, cert, fd, serverPrivateKey, authorizedKeys);
	}
}
