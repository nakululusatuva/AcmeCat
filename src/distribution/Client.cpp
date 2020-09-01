//
// Created by nova on 8/30/20.
//

#include "Client.h"

void Client::run()
{
	LOG(INFO) << "========== Start AcmeCat Client ==========";
	/* Get client's and server's private key */
	std::shared_ptr<RSA> clientPrivateKey = nullptr;
	std::string privateKeyPEM = globalConfigs["client"]["private_key"].asString();
	auto passphraseObject = globalConfigs["client"]["private_key_passphrase"];
	std::string passphrase;
	if (!passphraseObject.isNull() and !passphraseObject.asString().empty())
	{
		passphrase = passphraseObject.asString();
		clientPrivateKey = OpensslWrap::PEM::ToRsa(privateKeyPEM, passphrase);
	}
	else clientPrivateKey = OpensslWrap::PEM::ToRsa(privateKeyPEM);
	auto serverPublicKey = OpensslWrap::PEM::ToRsa(globalConfigs["client"]["server_public_key"].asString());
	
	/* hostname, port, client's fingerprint, cron expression, next cron time point, certificate cache, certSaveDir, shell command */
	std::string hostname = globalConfigs["client"]["host"].asString();
	int port = globalConfigs["client"]["port"].asInt();
	auto clientFingerprint = OpensslWrap::AsymmetricRSA::FingerprintSHA256(clientPrivateKey);
	auto cronExpression = globalConfigs["client"]["distribution"]["cron_expression"].asString();
	std::time_t nextTimePoint = 0;
	std::string shellCommand;
	Json::Value shellCommandObject = globalConfigs["client"]["distribution"]["shell_command"];
	if (!shellCommandObject.isNull() and !shellCommandObject.asString().empty())
		shellCommand = shellCommandObject.asString();
	auto certSaveDir = globalConfigs["client"]["distribution"]["save_dir"].asString();
	CertCache cache;
	
	bool firstStartUp = true;
	while (true)
	{
		auto cron = cron::make_cron(cronExpression);
		std::time_t now = std::time(nullptr);
		nextTimePoint = issueImmediately and firstStartUp ? now : cron::cron_next(cron, now);
		if (!issueImmediately or !firstStartUp)
		{
			LOG(INFO) << "The next request will be at "
			          << Utils::Time::UnixTimeToRFC3339(nextTimePoint, Utils::Time::localTimeZoneUTC());
		}
		firstStartUp = false;
		sleep(nextTimePoint - std::time(nullptr));
		
		if (request(hostname, port, cache, clientFingerprint, serverPublicKey, clientPrivateKey))
		{
			cache.toFile(certSaveDir);
			LOG(INFO) << "New Certificate was saved under " << certSaveDir << ".";
			if (!shellCommand.empty())
			{
				LOG(INFO) << "Execute shell command \"" << shellCommand << "\"";
				Utils::ExecuteShell(shellCommand);
			}
		}
	}
}

bool Client::request(
		const std::string& hostname, int port,
		CertCache& cache,
		const std::string& clientFingerprint,
		const std::shared_ptr<RSA>& serverPublicKey,
		const std::shared_ptr<RSA>& clientPrivateKey)
{
	std::string hostInfo = hostname + ":" + std::to_string(port);
	int fd = Protocol::Socket::openConnector(hostname, port);
	if (fd == Protocol::Socket::SOCKET_CANNOT_RESOLVE_HOSTNAME or
	    fd == Protocol::Socket::SOCKET_CANNOT_OPEN_CONNECTION)
	{
		LOG(ERROR) << "Can not connect to " << hostInfo;
		throw ClientFatalException();
	}
	else
		LOG(INFO) << "Connected to " << hostInfo;
	
	/* Send identity hello */
	auto identityHello = Protocol::Serialize::ClientIdentity(clientFingerprint, serverPublicKey);
	Protocol::Socket::writeSerial(fd, identityHello);
	LOG(INFO) << "Sent public key fingerprint: " << clientFingerprint;
	
	/* Receive authorization token and decrypt */
	std::string token;
	LOG(INFO) << "Receiving authorization token.";
	auto authorizationToken = Protocol::Socket::readSerial(fd);
	if (authorizationToken == nullptr)
	{
		LOG(WARNING) << "error(s) while reading socket.";
		Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(""));
		LOG(INFO) << "Disconnect to " << hostInfo;
		return false;
	}
	else if (Protocol::Serialize::IsCloseSocketSignal(authorizationToken))
	{
		std::string closeMsg = Protocol::Serialize::RemoteHostCloseMessage(authorizationToken);
		if (closeMsg.empty())
			LOG(WARNING) << "Socket closed by remote host.";
		else
			LOG(WARNING) << "Socket closed by remote host, reason: " << closeMsg;
		LOG(INFO) << "Disconnect to " << hostInfo;
		return false;
	}
	else if (!Protocol::Serialize::ValidateChecksum(identityHello))
	{
		std::string msg = "invalid checksum.";
		LOG(WARNING) << msg;
		Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(msg));
		LOG(INFO) << "Disconnect to " << hostInfo;
		return false;
	}
	else
	{
		token = Protocol::Serialize::DecryptAuthorizeToken(authorizationToken, clientPrivateKey);
		if (token.empty())
		{
			std::string msg = "can not decrypt the authorization token.";
			LOG(WARNING) << msg;
			Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(msg));
			LOG(INFO) << "Disconnect to " << hostInfo;
			return false;
		}
	}
	
	/* Send token as authorize reply */
	auto authorizeReply = Protocol::Serialize::AuthorizeReply(token, serverPublicKey);
	write(fd, authorizeReply->data(), authorizeReply->size());
	LOG(INFO) << "Sent token " << token << " as authorization reply.";
	
	/* Receive encrypted certificate */
	LOG(INFO) << "Receiving certificate data.";
	auto encryptedCertSerial = Protocol::Socket::readSerial(fd);
	if (encryptedCertSerial == nullptr)
	{
		LOG(WARNING) << "error(s) while reading socket.";
		Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(""));
		LOG(INFO) << "Disconnect to " << hostInfo;
		return false;
	}
	else if (Protocol::Serialize::IsCloseSocketSignal(encryptedCertSerial))
	{
		std::string closeMsg = Protocol::Serialize::RemoteHostCloseMessage(encryptedCertSerial);
		if (closeMsg.empty())
			LOG(WARNING) << "Socket closed by remote host.";
		else
			LOG(WARNING) << "Socket closed by remote host, reason: " << closeMsg;
		LOG(INFO) << "Disconnect to " << hostInfo;
		return false;
	}
	else if (!Protocol::Serialize::ValidateChecksum(encryptedCertSerial))
	{
		std::string msg = "invalid checksum.";
		LOG(WARNING) << msg;
		Protocol::Socket::closeWithMessage(fd, Protocol::Serialize::CloseSocketSignal(msg));
		LOG(INFO) << "Disconnect to " << hostInfo;
		return false;
	}
	else
	{
		Json::Value certData = Protocol::Serialize::DecryptCertificateData(encryptedCertSerial, token);
		std::string endEntityCert = certData["cert"].asString();
		std::string issuerCert = certData["issuerCert"].asString();
		std::string privateKey = certData["privateKey"].asString();
		cache.update(endEntityCert, issuerCert, privateKey);
		LOG(INFO) << "Received " << endEntityCert.size() + issuerCert.size() + privateKey.size()
		          << " bytes of certificate data.";
		LOG(INFO) << "Disconnect to " << hostInfo;
		return true;
	}
}
