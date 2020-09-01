//
// Created by nova on 8/27/20.
//

#include "Protocol.h"

std::string Protocol::RandomToken(int size)
{
	std::byte bytes[size];
	RAND_bytes((unsigned char*)bytes, size);
	auto vec = std::make_shared<std::vector<std::byte>>((std::byte*)bytes, (std::byte*)bytes + size);
	return Utils::Codec::Base64UrlEncode(vec);
}

unsigned int Protocol::Serialize::prefixToInteger(const std::byte* bytes)
{
	int length = 0;
	if (Utils::Endianness() == 'B')
		memcpy(&length, bytes, 4);
	else
	{   /* Reverse */
		((std::byte*)&length)[0] = bytes[3];
		((std::byte*)&length)[1] = bytes[2];
		((std::byte*)&length)[2] = bytes[1];
		((std::byte*)&length)[3] = bytes[0];
	}
	return length;
}

unsigned int Protocol::Serialize::prefixToInteger(const std::shared_ptr<const std::vector<std::byte>>& bytes)
{
	int length = 0;
	if (Utils::Endianness() == 'B')
		memcpy(&length, bytes->data(), 4);
	else
	{   /* Reverse */
		((std::byte*)&length)[0] = bytes->at(3);
		((std::byte*)&length)[1] = bytes->at(2);
		((std::byte*)&length)[2] = bytes->at(1);
		((std::byte*)&length)[3] = bytes->at(0);
	}
	return length;
}

std::shared_ptr<std::vector<std::byte>>
Protocol::Serialize::ExtractPayload(const std::shared_ptr<const std::vector<std::byte>>& serial)
{
	const auto* payloadBegin = serial->data() + 4;
	const auto* payloadEnd = serial->data() + serial->size() - 4;
	return std::make_shared<std::vector<std::byte>>(payloadBegin, payloadEnd);
}

bool Protocol::Serialize::ValidateChecksum(const std::shared_ptr<const std::vector<std::byte>>& serial)
{
	if (serial->size() <= 8)
		return false;
	unsigned int length = prefixToInteger(serial);
	if (serial->size() - 4 != length)
		return false;
	
	auto payload = ExtractPayload(serial);
	auto digest = OpensslWrap::Digest::SHA256(payload);
	std::byte expectedChecksum[4];
	std::byte checksum[4];
	/* Given that openssl treats all series of bytes as big-endian,
	 * there's no need to check the endianness */
	memcpy(expectedChecksum, digest->data()+digest->size()-4, 4);
	memcpy(checksum, serial->data()+serial->size()-4, 4);
	if (memcmp(checksum, expectedChecksum, 4) != 0)
		return false;
	return true;
}

std::shared_ptr<std::vector<std::byte>>
Protocol::Serialize::AddPrefixAndChecksum(const std::shared_ptr<const std::vector<std::byte>>& payload)
{
	auto digest = OpensslWrap::Digest::SHA256(payload);
	unsigned int followingLen = payload->size() + 4;
	
	std::byte prefix[4];
	std::byte checksum[4];
	
	if (Utils::Endianness() == 'B')
		memcpy(prefix, &followingLen, 4);
	else
	{   /* Reverse */
		prefix[0] = *((std::byte*)&followingLen + 3);
		prefix[1] = *((std::byte*)&followingLen + 2);
		prefix[2] = *((std::byte*)&followingLen + 1);
		prefix[3] = *((std::byte*)&followingLen + 0);
	}
	/* Given that openssl treats all series of bytes as big-endian,
	 * there's no need to check the endianness */
	for (int i = 0; i < 4; ++i)
		checksum[i] = digest->at(digest->size() - 4 + i);
	
	auto formatted = std::make_shared<std::vector<std::byte>>(4+followingLen);
	memcpy(formatted->data(), prefix, 4);
	memcpy(formatted->data()+4, payload->data(), payload->size());
	memcpy(formatted->data()+followingLen, checksum, 4);
	
	return formatted;
}

std::shared_ptr<std::vector<std::byte>> Protocol::Serialize::CloseSocketSignal(const std::string& message)
{
	auto bytes = Utils::StringProcess::StringToByteVec(Protocol::Socket::SOCKET_CLOSE+message);
	return AddPrefixAndChecksum(bytes);
}

bool Protocol::Serialize::IsCloseSocketSignal(const std::shared_ptr<const std::vector<std::byte>>& serial)
{
	if (!ValidateChecksum(serial)) return false;
	auto payload = Utils::StringProcess::ByteVecToString(ExtractPayload(serial));
	auto ret = memcmp(payload.c_str(), Protocol::Socket::SOCKET_CLOSE.c_str(), Protocol::Socket::SOCKET_CLOSE.size());
	if (ret == 0) return true;
	else return false;
}

std::string Protocol::Serialize::RemoteHostCloseMessage(const std::shared_ptr<const std::vector<std::byte>>& serial)
{
	auto payload = ExtractPayload(serial);
	if (payload->size() == Protocol::Socket::SOCKET_CLOSE.size())   /* Don't have a message following */
		return std::string();
	auto msgLen = payload->size() - Protocol::Socket::SOCKET_CLOSE.size();
	std::byte msg[msgLen];
	memcpy(msg, payload->data()+Protocol::Socket::SOCKET_CLOSE.size(), msgLen);
	return std::string((char*)msg, (char*)msg + msgLen);
}

std::shared_ptr<std::vector<std::byte>>
Protocol::Serialize::ClientIdentity(const std::string& fingerprintSHA256, const std::shared_ptr<RSA>& serverPublicKey)
{
	auto bytes = Utils::StringProcess::StringToByteVec(fingerprintSHA256);
	auto encrypted = OpensslWrap::AsymmetricRSA::PublicEncrypt(bytes, serverPublicKey, RSA_PKCS1_OAEP_PADDING);
	return AddPrefixAndChecksum(encrypted);
}

std::string Protocol::Serialize::DecryptClientIdentify(const std::shared_ptr<const std::vector<std::byte>>& serial,
                                                       const std::shared_ptr<RSA>& serverPrivateKey)
{
	try
	{
		auto valid = ValidateChecksum(serial);
		if (!valid)
			return std::string();
		auto payload = ExtractPayload(serial);
		auto decrypted = OpensslWrap::AsymmetricRSA::PrivateDecrypt(payload, serverPrivateKey, RSA_PKCS1_OAEP_PADDING);
		return Utils::StringProcess::ByteVecToString(decrypted);
	}
	catch (OpensslWrap::Exceptions::DecryptFailed& e)
	{
		return std::string();
	}
}

std::shared_ptr<std::vector<std::byte>>
Protocol::Serialize::AuthorizeToken(const std::string& token,
                                    const std::shared_ptr<RSA>& clientPublicKey)
{
	auto encrypted = OpensslWrap::AsymmetricRSA::PublicEncrypt(Utils::StringProcess::StringToByteVec(token), clientPublicKey, RSA_PKCS1_OAEP_PADDING);
	return AddPrefixAndChecksum(encrypted);
}

std::string Protocol::Serialize::DecryptAuthorizeToken(const std::shared_ptr<std::vector<std::byte>>& serial,
                                                       const std::shared_ptr<RSA>& clientPrivateKey)
{
	try
	{
		auto valid = ValidateChecksum(serial);
		if (!valid)
			return std::string();
		auto payload = ExtractPayload(serial);
		auto decrypted = OpensslWrap::AsymmetricRSA::PrivateDecrypt(payload, clientPrivateKey, RSA_PKCS1_OAEP_PADDING);
		return Utils::StringProcess::ByteVecToString(decrypted);
	}
	catch (OpensslWrap::Exceptions::DecryptFailed& e)
	{
		return std::string();
	}
}

std::shared_ptr<std::vector<std::byte>> Protocol::Serialize::AuthorizeReply(const std::string& token, const std::shared_ptr<RSA>& serverPublicKey)
{
	auto encrypted = OpensslWrap::AsymmetricRSA::PublicEncrypt(Utils::StringProcess::StringToByteVec(token), serverPublicKey, RSA_PKCS1_OAEP_PADDING);
	return AddPrefixAndChecksum(encrypted);
}

std::string Protocol::Serialize::DecryptAuthorizeReply(const std::shared_ptr<std::vector<std::byte>>& serial, const std::shared_ptr<RSA>& serverPrivateKey)
{
	try
	{
		auto valid = ValidateChecksum(serial);
		if (!valid)
			return std::string();
		auto payload = ExtractPayload(serial);
		auto decrypted = OpensslWrap::AsymmetricRSA::PrivateDecrypt(payload, serverPrivateKey, RSA_PKCS1_OAEP_PADDING);
		return Utils::StringProcess::ByteVecToString(decrypted);
	}
	catch (OpensslWrap::Exceptions::DecryptFailed& e)
	{
		return std::string();
	}
}

std::shared_ptr<std::vector<std::byte>> Protocol::Serialize::CertificateData(const Json::Value& certData, const std::string& passphrase)
{
	auto jsonString = certData.toStyledString();
	auto bytes = Utils::StringProcess::StringToByteVec(jsonString);
	auto encrypted = OpensslWrap::AES256CBC::Encrypt(bytes, passphrase);
	return AddPrefixAndChecksum(encrypted);
}

Json::Value Protocol::Serialize::DecryptCertificateData(const std::shared_ptr<const std::vector<std::byte>>& serial, const std::string& passphrase)
{
	try
	{
		auto valid = ValidateChecksum(serial);
		if (!valid)
			return std::string();
		auto payload = ExtractPayload(serial);
		auto decrypted = OpensslWrap::AES256CBC::Decrypt(payload, passphrase);
		auto jsonString = Utils::StringProcess::ByteVecToString(decrypted);
		Json::Value json;
		auto jsonErrors = Utils::StringProcess::StringToJson(jsonString, &json);
		if (jsonErrors.empty())
			return json;
		else
			return Json::Value();
	}
	catch (OpensslWrap::Exceptions::DecryptFailed& e)
	{
		return std::string();
	}
}

std::shared_ptr<std::vector<std::byte>> Protocol::Socket::readSerial(int fd)
{
	unsigned int readLen = 0;
	auto* buffer = (std::byte*)malloc(4);
	if (buffer == nullptr)
		return nullptr;
	
	readLen = read(fd, buffer, 4);
	if (readLen != 4)
		return nullptr;
	
	auto followingLen = Protocol::Serialize::prefixToInteger(buffer);
	auto totalLen = 4 + followingLen;
	auto* tmp = static_cast<std::byte*>(realloc(buffer, totalLen));
	if (tmp == nullptr)
	{
		free(buffer);
		return nullptr;
	}
	buffer = tmp;
	readLen = read(fd, buffer+4, followingLen);
	if (readLen != followingLen)
	{
		free(buffer);
		return nullptr;
	}
	
	auto serial = std::make_shared<std::vector<std::byte>>(buffer, buffer+totalLen);
	free(buffer);
	if (serial == nullptr)
		return nullptr;
	
	return serial;
}

void Protocol::Socket::writeSerial(int fd, const std::shared_ptr<const std::vector<std::byte>>& serial)
{
	write(fd, serial->data(), serial->size());
}

void Protocol::Socket::closeWithMessage(int fd, const std::shared_ptr<const std::vector<std::byte>>& signal)
{
	if (signal != nullptr)
		write(fd, signal->data(), signal->size());
	close(fd);
}

int Protocol::Socket::openListener(int port)
{
	int sd = 0;
	struct sockaddr_in6 addr;
	
	sd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	bzero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6; // Don't care IPv4 or IPv6
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;
	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
		return SOCKET_CANNOT_BIND_PORT;
	if (listen(sd, 10) != 0)
		return SOCKET_CANNOT_LISTENING;
	return sd;
}

int Protocol::Socket::openConnector(const std::string& hostname, int port)
{
	int fd = 0;
	struct addrinfo hints = {}, *addrs = nullptr;
	char port_str[16] = {};
	
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	
	sprintf(port_str, "%d", port);
	if (getaddrinfo(hostname.c_str(), port_str, &hints, &addrs) != 0)
		return SOCKET_CANNOT_RESOLVE_HOSTNAME;
	
	for (struct addrinfo* addr = addrs; addr != nullptr; addr = addr->ai_next)
	{
		fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (fd == -1) { continue; } // if using AF_UNSPEC above instead of AF_INET/6 specifically, replace this 'break' with 'continue' instead, as the 'ai_family'  may be different on the next iteration...
		if (connect(fd, addr->ai_addr, addr->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	
	freeaddrinfo(addrs);
	if (fd == -1)
		return SOCKET_CANNOT_OPEN_CONNECTION;
	return fd;
}
