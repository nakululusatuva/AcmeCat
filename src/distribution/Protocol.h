//
// Created by nova on 8/27/20.
//

#ifndef ACMECAT_PROTOCOL_H
#define ACMECAT_PROTOCOL_H

#include <netdb.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <netinet/in.h>
#include "../utils/Utils.h"
#include "../utils/OpensslWrap.h"

namespace Protocol
{/*  Serial Format
	+----------+----------+-------------+-------------------------------------------+
	| Part     | Length   | Endianness  | Description                               |
	+-------------------------------------------------------------------------------+
	| prefix   | 4 bytes  | Big endian  | Represent the length of payload || size.  |
	+-------------------------------------------------------------------------------+
	| payload  | variable | Big endian  | Encrypted message data bytes.             |
	+-------------------------------------------------------------------------------+
	| checksum | 4 bytes  | Big endian  | Last 4 bytes of SHA256(payload).          |
	+----------+----------+-------------+-------------------------------------------+
    Operator '||' means concatenate */
	std::string RandomToken(int size);   /* Get a 'size' bytes random token in base64url encode */
	
	namespace Serialize
	{
		unsigned int prefixToInteger(const std::byte* bytes);
		unsigned int prefixToInteger(const std::shared_ptr<const std::vector<std::byte>>& bytes);
		std::shared_ptr<std::vector<std::byte>> ExtractPayload(const std::shared_ptr<const std::vector<std::byte>>& serial);
		bool ValidateChecksum(const std::shared_ptr<const std::vector<std::byte>>& serial);
		std::shared_ptr<std::vector<std::byte>> AddPrefixAndChecksum(const std::shared_ptr<const std::vector<std::byte>>& payload);
		/* CloseSocketSignal format:
		 * prefix || bytes("close")+bytes("message") || checksum
		 *          └-----unencrypted payload-------┘            */
		std::shared_ptr<std::vector<std::byte>> CloseSocketSignal(const std::string& message);
		bool IsCloseSocketSignal(const std::shared_ptr<const std::vector<std::byte>>& serial);
		std::string RemoteHostCloseMessage(const std::shared_ptr<const std::vector<std::byte>>& serial);
		
		/* Hello Message */
		std::shared_ptr<std::vector<std::byte>> ClientIdentity(const std::string& fingerprintSHA256, const std::shared_ptr<RSA>& serverPublicKey);
		/* Return the client's public key's fingerprint.
		 * Return an empty string on errors or RSA decrypt failed. */
		std::string DecryptClientIdentify(const std::shared_ptr<const std::vector<std::byte>>& serial, const std::shared_ptr<RSA>& serverPrivateKey);
		
		/* Authorization */
		std::shared_ptr<std::vector<std::byte>> AuthorizeToken(const std::string& token, const std::shared_ptr<RSA>& clientPublicKey);
		std::string DecryptAuthorizeToken(const std::shared_ptr<std::vector<std::byte>>& serial, const std::shared_ptr<RSA>& clientPrivateKey);
		
		/* Authorize Reply */
		std::shared_ptr<std::vector<std::byte>> AuthorizeReply(const std::string& token, const std::shared_ptr<RSA>& serverPublicKey);
		std::string DecryptAuthorizeReply(const std::shared_ptr<std::vector<std::byte>>& serial, const std::shared_ptr<RSA>& serverPrivateKey);
		
		/* Data Transfer */
		std::shared_ptr<std::vector<std::byte>> CertificateData(const Json::Value& certData, const std::string& passphrase);
		/* Return a json object that contains three values: end-entity cert pem, fullchain pem, cert's private pem.
		 * Return an empty string on errors or RSA decrypt failed. */
		Json::Value DecryptCertificateData(const std::shared_ptr<const std::vector<std::byte>>& serial, const std::string& passphrase);
	}
	
	namespace Socket
	{
		static const std::string SOCKET_CLOSE = "close";
		static const int SOCKET_CANNOT_BIND_PORT = -1;
		static const int SOCKET_CANNOT_LISTENING = -2;
		static const int SOCKET_CANNOT_RESOLVE_HOSTNAME = -3;
		static const int SOCKET_CANNOT_OPEN_CONNECTION = -4;
		
		std::shared_ptr<std::vector<std::byte>> readSerial(int fd);
		void writeSerial(int fd, const std::shared_ptr<const std::vector<std::byte>>& serial);
		void closeWithMessage(int fd, const std::shared_ptr<const std::vector<std::byte>>& signal);
		/* Returns socket fd
		 * Errors: SOCKET_CANNOT_BIND_PORT, SOCKET_CANNOT_LISTENING */
		int openListener(int port);
		/* Returns socket fd
		 * Errors: SOCKET_CANNOT_RESOLVE_HOSTNAME, SOCKET_CANNOT_OPEN_CONNECTION */
		int openConnector(const std::string& hostname, int port);
	}
}


#endif //ACMECAT_PROTOCOL_H
