//
// Created by nova on 7/31/20.
//

#ifndef ACMED_OPENSSLWRAP_H
#define ACMED_OPENSSLWRAP_H

#include <regex>
#include <fstream>
#include <iostream>
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "Utils.h"

#define MINIMUM_RSA_KEY_BITS_OF_SECURE 2048

namespace OpensslWrap
{
	namespace PEM
	{
		/* PEM string in config file might contain spaces, unnecessary tab or duplicated '\n',
		 * make sure to call this function before you load the key with OpenSSL */
		std::string Formatting(const std::string& pemKeyString);
		
		bool MightBeEncrypted(const std::string& pemKeyString);   /* Maybe an encrypted key if "ENCRYPTED" was found in pem string. */
		bool IsPublicKey(const std::string& pemKeyString);
		bool IsPrivateKey(const std::string& pemKeyString);
		
		/* Return a pointer of RSA object's copy.
		 * Do NOT call RSA_free(ptr.get())
		 * Exceptions: OpensslWrap::Exceptions::PemStringToRsaFailedException()
		 *             OpensslWrap::Exceptions::NotRSAKeyException().*/
		[[nodiscard]] std::shared_ptr<RSA> ToRsa(const std::string& pemKeyString);
		[[nodiscard]] std::shared_ptr<RSA> ToRsa(const std::string& pemKeyString, const std::string& passphrase);
	}
	
	namespace AsymmetricRSA
	{
		std::shared_ptr<RSA> Create(int rsaBits);
		int KeyBits(const std::shared_ptr<const RSA>& key);
		std::string PublicKeyToPEMString(const std::shared_ptr<RSA>& rsa);
		std::string PrivateKeyToPKCS8(const std::shared_ptr<RSA>& rsa);
		std::string PrivateKeyToPKCS8(const std::shared_ptr<RSA>& rsa, const EVP_CIPHER* cipherType, const std::string& passphrase);
		std::string PrivateKeyToPKCS1(const std::shared_ptr<RSA>& rsa);
		std::string PrivateKeyToPKCS1(const std::shared_ptr<RSA>& rsa, const EVP_CIPHER* cipherType, const std::string& passphrase);
		
		/* Hex string in big-endian.
		 * The MD5 digest of n || e in big-endian (operator '||' means concatenate)
		 * Returns: nullptr if parameter 'rsa' is nullptr */
		[[deprecated]] std::string FingerprintMD5(const std::shared_ptr<const RSA>& rsa);
		
		/* Hex string in big-endian.
		 * The SHA256 digest of n || e in big-endian (operator '||' means concatenate)
		 * Returns: nullptr if parameter 'rsa' is nullptr */
		std::string FingerprintSHA256(const std::shared_ptr<const RSA>& rsa);
		
		std::shared_ptr<RSA> DumpPublicKey(const std::shared_ptr<RSA>& key);
		std::shared_ptr<RSA> DumpPrivateKey(const std::shared_ptr<RSA>& key);
		
		/* Exceptions: Utils::AllocateMemoryFailed()
		 *             OpensslWrap::Exceptions::EncryptFailed() */
		std::shared_ptr<std::vector<std::byte>>
		PublicEncrypt(
				const std::shared_ptr<const std::vector<std::byte>>& msg,
				const std::shared_ptr<RSA>& pubKey,
				int padding);
		
		/* Exceptions: Utils::AllocateMemoryFailed()
		 *             OpensslWrap::Exceptions::DecryptFailed() */
		std::shared_ptr<std::vector<std::byte>>
		PrivateDecrypt(
				const std::shared_ptr<const std::vector<std::byte>>& ciphertext,
				const std::shared_ptr<RSA>& privKey,
				int padding);
		
		/* Exceptions: OpensslWrap::Exceptions::SignFailed() */
		std::shared_ptr<std::vector<std::byte>>
		Sign(
				const std::shared_ptr<const std::vector<std::byte>>& msg,
				const std::shared_ptr<RSA>& privKey,
				int type);
		
		/* Exceptions: Utils::AllocateMemoryFailed()
		 *             OpensslWrap::Exceptions::SignFailed() */
		std::shared_ptr<std::vector<std::byte>>
		RS256(
				const std::shared_ptr<const std::vector<std::byte>>& msg,
				const std::shared_ptr<RSA>& privateKey);
		
		class PublicKeyList     /* Using SHA256 fingerprint */
		{
		public:
			/* Exceptions: Exceptions::PemStringToRsaFailedException() */
			explicit PublicKeyList(const std::vector<std::tuple<std::string, std::string>>& nameAndPem);
			~PublicKeyList()= default;
			std::tuple<std::string, std::shared_ptr<RSA>> get(const std::string& SHA256fingerprint);
		
		private:
			std::map<std::string, std::tuple<std::string, std::shared_ptr<RSA>>> list;    /* <Fingerprint, <NickName, RSA>> */
		};
	} // End of namespace AsymmetricRSA
	
	namespace Digest
	{
		/* Exceptions: Utils::AllocateMemoryFailed() */
		std::shared_ptr<std::vector<std::byte>> MD5(const std::shared_ptr<const std::vector<std::byte>>& msg);
		/* Exceptions: Utils::AllocateMemoryFailed() */
		std::shared_ptr<std::vector<std::byte>> SHA256(const std::shared_ptr<const std::vector<std::byte>>& msg);
	}
	
	namespace AES256CBC
	{
		int KeyIV(const std::string& passphrase, unsigned char* salt, unsigned char* key, unsigned char* iv);
		std::shared_ptr<std::vector<std::byte>> Encrypt(const std::shared_ptr<std::vector<std::byte>>& msg, const std::string& passphrase);
		std::shared_ptr<std::vector<std::byte>> Decrypt(const std::shared_ptr<std::vector<std::byte>>& cipher, const std::string& passphrase);
	}
	
	/* Return nullptr on error */
	std::shared_ptr<X509_REQ>
	CreateSANCertificateSigningRequest(
			const std::string& commonName,
			const std::vector<std::string>& subjectAltNames,
			const std::shared_ptr<RSA>& privateKey);
	
	/* Return "" on error */
	std::string X509reqToPKCS10(const std::shared_ptr<X509_REQ>& csr);
	/* Return nullptr on error */
	std::shared_ptr<std::vector<std::byte>> X509reqToDER(const std::shared_ptr<X509_REQ>& csr);
	
	namespace Exceptions
	{
		class EncryptFailed : std::exception
		{
		public:
			EncryptFailed() = default;
			explicit EncryptFailed(std::string str) : message(std::move(str)) {}
			~EncryptFailed() noexcept override = default;;
			[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
		
		private:
			std::string message;
		};
		
		class DecryptFailed : std::exception
		{
		public:
			DecryptFailed() = default;
			explicit DecryptFailed(std::string str) : message(std::move(str)) {}
			~DecryptFailed() noexcept override = default;;
			[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
		
		private:
			std::string message;
		};
		
		class SignFailed : std::exception
		{
		public:
			SignFailed() = default;
			explicit SignFailed(std::string str) : message(std::move(str)) {}
			~SignFailed() noexcept override = default;;
			[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
		
		private:
			std::string message;
		};
		
		class NotRSAKeyException : std::exception
		{
		public:
			NotRSAKeyException() = default;
			explicit NotRSAKeyException(std::string str) : message(std::move(str)) {}
			~NotRSAKeyException() noexcept override = default;;
			[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
		
		private:
			std::string message;
		};
		
		class PemStringToRsaFailedException : std::exception
		{
		public:
			PemStringToRsaFailedException() = default;
			explicit PemStringToRsaFailedException(std::string str) : message(std::move(str)) {}
			~PemStringToRsaFailedException() noexcept override = default;;
			[[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
		
		private:
			std::string message;
		};
	} // End of namespace Exceptions
} // End of namespace OpensslWrap

#endif //ACMED_OPENSSLWRAP_H
