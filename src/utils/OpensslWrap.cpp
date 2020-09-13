//
// Created by nova on 7/31/20.
//

#include "OpensslWrap.h"

std::string OpensslWrap::PEM::Formatting(const std::string& pemKeyString)
{
	std::string formatted = std::regex_replace(pemKeyString, std::regex("[' ']{2,}"), "");   /* Remove continuous spaces in string */
	formatted = std::regex_replace(formatted, std::regex("\n "), "\n");        /* Remove single space in the front of the line */
	formatted = std::regex_replace(formatted, std::regex("\t "), "\t");        /* Remove single space in the front of the line */
	formatted = std::regex_replace(formatted, std::regex("\r\n "), "\r\n");    /* Remove single space in the front of the line */
	// formatted = std::regex_replace(formatted, std::regex("['\n']{2,}"), "\n");        /* Replace empty lines */
	// formatted = std::regex_replace(formatted, std::regex("['\r\n']{2,}"), "\r\n");    /* Replace empty lines */
	formatted.erase(std::remove(formatted.begin(), formatted.end(), '\t'), formatted.end());    /* Remove tab '\t' in string */
	return formatted;
}

bool OpensslWrap::PEM::MightBeEncrypted(const std::string& pemKeyString)
{
	return pemKeyString.find("ENCRYPTED") != std::string::npos;
}

/* This callback function was used to suppress passphrase prompt
 * if the encrypted key mistakenly passes to PemStringToRsa() which don't have a passphrase parameter. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
int SuppressPassPrompt(char *buf, int size, int rwflag, void *u)
{
	buf[0] = 0x7f;
	return 1;
}
#pragma GCC diagnostic pop

bool OpensslWrap::PEM::IsPublicKey(const std::string& pemKeyString)
{
	/* Key string to raw memory */
	BIO* buffer = BIO_new_mem_buf((const void*)pemKeyString.c_str(), (int)pemKeyString.length());
	
	/* Raw memory to public or private key */
	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(buffer, nullptr, nullptr, nullptr);
	
	if (pkey == nullptr)
		return false;
	EVP_PKEY_free(pkey);
	BIO_free(buffer);
	return true;
}

bool OpensslWrap::PEM::IsPrivateKey(const std::string& pemKeyString)
{
	/* Key string to raw memory */
	BIO* buffer = BIO_new_mem_buf((const void*)pemKeyString.c_str(), (int)pemKeyString.length());
	
	/* Raw memory to public or private key */
	EVP_PKEY* pkey = PEM_read_bio_PrivateKey(buffer, nullptr, SuppressPassPrompt, nullptr);
	
	if (pkey == nullptr)
		return false;
	EVP_PKEY_free(pkey);
	BIO_free(buffer);
	return true;
}

std::shared_ptr<RSA> OpensslWrap::PEM::ToRsa(const std::string& pemKeyString)
{
	/* Key string to raw memory */
	BIO* bufferPublicKey = BIO_new_mem_buf((const void*)pemKeyString.c_str(), (int)pemKeyString.length());
	BIO* bufferPrivateKey = BIO_new_mem_buf((const void*)pemKeyString.c_str(), (int)pemKeyString.length());
	
	/* Raw memory to public or private key */
	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bufferPublicKey, nullptr, nullptr, nullptr);
	if (pkey == nullptr)    /* If not public key */
	{
		pkey = PEM_read_bio_PrivateKey(bufferPrivateKey, nullptr, SuppressPassPrompt, nullptr);
		if (pkey == nullptr)    /* If not private key */
		{
			BIO_free(bufferPublicKey);
			BIO_free(bufferPrivateKey);
			throw Exceptions::PemStringToRsaFailedException("not a valid PEM format key.");
		}
	}
	
	auto keyType = EVP_PKEY_id(pkey);   /* Check if key type is RSA */
	if (keyType != EVP_PKEY_RSA && keyType != EVP_PKEY_RSA2)
	{
		EVP_PKEY_free(pkey);
		BIO_free(bufferPublicKey);
		BIO_free(bufferPrivateKey);
		throw Exceptions::NotRSAKeyException("the key is not an RSA key.");
	}
	
	std::shared_ptr<RSA> rsa(EVP_PKEY_get1_RSA(pkey), Utils::Deleter<RSA_free>());     /* Get RSA */
	EVP_PKEY_free(pkey);
	BIO_free(bufferPublicKey);
	BIO_free(bufferPrivateKey);
	
	return rsa;
}

std::shared_ptr<RSA> OpensslWrap::PEM::ToRsa(const std::string& pemKeyString, const std::string& passphrase)
{
	/* Key string to raw memory */
	BIO* bufferPublicKey = BIO_new_mem_buf((const void*)pemKeyString.c_str(), (int)pemKeyString.length());
	BIO* bufferPrivateKey = BIO_new_mem_buf((const void*)pemKeyString.c_str(), (int)pemKeyString.length());
	
	/* Raw memory to public or private key */
	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bufferPublicKey, nullptr, nullptr, nullptr);
	if (pkey == nullptr)    /* If not public key */
	{
		pkey = PEM_read_bio_PrivateKey(bufferPrivateKey, nullptr, nullptr, (void*)passphrase.c_str());
		if (pkey == nullptr)    /* If not private key */
		{
			BIO_free(bufferPublicKey);
			BIO_free(bufferPrivateKey);
			throw Exceptions::PemStringToRsaFailedException("not a valid PEM format key or passphrase incorrect.");
		}
	}
	
	auto keyType = EVP_PKEY_id(pkey);   /* Check if key type is RSA */
	if (keyType != EVP_PKEY_RSA && keyType != EVP_PKEY_RSA2)
	{
		EVP_PKEY_free(pkey);
		BIO_free(bufferPublicKey);
		BIO_free(bufferPrivateKey);
		throw Exceptions::NotRSAKeyException("the key is not an RSA key.");
	}
	
	std::shared_ptr<RSA> rsa(EVP_PKEY_get1_RSA(pkey), Utils::Deleter<RSA_free>());     /* Get RSA */
	EVP_PKEY_free(pkey);
	BIO_free(bufferPublicKey);
	BIO_free(bufferPrivateKey);
	
	return rsa;
}

std::shared_ptr<RSA> OpensslWrap::AsymmetricRSA::Create(int rsaBits)
{
	BIGNUM* bne = nullptr;
	if (BN_hex2bn(&bne, "010001") == 0)
		return nullptr;
	
	RSA* rsa = nullptr;
	rsa = RSA_new();
	if (rsa == nullptr)
	{
		BN_free(bne);
		return nullptr;
	}
	
	if (RSA_generate_key_ex(rsa, rsaBits, bne, nullptr) != 1)
	{
		BN_free(bne);
		RSA_free(rsa);
		return nullptr;
	}
	BN_free(bne);
	return std::shared_ptr<RSA>(rsa, Utils::Deleter<RSA_free>());
}

int OpensslWrap::AsymmetricRSA::KeyBits(const std::shared_ptr<const RSA>& key)
{
	return RSA_size(key.get()) * 8;
}

std::string OpensslWrap::AsymmetricRSA::PublicKeyToPEMString(const std::shared_ptr<RSA>& rsa)
{
	auto* rsaCopy = RSAPrivateKey_dup(rsa.get());
	
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == nullptr)
	{
		RSA_free(rsaCopy);
		return std::string();
	}
	
	if (PEM_write_bio_RSA_PUBKEY(bio, rsaCopy) == 1)
	{
		BUF_MEM *buffer = nullptr;
		BIO_get_mem_ptr(bio, &buffer);
		int length = buffer->length;
		std::string pemString((char*)buffer->data, length);
		BIO_free(bio);
		RSA_free(rsaCopy);
		return pemString;
	}
	else
	{
		BIO_free(bio);
		RSA_free(rsaCopy);
		return std::string();
	}
}

std::string OpensslWrap::AsymmetricRSA::PrivateKeyToPKCS8(const std::shared_ptr<RSA>& rsa)
{
	auto* rsaCopy = RSAPrivateKey_dup(rsa.get());
	EVP_PKEY* pKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pKey, rsaCopy);
	rsaCopy = nullptr;   // will be freed when EVP_PKEY_free(pKey)
	
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == nullptr)
	{
		EVP_PKEY_free(pKey);
		return std::string();
	}
	
	if (PEM_write_bio_PKCS8PrivateKey(bio, pKey, nullptr, nullptr, 0, nullptr, nullptr) == 1)
	{
		BUF_MEM *buffer = nullptr;
		BIO_get_mem_ptr(bio, &buffer);
		int length = buffer->length;
		std::string pemString((char*)buffer->data, length);
		BIO_free(bio);
		EVP_PKEY_free(pKey);
		return pemString;
	}
	else
	{
		BIO_free(bio);
		EVP_PKEY_free(pKey);
		return std::string();
	}
}

std::string OpensslWrap::AsymmetricRSA::PrivateKeyToPKCS8(const std::shared_ptr<RSA>& rsa, const EVP_CIPHER* cipherType, const std::string& passphrase)
{
	auto* rsaCopy = RSAPrivateKey_dup(rsa.get());
	EVP_PKEY* pKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pKey, rsaCopy);
	rsaCopy = nullptr;   // will be freed when EVP_PKEY_free(pKey)
	
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == nullptr)
	{
		EVP_PKEY_free(pKey);
		return std::string();
	}
	
	if (PEM_write_bio_PKCS8PrivateKey(bio, pKey, cipherType, nullptr, 0, nullptr, (void*)passphrase.c_str()) == 1)
	{
		BUF_MEM *buffer = nullptr;
		BIO_get_mem_ptr(bio, &buffer);
		int length = buffer->length;
		std::string pemString((char*)buffer->data, length);
		BIO_free(bio);
		EVP_PKEY_free(pKey);
		return pemString;
	}
	else
	{
		BIO_free(bio);
		EVP_PKEY_free(pKey);
		return std::string();
	}
}

std::string OpensslWrap::AsymmetricRSA::PrivateKeyToPKCS1(const std::shared_ptr<RSA>& rsa)
{
	auto* rsaCopy = RSAPrivateKey_dup(rsa.get());
	
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == nullptr)
	{
		RSA_free(rsaCopy);
		return std::string();
	}
	
	if (PEM_write_bio_RSAPrivateKey(bio, rsaCopy, nullptr, nullptr, 0, nullptr, nullptr) == 1)
	{
		BUF_MEM *buffer = nullptr;
		BIO_get_mem_ptr(bio, &buffer);
		int length = buffer->length;
		std::string pemString((char*)buffer->data, length);
		BIO_free(bio);
		RSA_free(rsaCopy);
		return pemString;
	}
	else
	{
		BIO_free(bio);
		RSA_free(rsaCopy);
		return std::string();
	}
}

std::string OpensslWrap::AsymmetricRSA::PrivateKeyToPKCS1(const std::shared_ptr<RSA>& rsa, const EVP_CIPHER* cipherType, const std::string& passphrase)
{
	auto* rsaCopy = RSAPrivateKey_dup(rsa.get());
	
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == nullptr)
	{
		RSA_free(rsaCopy);
		return std::string();
	}
	
	if (PEM_write_bio_RSAPrivateKey(bio, rsaCopy, cipherType, nullptr, 0, nullptr, (void*)passphrase.c_str()) == 1)
	{
		BUF_MEM *buffer = nullptr;
		BIO_get_mem_ptr(bio, &buffer);
		int length = buffer->length;
		std::string pemString((char*)buffer->data, length);
		BIO_free(bio);
		RSA_free(rsaCopy);
		return pemString;
	}
	else
	{
		BIO_free(bio);
		RSA_free(rsaCopy);
		return std::string();
	}
}

OpensslWrap::AsymmetricRSA::PublicKeyList::PublicKeyList(const std::vector<std::tuple<std::string, std::string>>& nameAndPem)
{
	for (const auto& [name, pem] : nameAndPem)
	{
		try
		{
			auto rsa = OpensslWrap::PEM::ToRsa(pem);
			std::string fingerprint = OpensslWrap::AsymmetricRSA::FingerprintSHA256(rsa);
			list[fingerprint] = std::tuple<std::string, std::shared_ptr<RSA>>(name, rsa);
		}
		catch (Exceptions::PemStringToRsaFailedException& e)
		{
			throw Exceptions::PemStringToRsaFailedException(e.what());
		}
	}
}

std::tuple<std::string, std::shared_ptr<RSA>> OpensslWrap::AsymmetricRSA::PublicKeyList::get(const std::string& SHA256fingerprint)
{
	auto notFound = list.end();
	auto nameAndKey = list.find(SHA256fingerprint);
	if (nameAndKey != notFound)
	{
		auto [name, rsa] = nameAndKey->second;
		return std::tuple<std::string, std::shared_ptr<RSA>>(name, DumpPublicKey(rsa));
	}
	else
		return std::tuple<std::string, std::shared_ptr<RSA>>("", nullptr);
}

std::string OpensslWrap::AsymmetricRSA::FingerprintMD5(const std::shared_ptr<const RSA>& rsa)
{
	if (rsa == nullptr)
		return std::string("");
	
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	/* OpenSSL < 1.1.0 */
	const BIGNUM* n = rsa->n;   const BIGNUM* e = rsa->e;   const BIGNUM* d = rsa->d;
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	/* OpenSSL >= 1.1.0 */
	const BIGNUM* n = nullptr;  const BIGNUM* e = nullptr;  const BIGNUM* d = nullptr;
	RSA_get0_key(rsa.get(), &n, &e, &d);
#endif
	int size = 0;
	int pos = 0;
	auto* buffer = (unsigned char*)malloc(0);
	
	if (n)
	{
		auto extendSize = BN_num_bytes(n) * sizeof(unsigned char);
		size += extendSize;
		buffer = static_cast<unsigned char*>(realloc(buffer, size));
		BN_bn2bin(n, buffer+pos);
		pos += extendSize;
	}
	if (e)
	{
		auto extendSize = BN_num_bytes(e) * sizeof(unsigned char);
		size += extendSize;
		buffer = static_cast<unsigned char*>(realloc(buffer, size));
		BN_bn2bin(e, buffer+pos);
	}
	
	std::byte digest[MD5_DIGEST_LENGTH];
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, buffer, size);
	MD5_Final(reinterpret_cast<unsigned char*>(digest), &ctx);
	
	std::string fingerprint;
	for (const auto& byte : digest)
	{
		char byteStr[4];
		sprintf(byteStr, "%02x:", static_cast<unsigned int>(byte)); /* xx:xx:xx:xx: */
		fingerprint += byteStr;
	}
	fingerprint.pop_back();     /* Remove a ':' at the end of string */
	
	free(buffer);
	return fingerprint;
}

std::string OpensslWrap::AsymmetricRSA::FingerprintSHA256(const std::shared_ptr<const RSA>& rsa)
{
	if (rsa == nullptr)
		return std::string("");

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	/* OpenSSL < 1.1.0 */
	const BIGNUM* n = rsa->n;   const BIGNUM* e = rsa->e;   const BIGNUM* d = rsa->d;
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	/* OpenSSL >= 1.1.0 */
	const BIGNUM* n = nullptr;  const BIGNUM* e = nullptr;  const BIGNUM* d = nullptr;
	RSA_get0_key(rsa.get(), &n, &e, &d);
#endif
	int size = 0;
	int pos = 0;
	auto* buffer = (unsigned char*)malloc(0);
	
	if (n)
	{
		auto extendSize = BN_num_bytes(n) * sizeof(unsigned char);
		size += extendSize;
		buffer = static_cast<unsigned char*>(realloc(buffer, size));
		BN_bn2bin(n, buffer+pos);
		pos += extendSize;
	}
	if (e)
	{
		auto extendSize = BN_num_bytes(e) * sizeof(unsigned char);
		size += extendSize;
		buffer = static_cast<unsigned char*>(realloc(buffer, size));
		BN_bn2bin(e, buffer+pos);
	}
	
	std::byte digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buffer, size);
	SHA256_Final(reinterpret_cast<unsigned char*>(digest), &ctx);
	
	std::string fingerprint;
	for (const auto& byte : digest)
	{
		char byteStr[4];
		sprintf(byteStr, "%02x:", static_cast<unsigned int>(byte)); /* xx:xx:xx:xx: */
		fingerprint += byteStr;
	}
	fingerprint.pop_back();     /* Remove a ':' at the end of string */
	
	free(buffer);
	return fingerprint;
}

std::shared_ptr<std::vector<std::byte>> OpensslWrap::Digest::MD5(const std::shared_ptr<const std::vector<std::byte>>& msg)
{
	auto digest = std::make_shared<std::vector<std::byte>>(MD5_DIGEST_LENGTH);
	if (digest == nullptr)
		throw Utils::AllocateMemoryFailed();
	
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, msg->data(), msg->size() * sizeof(std::byte));
	MD5_Final(reinterpret_cast<unsigned char*>(digest->data()), &ctx);
	return digest;
}

std::shared_ptr<std::vector<std::byte>> OpensslWrap::Digest::SHA256(const std::shared_ptr<const std::vector<std::byte>>& msg)
{
	auto digest = std::make_shared<std::vector<std::byte>>(SHA256_DIGEST_LENGTH);
	if (digest == nullptr)
		throw Utils::AllocateMemoryFailed();
	
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, msg->data(), msg->size() * sizeof(std::byte));
	SHA256_Final(reinterpret_cast<unsigned char*>(digest->data()), &ctx);
	return digest;
}

std::shared_ptr<RSA> OpensslWrap::AsymmetricRSA::DumpPublicKey(const std::shared_ptr<RSA>& key)
{
	return std::shared_ptr<RSA>(RSAPublicKey_dup(key.get()), Utils::Deleter<RSA_free>());
}

std::shared_ptr<RSA> OpensslWrap::AsymmetricRSA::DumpPrivateKey(const std::shared_ptr<RSA>& key)
{
	return std::shared_ptr<RSA>(RSAPrivateKey_dup(key.get()), Utils::Deleter<RSA_free>());
}

std::shared_ptr<std::vector<std::byte>>
OpensslWrap::AsymmetricRSA::PublicEncrypt(
		const std::shared_ptr<const std::vector<std::byte>>& msg,
		const std::shared_ptr<RSA>& pubKey,
		int padding)
{
	unsigned char buffer[RSA_size(pubKey.get())];
	
	int size = RSA_public_encrypt(msg->size(), (unsigned char *)msg->data(), buffer, pubKey.get(), padding);
	if (size < 0)
		throw Exceptions::EncryptFailed();
	
	auto encrypted = std::make_shared<std::vector<std::byte>>((std::byte*)buffer, (std::byte*)buffer + size);
	if (encrypted == nullptr)
		throw Utils::AllocateMemoryFailed();
	
	return encrypted;
}

std::shared_ptr<std::vector<std::byte>>
OpensslWrap::AsymmetricRSA::PrivateDecrypt(
		const std::shared_ptr<const std::vector<std::byte>>& ciphertext,
		const std::shared_ptr<RSA>& privKey,
		int padding)
{
	unsigned char buffer[RSA_size(privKey.get())];
	
	int size = RSA_private_decrypt(ciphertext->size(), (unsigned char *)ciphertext->data(), buffer, privKey.get(), padding);
	if (size < 0)
		throw Exceptions::DecryptFailed();
	
	auto decrypted = std::make_shared<std::vector<std::byte>>((std::byte*)buffer, (std::byte*)buffer + size);
	if (decrypted == nullptr)
		throw Utils::AllocateMemoryFailed();
	
	return decrypted;
}

std::shared_ptr<std::vector<std::byte>>
OpensslWrap::AsymmetricRSA::Sign(
		const std::shared_ptr<const std::vector<std::byte>>& msg,
		const std::shared_ptr<RSA>& privKey,
		int type)
{
	unsigned char sig[RSA_size(privKey.get())];
	unsigned int sigSize = 0;
	int ret = RSA_sign(type, (const unsigned char*)msg->data(), (unsigned int)msg->size(), sig, &sigSize, privKey.get());
	if (ret != 1)
		throw Exceptions::SignFailed();
	
	return std::make_shared<std::vector<std::byte>>((std::byte*)sig, (std::byte*)sig + sigSize);
}

std::shared_ptr<std::vector<std::byte>>
OpensslWrap::AsymmetricRSA::RS256(
		const std::shared_ptr<const std::vector<std::byte>>& msg,
		const std::shared_ptr<RSA>& privateKey)
{
	std::shared_ptr<std::vector<std::byte>> digest = nullptr;
	try
	{
		digest = Digest::SHA256(msg);
	}
	catch (Utils::AllocateMemoryFailed& e)
	{
		throw Utils::AllocateMemoryFailed();
	}
	
	std::shared_ptr<std::vector<std::byte>> signature = nullptr;
	try
	{
		signature = AsymmetricRSA::Sign(digest, privateKey, NID_sha256);
	}
	catch (Exceptions::SignFailed& e)
	{
		throw OpensslWrap::Exceptions::SignFailed();
	}
	
	return signature;
}

/* Used by OpensslWrap::CreateSANCertificateSigningRequest() */
int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, const char *value)
{
	X509_EXTENSION *ex = nullptr;
	ex = X509V3_EXT_conf_nid(nullptr, nullptr, nid, value);
	if (ex == nullptr)
		return 0;
	sk_X509_EXTENSION_push(sk, ex);
	return 1;
}

std::shared_ptr<X509_REQ>
OpensslWrap::CreateSANCertificateSigningRequest(
		const std::string& commonName,
		const std::vector<std::string>& subjectAltNames,
		const std::shared_ptr<RSA>& privateKey)
{
	/* Make a copy */
	auto* rsaCopy = RSAPrivateKey_dup(privateKey.get());
	
	/* Set x509 req version */
	X509_REQ* x509_req = X509_REQ_new();
	if (X509_REQ_set_version(x509_req, 0) != 1)
	{
		X509_REQ_free(x509_req);
		return nullptr;
	}
	
	/* Set common name */
	X509_NAME* name = X509_NAME_new();
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName.c_str()), -1, -1, 0);
	if (X509_REQ_set_subject_name(x509_req, name) != 1)
	{
		X509_NAME_free(name);
		X509_REQ_free(x509_req);
		return nullptr;
	}
	X509_NAME_free(name);
	
	/* Add subject alternative names */
	stack_st_X509_EXTENSION* exts = sk_X509_EXTENSION_new_null();
	std::string altNamesStr;
	for (const auto& altName : subjectAltNames)
		altNamesStr += ("DNS:"+altName+",");
	altNamesStr.pop_back(); // Delete the trailing comma
	
	auto ret = add_ext(exts, NID_subject_alt_name, altNamesStr.c_str());
	if (ret != 1)
	{
		X509_REQ_free(x509_req);
		return nullptr;
	}
	
	if (X509_REQ_add_extensions(x509_req, exts) != 1)
	{
		X509_REQ_free(x509_req);
		return nullptr;
	}
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	
	/* Set public key of x509 req */
	EVP_PKEY* pKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pKey, rsaCopy);
	rsaCopy = nullptr;   // will be freed when EVP_PKEY_free(pKey)
	if (X509_REQ_set_pubkey(x509_req, pKey) != 1)
	{
		EVP_PKEY_free(pKey);
		X509_REQ_free(x509_req);
		return nullptr;
	}
	
	/* Set signature */
	if (X509_REQ_sign(x509_req, pKey, EVP_sha256()) <= 0)   // return x509_req->signature->length
	{
		EVP_PKEY_free(pKey);
		X509_REQ_free(x509_req);
		return nullptr;
	}
	
	EVP_PKEY_free(pKey);
	return std::shared_ptr<X509_REQ>(x509_req, Utils::Deleter<X509_REQ_free>());
}

std::string OpensslWrap::X509reqToPKCS10(const std::shared_ptr<X509_REQ>& csr)
{
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == nullptr)
		return std::string();
	if (PEM_write_bio_X509_REQ(bio, csr.get()) == 1)
	{
		BUF_MEM *buffer = nullptr;
		BIO_get_mem_ptr(bio, &buffer);
		int length = buffer->length;
		std::string pemString((char*)buffer->data, length);
		BIO_free(bio);
		return pemString;
	}
	return std::string();
}

std::shared_ptr<std::vector<std::byte>> OpensslWrap::X509reqToDER(const std::shared_ptr<X509_REQ>& csr)
{
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == nullptr)
		return nullptr;
	if (i2d_X509_REQ_bio(bio, csr.get()) == 1)
	{
		BUF_MEM *buffer = nullptr;
		BIO_get_mem_ptr(bio, &buffer);
		auto ptr = std::make_shared<std::vector<std::byte>>((std::byte*)buffer->data, (std::byte*)buffer->data + buffer->length);
		BIO_free(bio);
		return ptr;
	}
	return nullptr;
}

int OpensslWrap::AES256CBC::KeyIV(const std::string& passphrase, unsigned char* salt, unsigned char* key, unsigned char* iv)
{
	int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, reinterpret_cast<const unsigned char*>(passphrase.c_str()), passphrase.size(), 14, key, iv);
	if (i != 32)
		return 0;
	return 1;
}

std::shared_ptr<std::vector<std::byte>> OpensslWrap::AES256CBC::Encrypt(const std::shared_ptr<std::vector<std::byte>>& msg, const std::string& passphrase)
{
	unsigned char key[32];
	unsigned char iv[AES_BLOCK_SIZE];
	if (KeyIV(passphrase, nullptr, key, iv) != 1)
		throw OpensslWrap::Exceptions::EncryptFailed();
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr)
		throw OpensslWrap::Exceptions::EncryptFailed();
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int cipherLen = (int)msg->size() + AES_BLOCK_SIZE, f_len = 0;
	auto* ciphertext = static_cast<unsigned char*>(malloc(cipherLen));
	
	/* Init */
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
	{
		free(ciphertext);
		EVP_CIPHER_CTX_free(ctx);
		throw OpensslWrap::Exceptions::EncryptFailed();
	}
	
	/* Update */
	auto* copy = (unsigned char*)malloc(msg->size());
	for (unsigned int i = 0; i < msg->size(); ++i)
		copy[i] = static_cast<unsigned char>(msg->at(i));
	if (EVP_EncryptUpdate(ctx, ciphertext, &cipherLen, copy, msg->size()) != 1)
	{
		free(copy);
		free(ciphertext);
		EVP_CIPHER_CTX_free(ctx);
		throw OpensslWrap::Exceptions::EncryptFailed();
	}
	
	/* Update ciphertext with the final remaining bytes */
	if (EVP_EncryptFinal_ex(ctx, ciphertext+cipherLen, &f_len) != 1)
	{
		free(copy);
		free(ciphertext);
		EVP_CIPHER_CTX_free(ctx);
		throw OpensslWrap::Exceptions::EncryptFailed();
	}
	cipherLen += f_len;
	
	auto cipherBytes = std::make_shared<std::vector<std::byte>>((std::byte*)ciphertext, (std::byte*)ciphertext + cipherLen);
	free(copy);
	free(ciphertext);
	EVP_CIPHER_CTX_free(ctx);
	
	return cipherBytes;
}

std::shared_ptr<std::vector<std::byte>> OpensslWrap::AES256CBC::Decrypt(const std::shared_ptr<std::vector<std::byte>>& cipher, const std::string& passphrase)
{
	unsigned char key[32];
	unsigned char iv[AES_BLOCK_SIZE];
	if (KeyIV(passphrase, nullptr, key, iv) != 1)
		throw OpensslWrap::Exceptions::EncryptFailed();
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr)
		throw OpensslWrap::Exceptions::EncryptFailed();
	/* plaintext will always be equal to or lesser than length of ciphertext*/
	int plainLen = cipher->size(), f_len = 0;
	auto* plaintext = static_cast<unsigned char*>(malloc(plainLen));
	
	/* Init */
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
	{
		free(plaintext);
		EVP_CIPHER_CTX_free(ctx);
		throw OpensslWrap::Exceptions::EncryptFailed();
	}
	
	/* Update */
	auto* copy = (unsigned char*)malloc(cipher->size());
	for (unsigned int i = 0; i < cipher->size(); ++i)
		copy[i] = static_cast<unsigned char>(cipher->at(i));
	if (EVP_DecryptUpdate(ctx, plaintext, &plainLen, copy, cipher->size()) != 1)
	{
		free(copy);
		free(plaintext);
		EVP_CIPHER_CTX_free(ctx);
		throw OpensslWrap::Exceptions::EncryptFailed();
	}
	
	/* Final */
	if (EVP_DecryptFinal_ex(ctx, plaintext+plainLen, &f_len) != 1)
	{
		free(copy);
		free(plaintext);
		EVP_CIPHER_CTX_free(ctx);
		throw OpensslWrap::Exceptions::EncryptFailed();
	}
	plainLen += f_len;
	
	auto plainBytes = std::make_shared<std::vector<std::byte>>((std::byte*)plaintext, (std::byte*)plaintext + plainLen);
	free(copy);
	free(plaintext);
	EVP_CIPHER_CTX_free(ctx);
	
	return plainBytes;
}
