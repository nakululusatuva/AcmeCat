//
// Created by nova on 8/28/20.
//

int main(int argc, char* args[])
{
	/* AES256CBC test */
	std::string msg("hello world?");
	auto msgBytes = Utils::StringProcess::StringToByteVec(msg);
	auto cipherBytes = OpensslWrap::AES256CBC::Encrypt(msgBytes, "123456");
	std::cout << "cipher: " << Utils::Codec::Base64UrlEncode(cipherBytes) << std::endl;
	auto plainBytes = OpensslWrap::AES256CBC::Decrypt(cipherBytes, "123456");
	std::cout << "plain: " << Utils::StringProcess::ByteVecToString(plainBytes) << std::endl << std::endl;
	
	/* Keys */
	auto serverPrivate = OpensslWrap::AsymmetricRSA::Create(2048);
	auto serverPublic  = OpensslWrap::AsymmetricRSA::DumpPublicKey(serverPrivate);
	auto clientPrivate = OpensslWrap::AsymmetricRSA::Create(2048);
	auto clientPublic  = OpensslWrap::AsymmetricRSA::DumpPublicKey(clientPrivate);
	
	/* Client identity */
	auto clientFingerprint = OpensslWrap::AsymmetricRSA::FingerprintSHA256(clientPublic);
	auto clientIdentity = Protocol::ClientIdentity(clientFingerprint, serverPublic);
	auto decryptedFingerprint = Protocol::DecryptClientIdentify(clientIdentity, serverPrivate);
	std::cout << clientFingerprint << std::endl << decryptedFingerprint << std::endl << std::endl;
	
	/* Token */
	auto token = Protocol::RandomToken();
	auto encryptedToken = Protocol::AuthorizeToken(token, clientPublic);
	auto decryptedToken = Protocol::DecryptAuthorizeToken(encryptedToken, clientPrivate);
	std::cout << token << std::endl << decryptedToken << std::endl << std::endl;
	
	/* certificate */
	Json::Value json;
	json["cert"] = endEntityCertPEM;
	json["fullchain"] = endEntityCertPEM + "\n\n" + issuerCertPEM;
	json["privateKey"] = privateKeyPKCS8;
	auto encryptedCert = Protocol::CertificateData(json, "123456");
	auto decryptedCert = Protocol::DecryptCertificateData(encryptedCert, "123456");
	std::cout << decryptedCert.toStyledString() << std::endl;
}