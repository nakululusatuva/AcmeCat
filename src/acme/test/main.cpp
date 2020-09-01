//
// Created by nova on 8/29/20.
//

int main(int argc, char* args[])
{
	Acme::API acmeAPI(configs);
	std::tuple<std::string, std::string, std::string> certsAndPrivateKey;
	try {
		certsAndPrivateKey = acmeAPI.issueCertificate();
	} catch (Acme::IssueCertificateFailed& e) { exit(1); }
	auto[endEntityCertPEM, issuerCertPEM, privateKeyPKCS8] = certsAndPrivateKey;
	Certification cert;
	cert.update(endEntityCertPEM, issuerCertPEM, privateKeyPKCS8);
	cert.toFile("/home/nova/Data/Github/acmecat/devres/new_certs");
}