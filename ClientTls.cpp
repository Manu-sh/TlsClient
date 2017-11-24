#include "ClientTls.hpp"

ClientTls::ClientTls(const std::string &servername, const std::string &port) {
	ca = NULL;
	if (!(client = TlsClient_new(servername.c_str(), port.c_str())))
		throw std::runtime_error("Initialization Exception: invalid arguments or memory insufficient");
}

bool ClientTls::loadCA(const std::string &ca) {
	return TlsClient_loadCA(client, (this->ca = ca.c_str()));
}

bool ClientTls::doHandshake() {

	bool res = (!ca && !loadCA()) ? false : TlsClient_doHandShake(client, -1);
	if (!res) return false;

	hostname = std::string(client->hsinfo->hostname);
	ip	 = std::string(client->hsinfo->ip);
	port	 = std::string(client->hsinfo->port);
	cipher	 = std::string(SSL_get_cipher(client->ssl));

	for (char *crt = X509_NAME_oneline(X509_get_subject_name(client->cert), NULL, 0); crt;) {
		this->crt = std::string(crt);
		free(crt);
		return true;
	}

	return false;
}

const char * ClientTls::getError() {
	return TlsClient_getError(client);
}

ClientTls::~ClientTls() {
	TlsClient_free(client);
}

int ClientTls::read(void *buf, int size) const {
	return SSL_read(client->ssl, buf, size);
}

int ClientTls::write(const void *buf, int size) {
	return SSL_write(client->ssl, buf, size);
}

void ClientTls::skSpecialIO(const std::string &st) {

	int len;
	char buf[1536] = {};
	const char *s = st.c_str();

	if (write(s, strlen(s)) < 0)
		return;

	while ((len = read(buf, sizeof buf)) > 0) {
		std::cout << buf << "\n";
		memset(buf, 0, sizeof buf);
	}

}

void ClientTls::printCRT() {

	X509_NAME *crt_name;

	if (!(crt_name = X509_get_subject_name(client->cert))) {
		std::cerr << "[ERR] Can't print certificate\n";
		return;
	}

	std::cout << "\nCRT presented by server: \"";
	X509_NAME_print_ex_fp(stdout, crt_name, 0, XN_FLAG_MULTILINE);
	std::cout << "\"\n\n";
}

int ClientTls::shutdown() {
	return SSL_shutdown(client->ssl);
}

std::ostream & operator<<(std::ostream &s, const ClientTls &c) {
	return s << std::string("hostname: "+c.hostname +"\nip: "+ c.ip +"\nport: "+ c.port +"\ncipher: "+ c.cipher +"\ncrt: "+ c.crt+"\n");
}
