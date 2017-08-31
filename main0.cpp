#include "ClientTls.hpp"

#define HOST_RESOURCE "/"

int main(int argc, char **argv) {

	using std::cerr;
	using std::cout;

	if (argc < 2) {
		cerr << "usage: " << argv[0] << " host.com\n";
		return EXIT_FAILURE;
	}

	try {
	
		ClientTls client(argv[1], "443");

		if (!client.loadCA()) {
			cerr << "error: " << client.getError() << "\n";
			return EXIT_FAILURE;
		}

		if (!client.doHandshake()) {
			cerr << "error: " << client.getError() << "\n";
			return EXIT_FAILURE;
		}

		client.printCRT();
		cout << "HOST: "   << client.getHostname() << "\n";
		cout << "IP: "     << client.getIp()       << "\n";
		cout << "PORT: "   << client.getPort()     << "\n";
		cout << "CIPHER: " << client.getCipher()   << "\n";
		cout << "CRT: "    << client.getCrt()      << "\n\n";
		client.skSpecialIO("GET " HOST_RESOURCE " HTTP/1.1\r\n" "Connection: close\r\n\r\n");

	} catch (const std::string &e) { 
		cerr << e << "\n";
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;

}
