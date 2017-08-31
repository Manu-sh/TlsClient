#pragma once
extern "C" {
	#include "lib/TlsClient.h"
}

#include <iostream>
#include <stdexcept>

class ClientTls {

	private:
		TlsClient   *client;
		std::string crt, hostname, port, cipher, ip;
		const char  *ca;

	public:
		ClientTls(const std::string &servername = "google.com", const std::string &port = "443"); // throw(std::string &); deprecated
		~ClientTls();
		bool loadCA(const std::string &ca = CA_FILE);
		bool doHandshake();
		const char * getError();
		int read(void *buf, int size);
		int write(const void *buf, int size);
		void skSpecialIO(const std::string &buf);
		void printCRT();
		int shutdown();
		std::string getHostname();
		std::string getIp();
		std::string getPort();
		std::string getCipher();
		std::string getCrt();
		friend std::ostream & operator<<(std::ostream &s, const ClientTls &c);
};
