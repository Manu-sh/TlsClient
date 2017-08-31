#include "lib/TlsClient.h"
#define HOST_RESOURCE "/"

int main(int argc, char **argv) {

	TlsClient *client;
	const char *ca = CA_FILE;

	if (!(client = TlsClient_new(argv[1], "443"))) {
		fprintf(stderr, "err init\n");
		return EXIT_FAILURE;
	}

	if (!TlsClient_loadCA(client, ca))
		goto failure;

	if (!TlsClient_doHandShake(client, -1))
		goto failure;

	printf("%s [OK]\n", client->hsinfo->hostname);
	TlsClient_free(client);
	return EXIT_SUCCESS;

failure:
	printf("%s [BAD]\n", client->hsinfo->hostname);
	printf("error: %s\n", TlsClient_getError(client));
	TlsClient_free(client);
	return EXIT_FAILURE;

}
