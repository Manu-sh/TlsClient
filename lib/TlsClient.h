#pragma once

#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/opensslv.h>

#ifndef HOST_NAME_MAX
	#define HOST_NAME_MAX 64
#endif

#if OPENSSL_VERSION_NUMBER < 0x1010006f
	#error "require openssl lib >= 1.1.0f"
#endif


#ifdef HOST_NAME_SZ
	#error "redefinition of HOST_NAME_SZ"
#elif defined(PORT_MAX)
	#error "redefinition of PORT_MAX"
#elif defined(EBSIZE)
	#error "redefinition of EBSIZE"
#endif

#define EBSIZE 4096
#define PORT_MAX 10
#define CA_CERT "/etc/ssl/certs"
#define CA_FILE "/etc/ssl/certs/ca-certificates.crt"

typedef struct {
	char hostname[HOST_NAME_MAX+1];
	char port[PORT_MAX+1];
	char ip[INET_ADDRSTRLEN+1];
} HostInfo;

typedef struct {  char ebuf[EBSIZE];  } ErrInfo;

typedef struct {
	SSL_CTX    *ctx;
	SSL	   *ssl;
	X509	   *cert;
	HostInfo   *hsinfo;
	ErrInfo    *errinfo;
	int	   tcp_sk;
} TlsClient;

extern int errno, h_errno;

const char * TlsClient_getError(TlsClient *cl);
TlsClient  * TlsClient_new(const char *hostname, const char *port);

void TlsClient_free(TlsClient *cl);
bool TlsClient_loadCA(TlsClient *cl, const char *ca);
bool TlsClient_doHandShake(TlsClient *cl, int sk);

static void seterr(TlsClient *cl, const char *fname, const char *msg) {

	if (!cl || !cl->errinfo) return;

	if (!fname && msg)
		snprintf(cl->errinfo->ebuf, EBSIZE, "%s", msg);

	if (fname && msg)
		snprintf(cl->errinfo->ebuf, EBSIZE, "%s %s", fname, msg);

	if ((fname && !msg) || (!fname && !msg))
		seterr(cl, "Internal error seterr():", "invalid arguments");
}

static bool hostres(TlsClient *cl) {

	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sk;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family   = AF_INET;    /* AF_UNSPEC Allow IPv4 and IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	for (int ret = getaddrinfo(cl->hsinfo->hostname, cl->hsinfo->port, &hints, &result); ret != 0;) {
		seterr(cl, "getaddrinfo(): ", gai_strerror(ret));
		return false;
	}

	/* getaddrinfo() returns a list of address structures. Try each address until we successfully connect(2).
	   If socket(2) (or connect(2)) fails, we (close the socket and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (((sk = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) != -1) && connect(sk, rp->ai_addr, rp->ai_addrlen) != -1) {

			/* In memory, the struct sockaddr_in and struct sockaddr_in6 share the same beginning structure as struct sockaddr, 
			and you can freely cast the pointer of one type to the other without any harm, except the possible end of the universe.
			http://beej.us/guide/bgnet/output/html/multipage/sockaddr_inman.html */

			struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
			strncpy(cl->hsinfo->ip, inet_ntoa(ipv4->sin_addr), INET_ADDRSTRLEN); // see note *1

			close(sk);
			freeaddrinfo(result);
			return true;	
		}

		close(sk);
	}


	freeaddrinfo(result);
	return false;
}

static bool TlsClient_doTcp(TlsClient *cl) {

	if (!hostres(cl)) {
		seterr(cl, "hostres():", "Unknown host");
		return false;
	}

	struct sockaddr_in sockdata;
	memset(&sockdata, 0, sizeof(struct sockaddr_in));

	sockdata.sin_port = htons((uint16_t)atoi(cl->hsinfo->port));
	sockdata.sin_family = AF_INET;

	if ((cl->tcp_sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		seterr(cl, "socket(): ", gai_strerror(h_errno));
		return false;
	}


	if (inet_pton(AF_INET, cl->hsinfo->ip, &sockdata.sin_addr) != 1) {
		seterr(cl, "inet_pton(): ", strerror(errno));
		return false;
	}

	if (connect(cl->tcp_sk, (struct sockaddr *)&sockdata, sizeof(sockdata)) < 0) {
		seterr(cl, "connect(): ", strerror(errno));
		return false;
	}

	return true;
}

#if 0
static const char * crt_strerror(int err) {

	switch(err) {

		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			return "UNABLE_TO_DECRYPT_CERT_SIGNATURE";

		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
			return "UNABLE_TO_DECRYPT_CRL_SIGNATURE";

		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			return "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";

		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
			return "CERT_SIGNATURE_FAILURE";

		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			return "CRL_SIGNATURE_FAILURE";

		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			return "ERROR_IN_CERT_NOT_BEFORE_FIELD";

		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			return "ERROR_IN_CERT_NOT_AFTER_FIELD";

		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
			return "ERROR_IN_CRL_LAST_UPDATE_FIELD";

		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			return "ERROR_IN_CRL_NEXT_UPDATE_FIELD";

		case X509_V_ERR_CERT_NOT_YET_VALID:
			return "CERT_NOT_YET_VALID";

		case X509_V_ERR_CERT_HAS_EXPIRED:
			return "CERT_HAS_EXPIRED";

		case X509_V_ERR_OUT_OF_MEM:
			return "OUT_OF_MEM";

		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			return "UNABLE_TO_GET_ISSUER_CERT";

		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			return "UNABLE_TO_GET_ISSUER_CERT_LOCALLY";

		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			return "UNABLE_TO_VERIFY_LEAF_SIGNATURE";

		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			return "DEPTH_ZERO_SELF_SIGNED_CERT";

		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			return "SELF_SIGNED_CERT_IN_CHAIN";

		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			return "CERT_CHAIN_TOO_LONG";

		case X509_V_ERR_CERT_REVOKED:
			return "CERT_REVOKED";

		case X509_V_ERR_INVALID_CA:
			return "INVALID_CA";

		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			return "PATH_LENGTH_EXCEEDED";

		case X509_V_ERR_INVALID_PURPOSE:
			return "INVALID_PURPOSE";

		case X509_V_ERR_CERT_UNTRUSTED:
			return "CERT_UNTRUSTED";

		case X509_V_ERR_CERT_REJECTED:
			return "CERT_REJECTED";

		case X509_V_ERR_UNABLE_TO_GET_CRL:
			return "UNABLE_TO_GET_CRL";

		case X509_V_ERR_CRL_NOT_YET_VALID:
			return "CRL_NOT_YET_VALID";

		case X509_V_ERR_CRL_HAS_EXPIRED:
			return "CRL_HAS_EXPIRED";

	}

	return "Unknown verify error";
}
#endif
