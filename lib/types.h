#pragma once
#include <stdbool.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x1010006f
	#error "require openssl lib >= 1.1.0f"
#endif

#ifdef HOST_NAME_SZ
	#error "redefinition of HOST_NAME_SZ"
#elif defined(PORT_MAX)
	#error "redefinition of PORT_MAX"
#elif defined(EBSIZE)
	#error "redefinition of EBSIZE"
#elif defined(TRUE) || defined(FALSE)
	#error "redefinition of boolean constant TRUE, FALSE"
#endif

#define EBSIZE 4096
#define PORT_MAX 10

// #define IM_NOT_A_VALID_SK -1
#define FALSE false
#define TRUE  true

typedef struct _host {
	char hostname[HOST_NAME_MAX+1];
	char port[PORT_MAX+1];
	char ip[INET_ADDRSTRLEN+1];
} HostInfo;

typedef struct _errinfo {  char ebuf[EBSIZE];  } ErrInfo;

struct _tlsclient {
	SSL_CTX    *ctx;
	SSL	   *ssl;
	X509	   *cert;
	HostInfo   *hsinfo;
	ErrInfo    *errinfo;
	int	   tcp_sk;
};

typedef struct _tlsclient TlsClient;
extern int errno, h_errno;
