#include "TlsClient.h"

#define ERR_GET_STR() ERR_reason_error_string(ERR_peek_error())

#define VFY_DEPTH 10

void TlsClient_free(TlsClient *cl) {
	if (!cl) return;
	if (cl->tcp_sk != -1) close(cl->tcp_sk);
	SSL_free(cl->ssl);
	SSL_CTX_free(cl->ctx);
	X509_free(cl->cert);
	free(cl->hsinfo);
	free(cl->errinfo);
	free(cl);
}

const char * TlsClient_getError(TlsClient *cl) { return cl->errinfo->ebuf; }

/* Initialization: this return a new Tls Client structure, or null in case of insuccess */
TlsClient * TlsClient_new(const char *hostname, const char *port) {

	TlsClient *cl;

	if (!hostname || !port || strcmp(port, "") == 0 || !(cl = (TlsClient *)calloc(1, sizeof(TlsClient)))) 
		return NULL;

	if (!(cl->hsinfo = (HostInfo *)calloc(1, sizeof(HostInfo)))) {
		free(cl);
		return NULL;
	}

	if (!(cl->errinfo = (ErrInfo *)calloc(1, sizeof(ErrInfo)))) {
		free(cl->hsinfo);
		free(cl);
		return NULL;
	}

	strncpy(cl->hsinfo->hostname, hostname, HOST_NAME_MAX);
	strncpy(cl->hsinfo->port, port, PORT_MAX);
	cl->tcp_sk = -1;

	if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL)) {
		free(cl->hsinfo);
		free(cl->errinfo);
		free(cl);
		return NULL;
	}

	if (!(cl->ctx = SSL_CTX_new(TLS_client_method()))) {
		free(cl->hsinfo);
		free(cl->errinfo);
		free(cl);
		return NULL;
	}

	SSL_CTX_set_verify(cl->ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(cl->ctx, VFY_DEPTH);

	// exclude old protocol version
	SSL_CTX_set_min_proto_version(cl->ctx, TLS1_VERSION);
	SSL_CTX_set_max_proto_version(cl->ctx, TLS1_2_VERSION);

	// TODO create my own callback ?
	// SSL_CTX_set_cert_verify_callback(cl->ctx, NULL, NULL);

	return cl;
}

// set CA file or folder for crt validation sent by the host, two default value CA_FILE, and CA_CERT (should be renamed)
// are defined into TlsClient.h
bool TlsClient_loadCA(TlsClient *cl, const char *ca) {

	if (!cl || !ca || strcmp(ca, "") == 0) {
		seterr(cl, "TlsClient_loadCA(): ", "Invalid arguments");
		return false;
	}

	int fd = open(ca, O_RDONLY|O_NONBLOCK);
	struct stat status;

	if (fd == -1) {
		seterr(cl, "open(): ", strerror(errno));
		return false;
	}

	if (fstat(fd, &status) != 0) {
		seterr(cl, "fstat(): ", strerror(errno));
		goto fail;
	}

	switch (status.st_mode & S_IFMT) {
		case S_IFREG:
			SSL_CTX_set_verify_depth(cl->ctx, VFY_DEPTH);
			if ((SSL_CTX_load_verify_locations(cl->ctx, ca, NULL)) != 1) {
				seterr(cl, "SSL_CTX_load_verify_locations():", "load ca from path: failure");
				goto fail;
			}
			break;
		case S_IFDIR:
			if ((SSL_CTX_load_verify_locations(cl->ctx, NULL, ca)) != 1) {
				seterr(cl, "SSL_CTX_load_verify_locations():", "load ca from path: failure");
				goto fail;
			}
			break;
		default:
			seterr(cl, "SslClient_loadCA(): ", "the ca argument must to be a directory path or a regular file");
			goto fail;
	}


	close(fd);
	return true;

fail:
	close(fd);
	return false;
}

// provide an existing tcp socket to use or -1
bool TlsClient_doHandShake(TlsClient *cl, int sk) {

	if ((cl->tcp_sk = sk) == -1 && !TlsClient_doTcp(cl))
		return false;

	if (!(cl->ssl = SSL_new(cl->ctx))) {
		seterr(cl, "SSL_new(): ", ERR_GET_STR());
		return false;
	}

	if (SSL_set_fd(cl->ssl, cl->tcp_sk) != 1) {
		seterr(cl, "SSL_set_fd(): ", ERR_GET_STR());
		return false;
	}

	SSL_set_mode(cl->ssl, SSL_MODE_AUTO_RETRY);

	// SSL_connect() == SSL_set_connect_state(cl->ssl) (required for setting ssl handshake in client mode) + SSL_do_handshake()
	if (SSL_connect(cl->ssl) != 1) {
		seterr(cl, "SSL_connect(): ", ERR_GET_STR());
		return false;
	}

	if (!(cl->cert = SSL_get_peer_certificate(cl->ssl))) {
		seterr(cl, "SSL_get_peer_certificate(): ", "no crt presented");
		return false;
	}

	return true;

}
