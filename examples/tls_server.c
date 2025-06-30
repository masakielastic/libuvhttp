#include "uvhttp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>

void on_request_complete(uvhttp_request_t* req) {
    printf("Request received: ");
    uvhttp_str_t method = uvhttp_request_method(req);
    uvhttp_str_print(&method);
    printf(" ");
    uvhttp_str_t target = uvhttp_request_target(req);
    uvhttp_str_print(&target);
    printf("\n");

    const char* body = "Hello, World with TLS!";
    uvhttp_respond_simple(req, 200, "text/plain", body, strlen(body));
}

int main(int argc, char *argv[]) {
    int port = 8443;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    uv_loop_t* loop = uv_default_loop();

    uvhttp_server_config_t config = {
        .host = "0.0.0.0",
        .port = port,
        .on_complete = on_request_complete,
    };

    uvhttp_server_t* server = uvhttp_server_create(loop, &config);
    if (!server) {
        fprintf(stderr, "Failed to create server.\n");
        return 1;
    }

    // --- Custom OpenSSL Configuration ---
    SSL_CTX* ssl_ctx = uvhttp_server_get_ssl_ctx(server);
    
    // Example: Disable TLS 1.0 and 1.1
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    // Load certificate and key
    if (SSL_CTX_use_certificate_file(ssl_ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load TLS certificate/key\n");
        uvhttp_server_destroy(server);
        return 1;
    }
    // --- End of Custom OpenSSL Configuration ---

    if (uvhttp_server_listen(server) != 0) {
        fprintf(stderr, "Failed to listen on https://%s:%d\n", config.host, config.port);
        return 1;
    }

    printf("Server listening on https://%s:%d\n", config.host, config.port);

    uv_run(loop, UV_RUN_DEFAULT);

    uvhttp_server_destroy(server);
    return 0;
}