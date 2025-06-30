#include "uvhttp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

    // NOTE: You must provide your own cert.pem and key.pem files.
    // For testing, you can generate a self-signed certificate:
    // openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365
    uvhttp_server_config_t config = {
        .host = "0.0.0.0",
        .port = port,
        .on_complete = on_request_complete,
        .tls_enabled = 1, // Enable TLS
        .cert_file = "cert.pem",
        .key_file = "key.pem",
        .max_body_size = 8 * 1024 * 1024 // 8MB
    };

    uvhttp_server_t* server = uvhttp_server_create(loop, &config);
    if (!server) {
        fprintf(stderr, "Failed to create server. Check if cert.pem and key.pem exist.\n");
        return 1;
    }

    if (uvhttp_server_listen(server) != 0) {
        fprintf(stderr, "Failed to listen on https://%s:%d\n", config.host, config.port);
        return 1;
    }

    printf("Server listening on https://%s:%d\n", config.host, config.port);

    uv_run(loop, UV_RUN_DEFAULT);

    uvhttp_server_destroy(server);
    return 0;
}