#include "uvhttp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void on_request_complete(http_request_t* req) {
    printf("Request received: ");
    uvhttp_string_slice_t method = http_request_method(req);
    uvhttp_slice_print(&method);
    printf(" ");
    uvhttp_string_slice_t target = http_request_target(req);
    uvhttp_slice_print(&target);
    printf("\n");

    const char* body = "Hello, World!";
    http_respond_simple(req, 200, "text/plain", body, strlen(body));
}

int main(int argc, char *argv[]) {
    int port = 8080;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    uv_loop_t* loop = uv_default_loop();

    http_server_config_t config = {
        .host = "0.0.0.0",
        .port = port,
        .on_complete = on_request_complete,
        .tls_enabled = 0, // TLS is disabled
        .max_body_size = 8 * 1024 * 1024 // 8MB
    };

    http_server_t* server = http_server_create(loop, &config);
    if (!server) {
        fprintf(stderr, "Failed to create server.\n");
        return 1;
    }

    if (http_server_listen(server) != 0) {
        fprintf(stderr, "Failed to listen on http://%s:%d\n", config.host, config.port);
        return 1;
    }

    printf("Server listening on http://%s:%d\n", config.host, config.port);
    
    uv_run(loop, UV_RUN_DEFAULT);

    http_server_destroy(server);
    return 0;
}