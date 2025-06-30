#include "uvhttp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Request handler
void my_handler(http_request_t* req) {
    printf("Request received: ");
    uvhttp_string_slice_t method = http_request_method(req);
    uvhttp_slice_print(&method);
    printf(" ");
    uvhttp_string_slice_t target = http_request_target(req);
    uvhttp_slice_print(&target);
    printf("\n");

    // Create a response
    http_response_t* res = http_response_init();
    http_response_status(res, 200);
    http_response_header(res, "Content-Type", "text/plain");
    const char* body = "Hello, World!";
    http_response_body(res, body, strlen(body));

    // Send the response
    http_respond(req, res);

    // Destroy the response object
    http_response_destroy(res);
}

int main(int argc, char *argv[]) {
    int port = 8080;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    http_server_config_t config = {
        .host = "0.0.0.0",
        .port = port,
        .handler = my_handler,
        .tls_enabled = 0, // TLS is disabled
        .max_body_size = 8 * 1024 * 1024 // 8MB
    };

    http_server_t* server = http_server_create(&config);
    if (!server) {
        fprintf(stderr, "Failed to create server.\n");
        return 1;
    }

    printf("Server listening on http://%s:%d\n", config.host, config.port);
    http_server_listen(server);

    http_server_destroy(server);
    return 0;
}
