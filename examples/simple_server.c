#include "uvhttp.h"
#include <stdio.h>
#include <string.h>

// Request handler
void my_handler(http_request_t* req) {
    printf("Request received: %s %s\n", http_request_method(req), http_request_target(req));

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

int main() {
    http_server_config_t config = {
        .host = "0.0.0.0",
        .port = 8080,
        .handler = my_handler,
        .tls_enabled = 0 // TLS is disabled
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
