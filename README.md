# libuvhttp

A simple and high-performance HTTP/1.1 server library built on `libuv` and `llhttp`.

`libuvhttp` is a single-header library designed for ease of use and high performance. It leverages the asynchronous I/O capabilities of `libuv` and the efficiency of the `llhttp` parser. It features a zero-copy parsing approach for headers to minimize overhead and supports TLS for secure connections via OpenSSL.

## Features

-   **Asynchronous I/O**: Built on `libuv` for non-blocking network I/O.
-   **Fast Parsing**: Uses `llhttp`, the high-performance parser from the Node.js project.
-   **Zero-Copy**: Parses headers without memory allocation or data duplication for maximum performance.
-   **TLS Support**: Easily enable HTTPS by providing OpenSSL certificate and key files.
-   **Single-Header Library**: Simple to integrate—just include `uvhttp.h` in your project.

## Dependencies

-   [libuv](https://github.com/libuv/libuv)
-   [OpenSSL](https://www.openssl.org/)

## Getting Started

### Building

To build an application using `libuvhttp`, you need to link against `libuv` and `OpenSSL`.

```bash
gcc your_app.c -I. -luv -lssl -lcrypto -o your_app
```

This project includes a `Makefile` that simplifies building the provided examples. Simply run `make` to build them.

### Quick Start

Here is a minimal example of an HTTP server:

```c
#include "uvhttp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Request handler callback
void my_handler(http_request_t* req) {
    // Print the request method and target using the zero-copy slice API
    printf("Request received: ");
    uvhttp_string_slice_t method = http_request_method(req);
    uvhttp_slice_print(&method);
    printf(" ");
    uvhttp_string_slice_t target = http_request_target(req);
    uvhttp_slice_print(&target);
    printf("\n");

    // Create and send a response
    http_response_t* res = http_response_init();
    http_response_status(res, 200);
    http_response_header(res, "Content-Type", "text/plain");
    const char* body = "Hello, World!";
    http_response_body(res, body, strlen(body));

    http_respond(req, res);
    http_response_destroy(res);
}

int main() {
    // Configure the server
    http_server_config_t config = {
        .host = "0.0.0.0",
        .port = 8080,
        .handler = my_handler,
        .tls_enabled = 0, // TLS is disabled
        .max_body_size = 8 * 1024 * 1024 // 8MB limit
    };

    // Create the server
    http_server_t* server = http_server_create(&config);
    if (!server) {
        fprintf(stderr, "Failed to create server.\n");
        return 1;
    }

    // Start listening for connections
    printf("Server listening on http://%s:%d\n", config.host, config.port);
    http_server_listen(server);

    // Clean up
    http_server_destroy(server);
    return 0;
}
```

## Running the Examples

This repository includes examples for both an HTTP and an HTTPS server. You can build and run them using the `Makefile`.

```bash
# Build both example servers (simple_server and tls_server)
make

# Run the simple HTTP server on port 8080
make run-simple

# Run the simple HTTP server on a different port
make run-simple ARGS=8888

# Run the TLS (HTTPS) server on port 8443
# (Requires cert.pem and key.pem files to be present)
make run-tls
```
