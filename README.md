# libuvhttp

A simple and high-performance HTTP/1.1 server library built on `libuv` and `llhttp`.

`libuvhttp` is a single-header library designed for ease of use and high performance. It leverages the asynchronous I/O capabilities of `libuv` and the efficiency of the `llhttp` parser. It features a zero-copy parsing approach for headers to minimize overhead and supports TLS for secure connections via OpenSSL.

### Design Philosophy

This library is primarily designed for use within single-threaded environments, such as a PHP extension. The core architecture is built around a single `libuv` event loop and is not thread-safe by default. All interactions with the server and its requests should be performed on the same thread where the `uv_run` loop is executed.

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
#include <uv.h>

// Request handler callback
void on_request_complete(uvhttp_request_t* req) {
    // Print the request method and target using the zero-copy string API
    printf("Request received: ");
    uvhttp_str_t method = uvhttp_request_method(req);
    uvhttp_str_print(&method);
    printf(" ");
    uvhttp_str_t target = uvhttp_request_target(req);
    uvhttp_str_print(&target);
    printf("\n");

    // Create and send a simple response
    const char* body = "Hello, World!";
    uvhttp_respond_simple(req, 200, "text/plain", body, strlen(body));
}

int main() {
    uv_loop_t* loop = uv_default_loop();

    // Configure the server
    uvhttp_server_config_t config = {
        .host = "127.0.0.1",
        .port = 8080,
        .on_complete = on_request_complete,
    };

    // Create the server
    uvhttp_server_t* server = uvhttp_server_create(loop, &config);
    if (!server) {
        fprintf(stderr, "Failed to create server.\n");
        return 1;
    }

    // Start listening for connections
    if (uvhttp_server_listen(server) != 0) {
        fprintf(stderr, "Failed to listen on http://%s:%d\n", config.host, config.port);
        uvhttp_server_destroy(server);
        return 1;
    }
    
    printf("Server listening on http://%s:%d\n", config.host, config.port);

    // Run the event loop
    uv_run(loop, UV_RUN_DEFAULT);

    // Clean up (this part will not be reached in this simple example
    // unless the loop is stopped elsewhere)
    uvhttp_server_destroy(server);
    uv_loop_close(loop);
    
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

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
