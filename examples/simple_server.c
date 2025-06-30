#include "uvhttp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uv.h>

// Context to hold server and signal handles for graceful shutdown
typedef struct {
    http_server_t* server;
    uv_signal_t signal;
    int server_closed;
    int signal_closed;
} app_context_t;

static void on_server_close(uv_handle_t* handle) {
    http_server_t* server = (http_server_t*)handle->data;
    app_context_t* ctx = (app_context_t*)http_server_get_user_data(server);
    ctx->server_closed = 1;
    // Stop the loop only when both server and signal handles are closed
    if (ctx->signal_closed) {
        uv_stop(http_server_loop(ctx->server));
    }
}

static void on_signal_close(uv_handle_t* handle) {
    app_context_t* ctx = (app_context_t*)handle->data;
    ctx->signal_closed = 1;
    if (ctx->server_closed) {
        uv_stop(http_server_loop(ctx->server));
    }
}

// Signal handler for Ctrl+C (SIGINT)
void on_signal(uv_signal_t* handle, int signum) {
    printf("\nShutting down...\n");
    app_context_t* ctx = (app_context_t*)handle->data;
    
    // Stop the server from accepting new connections
    http_server_close(ctx->server, on_server_close);
    
    // Stop the signal handler
    uv_signal_stop(handle);
    uv_close((uv_handle_t*)handle, on_signal_close);
}

void on_request_complete(http_request_t* req) {
    printf("Request received: ");
    uvhttp_str_t method = http_request_method(req);
    uvhttp_str_print(&method);
    printf(" ");
    uvhttp_str_t target = http_request_target(req);
    uvhttp_str_print(&target);
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
    app_context_t app_ctx = {0};

    http_server_config_t config = {
        .host = "0.0.0.0",
        .port = port,
        .on_complete = on_request_complete,
        .tls_enabled = 0,
        .max_body_size = 8 * 1024 * 1024
    };

    app_ctx.server = http_server_create(loop, &config);
    if (!app_ctx.server) {
        fprintf(stderr, "Failed to create server.\n");
        return 1;
    }
    
    // Set context for close callbacks
    http_server_set_user_data(app_ctx.server, &app_ctx);

    if (http_server_listen(app_ctx.server) != 0) {
        fprintf(stderr, "Failed to listen on http://%s:%d\n", config.host, config.port);
        return 1;
    }

    // Initialize and start signal handler
    uv_signal_init(loop, &app_ctx.signal);
    app_ctx.signal.data = &app_ctx;
    uv_signal_start(&app_ctx.signal, on_signal, SIGINT);

    printf("Server listening on http://%s:%d\n", config.host, config.port);
    printf("Press Ctrl+C to shut down.\n");
    
    uv_run(loop, UV_RUN_DEFAULT);

    http_server_destroy(app_ctx.server);
    
    // Final check to ensure loop is closed properly
    uv_loop_close(loop);
    
    printf("Server shut down gracefully.\n");
    return 0;
}
