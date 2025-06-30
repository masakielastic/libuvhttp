#include "uvhttp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uv.h>

typedef struct {
    http_request_t* req;
    uv_timer_t timer;
    int count;
} chunk_context_t;

static void on_timer_close(uv_handle_t* handle) {
    free(handle->data);
}

static void on_timer(uv_timer_t* handle) {
    chunk_context_t* ctx = (chunk_context_t*)handle->data;
    char chunk[64];
    
    if (ctx->count < 5) {
        int len = sprintf(chunk, "Chunk %d: The current time is %ld\n", ctx->count + 1, time(NULL));
        http_respond_chunk(ctx->req, chunk, len);
        ctx->count++;
    } else {
        http_respond_chunked_end(ctx->req);
        uv_timer_stop(handle);
        uv_close((uv_handle_t*)handle, on_timer_close);
    }
}

void on_request_complete(http_request_t* req) {
    http_response_t* res = http_response_init();
    http_response_status(res, 200);
    http_response_header(res, "Content-Type", "text/plain");
    
    // Start chunked response and send headers
    http_respond_chunked_start(req, res);
    http_response_destroy(res);

    // Set up a timer to send a chunk every second
    chunk_context_t* ctx = (chunk_context_t*)malloc(sizeof(chunk_context_t));
    ctx->req = req;
    ctx->count = 0;
    
    uv_timer_init(http_server_loop(http_request_get_server(req)), &ctx->timer);
    ctx->timer.data = ctx;
    uv_timer_start(&ctx->timer, on_timer, 0, 1000);
}

int main(int argc, char *argv[]) {
    uv_loop_t* loop = uv_default_loop();
    http_server_config_t config = {
        .host = "0.0.0.0",
        .port = 8080,
        .on_complete = on_request_complete
    };

    http_server_t* server = http_server_create(loop, &config);
    printf("Chunked server listening on http://%s:%d\n", config.host, config.port);
    http_server_listen(server);
    uv_run(loop, UV_RUN_DEFAULT);
    http_server_destroy(server);
    return 0;
}
