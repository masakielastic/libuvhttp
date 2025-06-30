#include "uvhttp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uv.h>

typedef struct {
    uvhttp_request_t* req;
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
        uvhttp_respond_chunk(ctx->req, chunk, len);
        ctx->count++;
    } else {
        uvhttp_respond_chunked_end(ctx->req);
        uv_timer_stop(handle);
        uv_close((uv_handle_t*)handle, on_timer_close);
    }
}

void on_request_complete(uvhttp_request_t* req) {
    uvhttp_response_t* res = uvhttp_response_init();
    uvhttp_response_status(res, 200);
    uvhttp_response_header(res, "Content-Type", "text/plain");
    
    // Start chunked response and send headers
    uvhttp_respond_chunked_start(req, res);
    uvhttp_response_destroy(res);

    // Set up a timer to send a chunk every second
    chunk_context_t* ctx = (chunk_context_t*)malloc(sizeof(chunk_context_t));
    ctx->req = req;
    ctx->count = 0;
    
    uv_timer_init(uvhttp_server_loop(uvhttp_request_get_server(req)), &ctx->timer);
    ctx->timer.data = ctx;
    uv_timer_start(&ctx->timer, on_timer, 0, 1000);
}

int main(int argc, char *argv[]) {
    uv_loop_t* loop = uv_default_loop();
    uvhttp_server_config_t config = {
        .host = "0.0.0.0",
        .port = 8080,
        .on_complete = on_request_complete
    };

    uvhttp_server_t* server = uvhttp_server_create(loop, &config);
    printf("Chunked server listening on http://%s:%d\n", config.host, config.port);
    uvhttp_server_listen(server);
    uv_run(loop, UV_RUN_DEFAULT);
    uvhttp_server_destroy(server);
    return 0;
}