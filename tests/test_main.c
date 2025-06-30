#include "acutest.h"
#include "../uvhttp.h"
#include <uv.h>

// --- Test Context & Client Logic ---

#define TEST_PORT 8888
#define TEST_BUFFER_SIZE 1024

typedef struct {
    // Test state
    int connect_success;
    int server_close_called;
    int client_close_called;
    
    // Buffers
    char response_buffer[TEST_BUFFER_SIZE];
    size_t response_len;
    char received_body[TEST_BUFFER_SIZE];
    size_t received_body_len;

    // libuv handles
    uv_loop_t loop;
    http_server_t* server;
    uv_tcp_t client_socket;
    uv_connect_t connect_req;
    uv_write_t write_req;
} test_context_t;

static void on_server_close(uv_handle_t* handle) {
    test_context_t* ctx = (test_context_t*)http_server_get_user_data((http_server_t*)handle->data);
    ctx->server_close_called = 1;
}

static void on_client_close(uv_handle_t* handle) {
    test_context_t* ctx = (test_context_t*)handle->data;
    ctx->client_close_called = 1;
}

static void on_client_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    test_context_t* ctx = (test_context_t*)stream->data;
    if (nread > 0) {
        memcpy(ctx->response_buffer + ctx->response_len, buf->base, nread);
        ctx->response_len += nread;
    } else {
        uv_close((uv_handle_t*)stream, on_client_close);
        http_server_close(ctx->server, on_server_close);
    }
}

static void on_client_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = ((test_context_t*)handle->data)->response_buffer;
    buf->len = TEST_BUFFER_SIZE;
}

static void on_client_write(uv_write_t* req, int status) {
    free(req->data); // Free the request string buffer
    if (status != 0) {
        fprintf(stderr, "write failed: %s\n", uv_strerror(status));
        return;
    }
    uv_read_start((uv_stream_t*)req->handle, on_client_alloc, on_client_read);
}

static void on_client_connect(uv_connect_t* req, int status) {
    test_context_t* ctx = (test_context_t*)req->data;
    ctx->connect_success = (status == 0);
    if (status != 0) {
        fprintf(stderr, "connect failed: %s\n", uv_strerror(status));
        http_server_close(ctx->server, on_server_close);
        return;
    }
    uv_write(&ctx->write_req, (uv_stream_t*)&ctx->client_socket, (const uv_buf_t*)ctx->write_req.data, 1, on_client_write);
}

static void run_test(http_server_config_t* config, const char* req_str, void (*test_assertions)(test_context_t*)) {
    test_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    uv_loop_init(&ctx.loop);

    ctx.server = http_server_create(&ctx.loop, config);
    TEST_CHECK(ctx.server != NULL);
    http_server_set_user_data(ctx.server, &ctx);

    TEST_CHECK(http_server_listen(ctx.server) == 0);

    uv_tcp_init(&ctx.loop, &ctx.client_socket);
    ctx.client_socket.data = &ctx;
    ctx.connect_req.data = &ctx;
    ctx.write_req.handle = (uv_stream_t*)&ctx.client_socket;
    
    uv_buf_t* write_buf = malloc(sizeof(uv_buf_t));
    write_buf->base = strdup(req_str);
    write_buf->len = strlen(req_str);
    ctx.write_req.data = write_buf;

    struct sockaddr_in dest;
    uv_ip4_addr("127.0.0.1", TEST_PORT, &dest);
    uv_tcp_connect(&ctx.connect_req, &ctx.client_socket, (const struct sockaddr*)&dest, on_client_connect);

    uv_run(&ctx.loop, UV_RUN_DEFAULT);

    if (test_assertions) {
        test_assertions(&ctx);
    }

    http_server_destroy(ctx.server);
    uv_loop_close(&ctx.loop);
}

// --- Test Handlers ---
static void on_body_chunk_test(http_request_t* req, const uvhttp_string_slice_t* chunk) {
    test_context_t* ctx = (test_context_t*)http_request_get_user_data(req);
    if (chunk->length > 0) {
        memcpy(ctx->received_body + ctx->received_body_len, chunk->at, chunk->length);
        ctx->received_body_len += chunk->length;
    }
}

static void on_complete_ok(http_request_t* req) {
    http_respond_simple(req, 200, "text/plain", "OK", 2);
}

static void on_headers_check(http_request_t* req) {
    // The user_data is now propagated automatically.
}

static void on_complete_header_check(http_request_t* req) {
    uvhttp_string_slice_t h1 = http_request_header(req, "X-Test-Header-1");
    uvhttp_string_slice_t h2 = http_request_header(req, "X-Test-Header-2");
    TEST_CHECK(uvhttp_slice_cmp(&h1, "Value1") == 0);
    TEST_CHECK(uvhttp_slice_cmp(&h2, "Value2") == 0);
    on_complete_ok(req);
}

static void on_complete_post_check(http_request_t* req) {
    test_context_t* ctx = (test_context_t*)http_request_get_user_data(req);
    TEST_CHECK(ctx->received_body_len == 9);
    TEST_CHECK(strncmp(ctx->received_body, "key=value", 9) == 0);
    on_complete_ok(req);
}

// --- Test Cases ---
void test_header_parsing(void) {
    http_server_config_t config = { .host = "127.0.0.1", .port = TEST_PORT, .on_headers = on_headers_check, .on_complete = on_complete_header_check };
    const char* req = "GET / HTTP/1.1\r\n"
                      "X-Test-Header-1: Value1\r\n"
                      "X-Test-Header-2: Value2\r\n\r\n";
    run_test(&config, req, NULL);
}

void test_post_request(void) {
    http_server_config_t config = { .host = "127.0.0.1", .port = TEST_PORT, .on_headers = on_headers_check, .on_body_chunk = on_body_chunk_test, .on_complete = on_complete_post_check };
    const char* req = "POST / HTTP/1.1\r\n"
                      "Content-Length: 9\r\n\r\n"
                      "key=value";
    run_test(&config, req, NULL);
}

void test_body_too_large(void) {
    http_server_config_t config = { .host = "127.0.0.1", .port = TEST_PORT, .on_complete = on_complete_ok, .max_body_size = 5 };
    const char* req = "POST / HTTP/1.1\r\n"
                      "Content-Length: 10\r\n\r\n"
                      "0123456789";
    run_test(&config, req, NULL);
}

void test_slice_cmp(void) {
    uvhttp_string_slice_t slice = {"hello", 5};
    TEST_CHECK(uvhttp_slice_cmp(&slice, "hello") == 0);
    TEST_CHECK(uvhttp_slice_cmp(&slice, "world") != 0);
    TEST_CHECK(uvhttp_slice_cmp(&slice, "HELLO") == 0);
    TEST_CHECK(uvhttp_slice_cmp(&slice, "hell") != 0);
    TEST_CHECK(uvhttp_slice_cmp(&slice, "helloo") != 0);
}

TEST_LIST = {
    { "slice/cmp", test_slice_cmp },
    { "server/header_parsing", test_header_parsing },
    { "server/post_request", test_post_request },
    { "server/body_too_large", test_body_too_large },
    { NULL, NULL }
};