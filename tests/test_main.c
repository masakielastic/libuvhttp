#include "acutest.h"
#include "../uvhttp.h"
#include "../llhttp.h"
#include <uv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

// --- Test Context & Client Logic ---

#define TEST_PORT 8888
#define TEST_TLS_PORT 8889
#define TEST_CERT_FILE "tests/test_cert.pem"
#define TEST_KEY_FILE "tests/test_key.pem"
#define TEST_BUFFER_SIZE 4096

typedef struct {
    // Test state
    int connect_success;
    int server_close_called;
    int client_close_called;
    int error_cb_called;
    int tls_handshake_complete;

    // Buffers
    char response_buffer[TEST_BUFFER_SIZE];
    size_t response_len;
    char received_body[TEST_BUFFER_SIZE];
    size_t received_body_len;

    // libuv handles
    uv_loop_t loop;
    uvhttp_server_t* server;
    uv_tcp_t client_socket;
    uv_connect_t connect_req;
    uv_write_t write_req;

    // TLS client state
    int tls_enabled;
    SSL_CTX* ssl_ctx;
    SSL* ssl;
    BIO* read_bio;
    BIO* write_bio;
} test_context_t;

static void on_server_close(uv_handle_t* handle) {
    test_context_t* ctx = (test_context_t*)uvhttp_server_get_user_data((uvhttp_server_t*)handle->data);
    ctx->server_close_called = 1;
}

static void on_client_close(uv_handle_t* handle) {
    test_context_t* ctx = (test_context_t*)handle->data;
    if (ctx->ssl) {
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    if (ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }
    ctx->client_close_called = 1;
}

static void client_do_write(test_context_t* ctx, const char* data, size_t len);
static int client_do_handshake(test_context_t* ctx);

static void on_client_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    test_context_t* ctx = (test_context_t*)stream->data;
    if (nread > 0) {
        if (ctx->tls_enabled) {
            BIO_write(ctx->read_bio, buf->base, nread);
            if (!ctx->tls_handshake_complete) {
                if (client_do_handshake(ctx) < 0) {
                    uv_close((uv_handle_t*)stream, on_client_close);
                    uvhttp_server_close(ctx->server, on_server_close);
                    return;
                }
            }
            
            int bytes_read = SSL_read(ctx->ssl, ctx->response_buffer + ctx->response_len, TEST_BUFFER_SIZE - ctx->response_len);
            if (bytes_read > 0) {
                ctx->response_len += bytes_read;
            }
        } else {
            memcpy(ctx->response_buffer + ctx->response_len, buf->base, nread);
            ctx->response_len += nread;
        }
    } else {
        uv_close((uv_handle_t*)stream, on_client_close);
        uvhttp_server_close(ctx->server, on_server_close);
    }
}

static void on_client_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = ((test_context_t*)handle->data)->response_buffer;
    buf->len = TEST_BUFFER_SIZE;
}

static void on_client_write(uv_write_t* req, int status) {
    free(req->data);
    if (status != 0) {
        fprintf(stderr, "write failed: %s\n", uv_strerror(status));
        return;
    }
    uv_read_start((uv_stream_t*)req->handle, on_client_alloc, on_client_read);
}

static void client_do_write(test_context_t* ctx, const char* data, size_t len) {
    if (ctx->tls_enabled) {
        SSL_write(ctx->ssl, data, len);
        int pending = BIO_pending(ctx->write_bio);
        if (pending > 0) {
            char* buf_data = (char*)malloc(pending);
            int bytes_read = BIO_read(ctx->write_bio, buf_data, pending);
            if (bytes_read > 0) {
                uv_buf_t* write_buf = malloc(sizeof(uv_buf_t));
                write_buf->base = buf_data;
                write_buf->len = bytes_read;
                ctx->write_req.data = write_buf;
                uv_write(&ctx->write_req, (uv_stream_t*)&ctx->client_socket, write_buf, 1, on_client_write);
            } else {
                free(buf_data);
            }
        }
    } else {
        uv_buf_t* write_buf = malloc(sizeof(uv_buf_t));
        write_buf->base = (char*)data;
        write_buf->len = len;
        ctx->write_req.data = write_buf;
        uv_write(&ctx->write_req, (uv_stream_t*)&ctx->client_socket, write_buf, 1, on_client_write);
    }
}

static int client_do_handshake(test_context_t* ctx) {
    int r = SSL_do_handshake(ctx->ssl);
    if (r == 1) {
        ctx->tls_handshake_complete = 1;
        char* req_str = (char*)((uv_buf_t*)ctx->write_req.data)->base;
        client_do_write(ctx, req_str, strlen(req_str));
        return 0;
    }
    int err = SSL_get_error(ctx->ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        int pending = BIO_pending(ctx->write_bio);
        if (pending > 0) {
            char* buf_data = (char*)malloc(pending);
            int bytes_read = BIO_read(ctx->write_bio, buf_data, pending);
            if (bytes_read > 0) {
                uv_buf_t* write_buf = malloc(sizeof(uv_buf_t));
                write_buf->base = buf_data;
                write_buf->len = bytes_read;
                ctx->write_req.data = write_buf;
                uv_write(&ctx->write_req, (uv_stream_t*)&ctx->client_socket, write_buf, 1, on_client_write);
            } else {
                free(buf_data);
            }
        }
        return 0;
    }
    return -1;
}

static void on_client_connect(uv_connect_t* req, int status) {
    test_context_t* ctx = (test_context_t*)req->data;
    ctx->connect_success = (status == 0);
    if (status != 0) {
        fprintf(stderr, "connect failed: %s\n", uv_strerror(status));
        uvhttp_server_close(ctx->server, on_server_close);
        return;
    }
    if (ctx->tls_enabled) {
        client_do_handshake(ctx);
    } else {
        char* req_str = (char*)((uv_buf_t*)ctx->write_req.data)->base;
        client_do_write(ctx, req_str, strlen(req_str));
    }
}

static test_context_t* test_context_create(int tls_enabled) {
    test_context_t* ctx = (test_context_t*)calloc(1, sizeof(test_context_t));
    if (!ctx) return NULL;

    ctx->tls_enabled = tls_enabled;
    uv_loop_init(&ctx->loop);

    if (tls_enabled) {
        ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
        ctx->ssl = SSL_new(ctx->ssl_ctx);
        ctx->read_bio = BIO_new(BIO_s_mem());
        ctx->write_bio = BIO_new(BIO_s_mem());
        SSL_set_bio(ctx->ssl, ctx->read_bio, ctx->write_bio);
        SSL_set_connect_state(ctx->ssl);
    }
    return ctx;
}

static void test_context_destroy(test_context_t* ctx) {
    uvhttp_server_destroy(ctx->server);
    uv_loop_close(&ctx->loop);
    free(ctx);
}

static void run_test(uvhttp_server_config_t* config, const char* req_str, void (*test_assertions)(test_context_t*)) {
    test_context_t* ctx = test_context_create(config->tls_enabled);
    TEST_CHECK(ctx != NULL);

    ctx->server = uvhttp_server_create(&ctx->loop, config);
    TEST_CHECK(ctx->server != NULL);
    uvhttp_server_set_user_data(ctx->server, ctx);

    TEST_CHECK(uvhttp_server_listen(ctx->server) == 0);

    uv_tcp_init(&ctx->loop, &ctx->client_socket);
    ctx->client_socket.data = ctx;
    ctx->connect_req.data = ctx;
    ctx->write_req.handle = (uv_stream_t*)&ctx->client_socket;
    
    uv_buf_t* write_buf = malloc(sizeof(uv_buf_t));
    write_buf->base = strdup(req_str);
    write_buf->len = strlen(req_str);
    ctx->write_req.data = write_buf;

    struct sockaddr_in dest;
    uv_ip4_addr("127.0.0.1", config->port, &dest);
    uv_tcp_connect(&ctx->connect_req, &ctx->client_socket, (const struct sockaddr*)&dest, on_client_connect);

    uv_run(&ctx->loop, UV_RUN_DEFAULT);

    if (test_assertions) {
        test_assertions(ctx);
    }

    test_context_destroy(ctx);
}

// --- Test Handlers ---
static void on_body_chunk_test(uvhttp_request_t* req, const uvhttp_str_t* chunk) {
    test_context_t* ctx = (test_context_t*)uvhttp_request_get_user_data(req);
    if (chunk->length > 0) {
        memcpy(ctx->received_body + ctx->received_body_len, chunk->at, chunk->length);
        ctx->received_body_len += chunk->length;
    }
}

static void on_complete_ok(uvhttp_request_t* req) {
    uvhttp_respond_simple(req, 200, "text/plain", "OK", 2);
}

static void on_headers_check(uvhttp_request_t* req) {
    uvhttp_request_set_user_data(req, uvhttp_server_get_user_data(uvhttp_request_get_server(req)));
}

static void on_complete_header_check(uvhttp_request_t* req) {
    uvhttp_str_t h1 = uvhttp_request_header(req, "X-Test-Header-1");
    uvhttp_str_t h2 = uvhttp_request_header(req, "X-Test-Header-2");
    TEST_CHECK(uvhttp_str_cmp(&h1, "Value1") == 0);
    TEST_CHECK(uvhttp_str_cmp(&h2, "Value2") == 0);
    on_complete_ok(req);
}

static void on_complete_post_check(uvhttp_request_t* req) {
    test_context_t* ctx = (test_context_t*)uvhttp_request_get_user_data(req);
    TEST_CHECK(ctx->received_body_len == 9);
    TEST_CHECK(strncmp(ctx->received_body, "key=value", 9) == 0);
    on_complete_ok(req);
}

static void on_complete_chunked_check(uvhttp_request_t* req) {
    uvhttp_response_t* res = uvhttp_response_init();
    uvhttp_response_status(res, 200);
    uvhttp_response_header(res, "Content-Type", "text/plain");
    uvhttp_respond_chunked_start(req, res);
    uvhttp_response_destroy(res);
    uvhttp_respond_chunk(req, "chunk1", 6);
    uvhttp_respond_chunk(req, "chunk2", 6);
    uvhttp_respond_chunked_end(req);
}

static void on_error_check(uvhttp_request_t* req, int err, const char* msg) {
    test_context_t* ctx = (test_context_t*)uvhttp_request_get_user_data(req);
    ctx->error_cb_called = 1;
    TEST_CHECK(err == HPE_INVALID_METHOD);
}

// --- Test Cases ---
void test_header_parsing(void) {
    uvhttp_server_config_t config = { .host = "127.0.0.1", .port = TEST_PORT, .on_headers = on_headers_check, .on_complete = on_complete_header_check };
    const char* req = "GET / HTTP/1.1\r\n"
                      "X-Test-Header-1: Value1\r\n"
                      "X-Test-Header-2: Value2\r\n\r\n";
    run_test(&config, req, NULL);
}

void test_post_request(void) {
    uvhttp_server_config_t config = { .host = "127.0.0.1", .port = TEST_PORT, .on_headers = on_headers_check, .on_body_chunk = on_body_chunk_test, .on_complete = on_complete_post_check };
    const char* req = "POST / HTTP/1.1\r\n"
                      "Content-Length: 9\r\n\r\n"
                      "key=value";
    run_test(&config, req, NULL);
}

void test_body_too_large(void) {
    uvhttp_server_config_t config = { .host = "127.0.0.1", .port = TEST_PORT, .on_complete = on_complete_ok, .max_body_size = 5 };
    const char* req = "POST / HTTP/1.1\r\n"
                      "Content-Length: 10\r\n\r\n"
                      "0123456789";
    run_test(&config, req, NULL);
}

void test_chunked_response(void) {
    uvhttp_server_config_t config = { .host = "127.0.0.1", .port = TEST_PORT, .on_complete = on_complete_chunked_check };
    const char* req = "GET / HTTP/1.1\r\n\r\n";
    run_test(&config, req, NULL);
}

void test_parse_error(void) {
    uvhttp_server_config_t config = { .host = "127.0.0.1", .port = TEST_PORT, .on_error = on_error_check };
    const char* req = "INVALID METHOD / HTTP/1.1\r\n\r\n";
    run_test(&config, req, NULL);
}

void test_header_parsing_tls(void) {
    uvhttp_server_config_t config = { .host = "127.0.0.1", .port = TEST_TLS_PORT, .on_headers = on_headers_check, .on_complete = on_complete_header_check, .tls_enabled = 1, .cert_file = TEST_CERT_FILE, .key_file = TEST_KEY_FILE };
    const char* req = "GET / HTTP/1.1\r\n"
                      "X-Test-Header-1: Value1\r\n"
                      "X-Test-Header-2: Value2\r\n\r\n";
    run_test(&config, req, NULL);
}

void test_chunked_response_tls(void) {
    uvhttp_server_config_t config = { .host = "127.0.0.1", .port = TEST_TLS_PORT, .on_complete = on_complete_chunked_check, .tls_enabled = 1, .cert_file = TEST_CERT_FILE, .key_file = TEST_KEY_FILE };
    const char* req = "GET / HTTP/1.1\r\n\r\n";
    run_test(&config, req, NULL);
}

void test_slice_cmp(void) {
    uvhttp_str_t slice = {"hello", 5};
    TEST_CHECK(uvhttp_str_cmp(&slice, "hello") == 0);
    TEST_CHECK(uvhttp_str_cmp(&slice, "world") != 0);
    TEST_CHECK(uvhttp_str_cmp(&slice, "HELLO") == 0);
    TEST_CHECK(uvhttp_str_cmp(&slice, "hell") != 0);
    TEST_CHECK(uvhttp_str_cmp(&slice, "helloo") != 0);
}

TEST_LIST = {
    { "slice/cmp", test_slice_cmp },
    { "server/header_parsing", test_header_parsing },
    { "server/post_request", test_post_request },
    { "server/body_too_large", test_body_too_large },
    { "server/chunked_response", test_chunked_response },
    { "server/parse_error", test_parse_error },
    { "server/tls_header_parsing", test_header_parsing_tls },
    { "server/tls_chunked_response", test_chunked_response_tls },
    { NULL, NULL }
};