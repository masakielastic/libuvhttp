#include "acutest.h"
#include "../uvhttp.h"
#include <uv.h>

// --- Test Globals & Test Client ---
static http_server_t* test_server = NULL;
static int test_port = 8888;
static int client_on_connect_called = 0;
static int client_on_read_called = 0;
static int client_on_close_called = 0;
static int server_on_close_called = 0;
static char client_read_buffer[1024];

typedef struct {
    uv_connect_t connect_req;
    uv_tcp_t socket;
    uv_write_t write_req;
} test_client_t;

static void client_on_close(uv_handle_t* handle) {
    client_on_close_called = 1;
}

static void server_on_close(uv_handle_t* handle) {
    server_on_close_called = 1;
}

static void client_on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = client_read_buffer;
    buf->len = sizeof(client_read_buffer);
}

// --- Test Handlers ---
void simple_get_handler(http_request_t* req) {
    http_response_t* res = http_response_init();
    http_response_status(res, 200);
    const char* body = "Hello, World!";
    http_response_body(res, body, strlen(body));
    http_respond(req, res);
    http_response_destroy(res);
}

void header_parsing_handler(http_request_t* req) {
    uvhttp_string_slice_t h1 = http_request_header(req, "X-Test-Header-1");
    uvhttp_string_slice_t h2 = http_request_header(req, "X-Test-Header-2");
    uvhttp_string_slice_t h_absent = http_request_header(req, "X-Not-Found");

    TEST_CHECK(uvhttp_slice_cmp(&h1, "Value1") == 0);
    TEST_CHECK(uvhttp_slice_cmp(&h2, "Value2") == 0);
    TEST_CHECK(h_absent.at == NULL && h_absent.length == 0);

    simple_get_handler(req);
}

void post_request_handler(http_request_t* req) {
    uvhttp_string_slice_t method = http_request_method(req);
    uvhttp_string_slice_t body = http_request_body(req);

    TEST_CHECK(uvhttp_slice_cmp(&method, "POST") == 0);
    TEST_CHECK(body.length == 9);
    TEST_CHECK(strncmp(body.at, "key=value", 9) == 0);

    simple_get_handler(req);
}

// --- Test Cases ---

// Client callback for simple GET/POST tests
static void client_on_read_ok(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    if (nread > 0) {
        client_on_read_called = 1;
        TEST_CHECK(strstr(buf->base, "HTTP/1.1 200 OK") != NULL);
    }
    uv_close((uv_handle_t*)stream, client_on_close);
    http_server_close(test_server, server_on_close);
}

// Client callback for body_too_large test (expects connection close)
static void client_on_read_close(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    // nread < 0 indicates an error (like connection closed), which is expected here
    if (nread < 0) {
        client_on_read_called = 1;
    }
    uv_close((uv_handle_t*)stream, client_on_close);
    http_server_close(test_server, server_on_close);
}

static void client_on_write(uv_write_t* req, int status) {
    TEST_CHECK(status == 0);
    uv_buf_t* write_buf = (uv_buf_t*)req->data;
    free(write_buf->base);
    free(write_buf);
    uv_read_start((uv_stream_t*)req->handle, client_on_alloc, (uv_read_cb)req->handle->data);
}

static void client_on_connect(uv_connect_t* req, int status) {
    TEST_CHECK(status == 0);
    if (status != 0) {
        fprintf(stderr, "connect failed: %s\n", uv_strerror(status));
        uv_close((uv_handle_t*)req->handle, client_on_close);
        http_server_close(test_server, server_on_close);
        return;
    }
    client_on_connect_called = 1;
    test_client_t* client = (test_client_t*)req->data;
    uv_write(&client->write_req, (uv_stream_t*)&client->socket, (uv_buf_t*)client->write_req.data, 1, client_on_write);
}

void run_test_with_server(http_request_handler_t handler, size_t max_body_size, const char* http_req_str, uv_read_cb read_cb) {
    // Reset test globals
    client_on_connect_called = 0;
    client_on_read_called = 0;
    client_on_close_called = 0;
    server_on_close_called = 0;
    memset(client_read_buffer, 0, sizeof(client_read_buffer));

    uv_loop_t loop;
    uv_loop_init(&loop);

    http_server_config_t config = { .host = "127.0.0.1", .port = test_port, .handler = handler, .max_body_size = max_body_size };
    test_server = http_server_create(&loop, &config);
    TEST_CHECK(http_server_listen(test_server) == 0);

    // Run client
    test_client_t client;
    client.connect_req.data = &client;
    uv_tcp_init(&loop, &client.socket);
    struct sockaddr_in dest;
    uv_ip4_addr("127.0.0.1", test_port, &dest);
    
    // Allocate a buffer for the write operation that will persist
    uv_buf_t* write_buf = malloc(sizeof(uv_buf_t));
    write_buf->base = strdup(http_req_str);
    write_buf->len = strlen(http_req_str);
    client.write_req.data = write_buf;
    client.socket.data = read_cb; // Pass read_cb to on_write

    uv_tcp_connect(&client.connect_req, &client.socket, (const struct sockaddr*)&dest, client_on_connect);

    uv_run(&loop, UV_RUN_DEFAULT);

    TEST_CHECK(client_on_connect_called == 1);
    TEST_CHECK(client_on_read_called == 1);
    TEST_CHECK(client_on_close_called == 1);
    TEST_CHECK(server_on_close_called == 1);

    http_server_destroy(test_server);
    test_server = NULL;
    uv_loop_close(&loop);
}

void test_header_parsing(void) {
    const char* req = "GET / HTTP/1.1\r\n"
                      "X-Test-Header-1: Value1\r\n"
                      "X-Test-Header-2: Value2\r\n\r\n";
    run_test_with_server(header_parsing_handler, 0, req, client_on_read_ok);
}

void test_post_request(void) {
    const char* req = "POST / HTTP/1.1\r\n"
                      "Content-Length: 9\r\n\r\n"
                      "key=value";
    run_test_with_server(post_request_handler, 0, req, client_on_read_ok);
}

void test_body_too_large(void) {
    const char* req = "POST / HTTP/1.1\r\n"
                      "Content-Length: 10\r\n\r\n"
                      "0123456789";
    run_test_with_server(simple_get_handler, 5, req, client_on_read_close);
}

void test_server_lifecycle(void) {
    uv_loop_t loop;
    uv_loop_init(&loop);
    http_server_config_t config = { .host = "127.0.0.1", .port = test_port, .handler = simple_get_handler };
    test_server = http_server_create(&loop, &config);
    TEST_CHECK(test_server != NULL);
    TEST_CHECK(http_server_listen(test_server) == 0);
    
    server_on_close_called = 0;
    http_server_close(test_server, server_on_close);
    
    uv_run(&loop, UV_RUN_DEFAULT);

    TEST_CHECK(server_on_close_called == 1);

    http_server_destroy(test_server);
    test_server = NULL;
    uv_loop_close(&loop);
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
    { "server/lifecycle", test_server_lifecycle },
    { "server/header_parsing", test_header_parsing },
    { "server/post_request", test_post_request },
    { "server/body_too_large", test_body_too_large },
    { NULL, NULL }
};