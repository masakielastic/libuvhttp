#include "acutest.h"
#include "../uvhttp.h"
#include <uv.h>

// --- Test Globals & Test Client ---
static http_server_t* test_server = NULL;
static int test_port = 8888;
static int client_on_connect_called = 0;
static int client_on_read_called = 0;
static char client_read_buffer[1024];

typedef struct {
    uv_connect_t connect_req;
    uv_tcp_t socket;
    uv_write_t write_req;
} test_client_t;

static void client_on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = client_read_buffer;
    buf->len = sizeof(client_read_buffer);
}

static void client_on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    if (nread > 0) {
        client_on_read_called = 1;
        // Simple check for response
        TEST_CHECK(strstr(buf->base, "HTTP/1.1 200 OK") != NULL);
        TEST_CHECK(strstr(buf->base, "Hello, World!") != NULL);
    }
    uv_close((uv_handle_t*)stream, NULL);
    // Stop the event loop now that the test is done
    uv_stop(http_server_loop(test_server));
}

static void client_on_write(uv_write_t* req, int status) {
    TEST_CHECK(status == 0);
    uv_read_start((uv_stream_t*)req->handle, client_on_alloc, client_on_read);
}

static void client_on_connect(uv_connect_t* req, int status) {
    TEST_CHECK(status == 0);
    client_on_connect_called = 1;
    
    const char* http_req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    uv_buf_t buf = uv_buf_init((char*)http_req, strlen(http_req));
    
    test_client_t* client = (test_client_t*)req->data;
    uv_write(&client->write_req, (uv_stream_t*)&client->socket, &buf, 1, client_on_write);
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

// --- Test Cases ---

void test_simple_get(void) {
    // Reset test globals
    client_on_connect_called = 0;
    client_on_read_called = 0;
    memset(client_read_buffer, 0, sizeof(client_read_buffer));

    uv_loop_t* loop = uv_default_loop();
    http_server_config_t config = {
        .host = "127.0.0.1",
        .port = test_port,
        .handler = simple_get_handler
    };
    test_server = http_server_create(&config);
    TEST_CHECK(http_server_listen(test_server) == 0);

    // Run client
    test_client_t client;
    client.connect_req.data = &client;
    uv_tcp_init(loop, &client.socket);
    struct sockaddr_in dest;
    uv_ip4_addr("127.0.0.1", test_port, &dest);
    uv_tcp_connect(&client.connect_req, &client.socket, (const struct sockaddr*)&dest, client_on_connect);

    // Run loop until client is done and stops it
    uv_run(loop, UV_RUN_DEFAULT);

    TEST_CHECK(client_on_connect_called == 1);
    TEST_CHECK(client_on_read_called == 1);

    http_server_destroy(test_server);
    test_server = NULL;
}

void test_server_lifecycle(void) {
    http_server_config_t config = {
        .host = "127.0.0.1",
        .port = test_port,
        .handler = simple_get_handler
    };
    test_server = http_server_create(&config);
    TEST_CHECK(test_server != NULL);

    int listen_r = http_server_listen(test_server);
    TEST_CHECK(listen_r == 0);

    // Stop the server immediately
    uv_stop(http_server_loop(test_server));
    
    // Run the loop to allow the stop to be processed
    uv_run(http_server_loop(test_server), UV_RUN_DEFAULT);

    http_server_destroy(test_server);
    test_server = NULL;
}


void test_slice_cmp(void) {
    uvhttp_string_slice_t slice = {"hello", 5};
    TEST_CHECK(uvhttp_slice_cmp(&slice, "hello") == 0);
    TEST_CHECK(uvhttp_slice_cmp(&slice, "world") != 0);
    TEST_CHECK(uvhttp_slice_cmp(&slice, "HELLO") == 0); // Case-insensitive
    TEST_CHECK(uvhttp_slice_cmp(&slice, "hell") != 0);
    TEST_CHECK(uvhttp_slice_cmp(&slice, "helloo") != 0);
}

TEST_LIST = {
    { "slice/cmp", test_slice_cmp },
    { "server/lifecycle", test_server_lifecycle },
    { "server/simple_get", test_simple_get },
    { NULL, NULL }
};
