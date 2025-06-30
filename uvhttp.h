#ifndef UVHTTP_H
#define UVHTTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <uv.h>

// Forward declarations
struct uvhttp_server_s;
struct uvhttp_request_s;
struct uvhttp_response_s;
struct uvhttp_server_config_s;

// A string slice structure for zero-copy parsing
typedef struct {
    const char* at;
    size_t length;
} uvhttp_str_t;

// Callback types
typedef void (*uvhttp_request_handler_t)(struct uvhttp_request_s* request);
typedef void (*uvhttp_body_chunk_handler_t)(struct uvhttp_request_s* request, const uvhttp_str_t* chunk);
typedef void (*uvhttp_error_handler_t)(struct uvhttp_request_s* request, int error_code, const char* message);

// HTTP server structure (opaque)
typedef struct uvhttp_server_s uvhttp_server_t;

// HTTP request structure (opaque)
typedef struct uvhttp_request_s uvhttp_request_t;

// HTTP response structure (opaque)
typedef struct uvhttp_response_s uvhttp_response_t;

// HTTP server configuration structure
typedef struct uvhttp_server_config_s {
    const char* host;
    int port;
    uvhttp_request_handler_t on_headers; // Called after headers are parsed
    uvhttp_body_chunk_handler_t on_body_chunk; // Called for each body data chunk
    uvhttp_request_handler_t on_complete; // Called after the message is fully received
    uvhttp_error_handler_t on_error; // Called on parse error
    int tls_enabled;
    const char* cert_file;
    const char* key_file;
    size_t max_body_size; // Max allowed body size, 0 for unlimited
} uvhttp_server_config_t;

// Server management functions
uvhttp_server_t* uvhttp_server_create(uv_loop_t* loop, const uvhttp_server_config_t* config);
int uvhttp_server_listen(uvhttp_server_t* server);
void uvhttp_server_close(uvhttp_server_t* server, uv_close_cb on_close);
void uvhttp_server_destroy(uvhttp_server_t* server);
uv_loop_t* uvhttp_server_loop(uvhttp_server_t* server);
void uvhttp_server_set_user_data(uvhttp_server_t* server, void* user_data);
void* uvhttp_server_get_user_data(uvhttp_server_t* server);


// Request functions
uvhttp_server_t* uvhttp_request_get_server(uvhttp_request_t* request);
uvhttp_str_t uvhttp_request_method(uvhttp_request_t* request);
uvhttp_str_t uvhttp_request_target(uvhttp_request_t* request);
uvhttp_str_t uvhttp_request_header(uvhttp_request_t* request, const char* name);
void* uvhttp_request_get_user_data(uvhttp_request_t* request);
void uvhttp_request_set_user_data(uvhttp_request_t* request, void* user_data);

// String slice helpers
int uvhttp_str_cmp(const uvhttp_str_t* slice, const char* str);
void uvhttp_str_print(const uvhttp_str_t* slice);


// Response functions
uvhttp_response_t* uvhttp_response_init(void);
void uvhttp_response_status(uvhttp_response_t* response, int status);
void uvhttp_response_header(uvhttp_response_t* response, const char* name, const char* value);
void uvhttp_response_body(uvhttp_response_t* response, const char* body, size_t length);
int uvhttp_respond(uvhttp_request_t* request, uvhttp_response_t* response);
void uvhttp_response_destroy(uvhttp_response_t* response);
int uvhttp_respond_simple(uvhttp_request_t* req, int status, const char* content_type, const char* body, size_t body_length);
int uvhttp_respond_chunked_start(uvhttp_request_t* req, uvhttp_response_t* res);
int uvhttp_respond_chunk(uvhttp_request_t* req, const char* data, size_t length);
int uvhttp_respond_chunked_end(uvhttp_request_t* req);


#ifdef __cplusplus
}
#endif

#endif // UVHTTP_H


#ifdef UVHTTP_IMPL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "llhttp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define MAX_HEADERS 64
#define READ_BUFFER_SIZE (64 * 1024)

// Internal structures
struct uvhttp_server_s {
    uv_tcp_t tcp;
    uv_loop_t* loop;
    SSL_CTX* ssl_ctx;
    uvhttp_server_config_t config;
    void* user_data;
};

typedef struct {
    uv_tcp_t tcp;
    SSL* ssl;
    BIO* read_bio;
    BIO* write_bio;
    llhttp_t parser;
    llhttp_settings_t parser_settings;
    int handshake_complete;
    uvhttp_server_t* server;
    
    char read_buffer[READ_BUFFER_SIZE]; // Per-connection read buffer

    uvhttp_str_t method;
    uvhttp_str_t url;
    uvhttp_str_t headers[MAX_HEADERS][2];
    int header_count;
    uvhttp_str_t current_header_field;

    void* user_data;
} uvhttp_connection_t;

struct uvhttp_request_s {
    uvhttp_connection_t* connection;
};

struct uvhttp_response_s {
    int status_code;
    char* headers[MAX_HEADERS][2];
    int header_count;
    char* body;
    size_t body_length;
};

typedef struct {
    uv_write_t req;
    char* buffer; // Used for the combined TLS buffer
} uvhttp_write_req_t;


// Forward declarations for internal functions
static void on_new_connection(uv_stream_t* server_stream, int status);
static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void on_final_write_cb(uv_write_t* req, int status);
static void on_transient_write_cb(uv_write_t* req, int status);
static void on_close(uv_handle_t* handle);

static int on_message_begin(llhttp_t* parser);
static int on_url(llhttp_t* parser, const char* at, size_t length);
static int on_header_field(llhttp_t* parser, const char* at, size_t length);
static int on_header_value(llhttp_t* parser, const char* at, size_t length);
static int on_headers_complete(llhttp_t* parser);
static int on_body(llhttp_t* parser, const char* at, size_t length);
static int on_message_complete(llhttp_t* parser);

static void flush_write_bio(uvhttp_connection_t* conn, uv_write_cb cb);
static int handle_tls_handshake(uvhttp_connection_t* conn);

// --- Function Implementations ---

uvhttp_server_t* uvhttp_request_get_server(uvhttp_request_t* request) { return request->connection->server; }
uvhttp_str_t uvhttp_request_method(uvhttp_request_t* request) { return request->connection->method; }
uvhttp_str_t uvhttp_request_target(uvhttp_request_t* request) { return request->connection->url; }
void* uvhttp_request_get_user_data(uvhttp_request_t* request) { return request->connection->user_data; }
void uvhttp_request_set_user_data(uvhttp_request_t* request, void* user_data) { request->connection->user_data = user_data; }

uvhttp_str_t uvhttp_request_header(uvhttp_request_t* request, const char* name) {
    for (int i = 0; i < request->connection->header_count; i++) {
        if (uvhttp_str_cmp(&request->connection->headers[i][0], name) == 0) {
            return request->connection->headers[i][1];
        }
    }
    uvhttp_str_t empty = { NULL, 0 };
    return empty;
}

int uvhttp_str_cmp(const uvhttp_str_t* slice, const char* str) {
    if (slice == NULL || slice->at == NULL || str == NULL) {
        return -1;
    }
    size_t str_len = strlen(str);
    if (slice->length != str_len) {
        return (int)slice->length - (int)str_len;
    }
    return strncasecmp(slice->at, str, str_len);
}

void uvhttp_str_print(const uvhttp_str_t* slice) {
    if (slice && slice->at) {
        fwrite(slice->at, 1, slice->length, stdout);
    }
}

uvhttp_response_t* uvhttp_response_init(void) {
    uvhttp_response_t* response = (uvhttp_response_t*)calloc(1, sizeof(uvhttp_response_t));
    response->status_code = 200;
    return response;
}

void uvhttp_response_status(uvhttp_response_t* response, int status) { response->status_code = status; }

void uvhttp_response_header(uvhttp_response_t* response, const char* name, const char* value) {
    if (response->header_count < MAX_HEADERS) {
        response->headers[response->header_count][0] = strdup(name);
        response->headers[response->header_count][1] = strdup(value);
        response->header_count++;
    }
}

void uvhttp_response_body(uvhttp_response_t* response, const char* body, size_t length) {
    if (response->body) {
        free(response->body);
    }
    response->body = (char*)malloc(length);
    memcpy(response->body, body, length);
    response->body_length = length;
}

void uvhttp_response_destroy(uvhttp_response_t* response) {
    for (int i = 0; i < response->header_count; i++) {
        free(response->headers[i][0]);
        free(response->headers[i][1]);
    }
    if (response->body) free(response->body);
    free(response);
}

static void on_final_write_cb(uv_write_t* req, int status) {
    uvhttp_write_req_t* write_req = (uvhttp_write_req_t*)req;
    if (write_req->buffer) {
        free(write_req->buffer);
    }
    free(write_req);
    uv_close((uv_handle_t*)req->handle, on_close);
}

static void on_transient_write_cb(uv_write_t* req, int status) {
    uvhttp_write_req_t* write_req = (uvhttp_write_req_t*)req;
    if (write_req->buffer) {
        free(write_req->buffer);
    }
    free(write_req);
}

int uvhttp_respond(uvhttp_request_t* request, uvhttp_response_t* response) {
    uvhttp_connection_t* conn = request->connection;

    if (conn->server->config.tls_enabled) {
        // For TLS, we still need to buffer everything to pass it to SSL_write
        char status_line[128];
        int status_len = snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d OK\r\n", response->status_code);

        size_t headers_len = 0;
        for (int i = 0; i < response->header_count; i++) {
            headers_len += strlen(response->headers[i][0]) + 2 + strlen(response->headers[i][1]) + 2;
        }

        char content_len_header[64];
        int content_len_header_len = snprintf(content_len_header, sizeof(content_len_header), "Content-Length: %zu\r\n", response->body_length);

        size_t total_len = status_len + headers_len + content_len_header_len + 2 + response->body_length;
        char* response_buf = (char*)malloc(total_len);
        char* p = response_buf;

        memcpy(p, status_line, status_len);
        p += status_len;

        for (int i = 0; i < response->header_count; i++) {
            p += sprintf(p, "%s: %s\r\n", response->headers[i][0], response->headers[i][1]);
        }

        memcpy(p, content_len_header, content_len_header_len);
        p += content_len_header_len;

        memcpy(p, "\r\n", 2);
        p += 2;

        if (response->body && response->body_length > 0) {
            memcpy(p, response->body, response->body_length);
        }

        SSL_write(conn->ssl, response_buf, total_len);
        flush_write_bio(conn, on_final_write_cb);
        free(response_buf);
    } else {
        // For plain HTTP, use scatter-gather I/O
        uv_buf_t bufs[MAX_HEADERS + 3]; // Status, Headers, CRLF, Body
        int nbufs = 0;
        char header_bufs[MAX_HEADERS][1024]; // Temporary storage for formatted headers
        char status_line[128];
        char content_len_header[64];
        const char* crlf = "\r\n";

        // 1. Status Line
        int status_len = snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d OK\r\n", response->status_code);
        bufs[nbufs++] = uv_buf_init(status_line, status_len);

        // 2. Headers
        for (int i = 0; i < response->header_count; i++) {
            int len = snprintf(header_bufs[i], sizeof(header_bufs[i]), "%s: %s\r\n", response->headers[i][0], response->headers[i][1]);
            bufs[nbufs++] = uv_buf_init(header_bufs[i], len);
        }

        // 3. Content-Length
        int content_len_len = snprintf(content_len_header, sizeof(content_len_header), "Content-Length: %zu\r\n", response->body_length);
        bufs[nbufs++] = uv_buf_init(content_len_header, content_len_len);

        // 4. Final CRLF
        bufs[nbufs++] = uv_buf_init((char*)crlf, 2);

        // 5. Body
        if (response->body && response->body_length > 0) {
            bufs[nbufs++] = uv_buf_init(response->body, response->body_length);
        }

        uvhttp_write_req_t* req = (uvhttp_write_req_t*)malloc(sizeof(uvhttp_write_req_t));
        req->buffer = NULL; // Nothing to free for scatter-gather
        uv_write((uv_write_t*)req, (uv_stream_t*)&conn->tcp, bufs, nbufs, on_final_write_cb);
    }

    return 0;
}

int uvhttp_respond_simple(uvhttp_request_t* req, int status, const char* content_type, const char* body, size_t body_length) {
    uvhttp_response_t* res = uvhttp_response_init();
    uvhttp_response_status(res, status);
    if (content_type) {
        uvhttp_response_header(res, "Content-Type", content_type);
    }
    if (body && body_length > 0) {
        uvhttp_response_body(res, body, body_length);
    }
    int r = uvhttp_respond(req, res);
    uvhttp_response_destroy(res);
    return r;
}

int uvhttp_respond_chunked_start(uvhttp_request_t* req, uvhttp_response_t* res) {
    uvhttp_connection_t* conn = req->connection;
    uvhttp_response_header(res, "Transfer-Encoding", "chunked");
    
    char status_line[128];
    int status_len = snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d OK\r\n", res->status_code);

    char header_bufs[MAX_HEADERS][1024];
    uv_buf_t bufs[MAX_HEADERS + 2];
    int nbufs = 0;

    bufs[nbufs++] = uv_buf_init(status_line, status_len);

    for (int i = 0; i < res->header_count; i++) {
        int len = snprintf(header_bufs[i], sizeof(header_bufs[i]), "%s: %s\r\n", res->headers[i][0], res->headers[i][1]);
        bufs[nbufs++] = uv_buf_init(header_bufs[i], len);
    }
    bufs[nbufs++] = uv_buf_init("\r\n", 2);

    if (conn->server->config.tls_enabled) {
        for (int i = 0; i < nbufs; i++) {
            SSL_write(conn->ssl, bufs[i].base, bufs[i].len);
        }
        flush_write_bio(conn, on_transient_write_cb);
    } else {
        uvhttp_write_req_t* write_req = (uvhttp_write_req_t*)malloc(sizeof(uvhttp_write_req_t));
        write_req->buffer = NULL;
        uv_write((uv_write_t*)write_req, (uv_stream_t*)&conn->tcp, bufs, nbufs, on_transient_write_cb);
    }
    return 0;
}

int uvhttp_respond_chunk(uvhttp_request_t* req, const char* data, size_t length) {
    if (length == 0) return 0;
    uvhttp_connection_t* conn = req->connection;

    char size_hex[16];
    int size_len = snprintf(size_hex, sizeof(size_hex), "%zx\r\n", length);

    if (conn->server->config.tls_enabled) {
        SSL_write(conn->ssl, size_hex, size_len);
        SSL_write(conn->ssl, data, length);
        SSL_write(conn->ssl, "\r\n", 2);
        flush_write_bio(conn, on_transient_write_cb);
    } else {
        uv_buf_t bufs[3];
        bufs[0] = uv_buf_init(size_hex, size_len);
        bufs[1] = uv_buf_init((char*)data, length);
        bufs[2] = uv_buf_init("\r\n", 2);

        uvhttp_write_req_t* write_req = (uvhttp_write_req_t*)malloc(sizeof(uvhttp_write_req_t));
        write_req->buffer = NULL;
        uv_write((uv_write_t*)write_req, (uv_stream_t*)&conn->tcp, bufs, 3, on_transient_write_cb);
    }
    return 0;
}

int uvhttp_respond_chunked_end(uvhttp_request_t* req) {
    uvhttp_connection_t* conn = req->connection;
    if (conn->server->config.tls_enabled) {
        SSL_write(conn->ssl, "0\r\n\r\n", 5);
        flush_write_bio(conn, on_final_write_cb);
    } else {
        uv_buf_t buf = uv_buf_init("0\r\n\r\n", 5);
        uvhttp_write_req_t* write_req = (uvhttp_write_req_t*)malloc(sizeof(uvhttp_write_req_t));
        write_req->buffer = NULL;
        uv_write((uv_write_t*)write_req, (uv_stream_t*)&conn->tcp, &buf, 1, on_final_write_cb);
    }
    return 0;
}


uvhttp_server_t* uvhttp_server_create(uv_loop_t* loop, const uvhttp_server_config_t* config) {
    uvhttp_server_t* server = (uvhttp_server_t*)calloc(1, sizeof(uvhttp_server_t));
    server->loop = loop;
    memcpy(&server->config, config, sizeof(uvhttp_server_config_t));
    
    if (server->config.tls_enabled) {
        SSL_library_init();
        SSL_load_error_strings();
        server->ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (SSL_CTX_use_certificate_file(server->ssl_ctx, server->config.cert_file, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(server->ssl_ctx, server->config.key_file, SSL_FILETYPE_PEM) <= 0) {
            fprintf(stderr, "Failed to load TLS certificate/key\n");
            free(server);
            return NULL;
        }
    }
    return server;
}

int uvhttp_server_listen(uvhttp_server_t* server) {
    uv_tcp_init(server->loop, &server->tcp);
    struct sockaddr_in addr;
    uv_ip4_addr(server->config.host, server->config.port, &addr);
    uv_tcp_bind(&server->tcp, (const struct sockaddr*)&addr, 0);
    int r = uv_listen((uv_stream_t*)&server->tcp, 128, on_new_connection);
    if (r) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return 1;
    }
    server->tcp.data = server;
    return 0;
}

void uvhttp_server_close(uvhttp_server_t* server, uv_close_cb on_server_close) {
    uv_close((uv_handle_t*)&server->tcp, on_server_close);
}

void uvhttp_server_destroy(uvhttp_server_t* server) {
    if (server->ssl_ctx) SSL_CTX_free(server->ssl_ctx);
    free(server);
}

uv_loop_t* uvhttp_server_loop(uvhttp_server_t* server) { return server->loop; }
void uvhttp_server_set_user_data(uvhttp_server_t* server, void* user_data) { server->user_data = user_data; }
void* uvhttp_server_get_user_data(uvhttp_server_t* server) { return server->user_data; }

static void on_new_connection(uv_stream_t* server_stream, int status) {
    if (status < 0) {
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        return;
    }
    uvhttp_server_t* server = (uvhttp_server_t*)server_stream->data;
    uvhttp_connection_t* conn = (uvhttp_connection_t*)calloc(1, sizeof(uvhttp_connection_t));
    conn->server = server;
    uv_tcp_init(server->loop, &conn->tcp);
    conn->tcp.data = conn;

    // Propagate the server's user_data to the connection's user_data
    conn->user_data = server->user_data;

    if (uv_accept(server_stream, (uv_stream_t*)&conn->tcp) == 0) {
        if (server->config.tls_enabled) {
            conn->ssl = SSL_new(server->ssl_ctx);
            conn->read_bio = BIO_new(BIO_s_mem());
            conn->write_bio = BIO_new(BIO_s_mem());
            SSL_set_bio(conn->ssl, conn->read_bio, conn->write_bio);
            SSL_set_accept_state(conn->ssl);
        }
        llhttp_settings_init(&conn->parser_settings);
        conn->parser_settings.on_message_begin = on_message_begin;
        conn->parser_settings.on_url = on_url;
        conn->parser_settings.on_header_field = on_header_field;
        conn->parser_settings.on_header_value = on_header_value;
        conn->parser_settings.on_headers_complete = on_headers_complete;
        conn->parser_settings.on_body = on_body;
        conn->parser_settings.on_message_complete = on_message_complete;
        llhttp_init(&conn->parser, HTTP_REQUEST, &conn->parser_settings);
        conn->parser.data = conn;
        uv_read_start((uv_stream_t*)&conn->tcp, on_alloc, on_read);
    } else {
        uv_close((uv_handle_t*)&conn->tcp, on_close);
    }
}

static void on_close(uv_handle_t* handle) {
    uvhttp_connection_t* conn = (uvhttp_connection_t*)handle->data;
    if (conn->ssl) SSL_free(conn->ssl);
    free(conn);
}

static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    uvhttp_connection_t* conn = (uvhttp_connection_t*)handle->data;
    buf->base = conn->read_buffer;
    buf->len = READ_BUFFER_SIZE;
}

static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    uvhttp_connection_t* conn = (uvhttp_connection_t*)stream->data;
    if (nread > 0) {
        llhttp_errno_t err;
        if (conn->server->config.tls_enabled) {
            BIO_write(conn->read_bio, buf->base, nread);
            if (!conn->handshake_complete) {
                if (handle_tls_handshake(conn) < 0) {
                    uv_close((uv_handle_t*)stream, on_close);
                    return;
                }
                if (!conn->handshake_complete) return;
            }
            
            char read_buf[4096];
            int bytes_read;
            while ((bytes_read = SSL_read(conn->ssl, read_buf, sizeof(read_buf))) > 0) {
                err = llhttp_execute(&conn->parser, read_buf, bytes_read);
                if (err != HPE_OK) goto error;
            }
            flush_write_bio(conn, on_transient_write_cb);
        } else {
            err = llhttp_execute(&conn->parser, buf->base, nread);
            if (err != HPE_OK) goto error;
        }
    } else if (nread < 0) {
        uv_close((uv_handle_t*)stream, on_close);
    }
    return;

error:
    if (conn->server->config.on_error) {
        uvhttp_request_t request = { .connection = conn };
        conn->server->config.on_error(&request, llhttp_get_errno(&conn->parser), conn->parser.reason);
    } else {
        fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(llhttp_get_errno(&conn->parser)), conn->parser.reason);
    }
    uv_close((uv_handle_t*)stream, on_close);
}

static void flush_write_bio(uvhttp_connection_t* conn, uv_write_cb cb) {
    int pending = BIO_pending(conn->write_bio);
    if (pending > 0) {
        char* buf_data = (char*)malloc(pending);
        int bytes_read = BIO_read(conn->write_bio, buf_data, pending);
        if (bytes_read > 0) {
            uvhttp_write_req_t* req = (uvhttp_write_req_t*)malloc(sizeof(uvhttp_write_req_t));
            req->buffer = buf_data;
            uv_buf_t buf = uv_buf_init(buf_data, bytes_read);
            uv_write((uv_write_t*)req, (uv_stream_t*)&conn->tcp, &buf, 1, cb);
        } else {
            free(buf_data);
        }
    }
}

static int handle_tls_handshake(uvhttp_connection_t* conn) {
    int r = SSL_do_handshake(conn->ssl);
    flush_write_bio(conn, on_transient_write_cb);
    if (r == 1) {
        conn->handshake_complete = 1;
        return 0;
    }
    int err = SSL_get_error(conn->ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return 0;
    }
    return -1;
}

static int on_message_begin(llhttp_t* parser) {
    uvhttp_connection_t* conn = (uvhttp_connection_t*)parser->data;
    conn->header_count = 0;
    return 0;
}

static int on_url(llhttp_t* parser, const char* at, size_t length) {
    uvhttp_connection_t* conn = (uvhttp_connection_t*)parser->data;
    conn->url.at = at;
    conn->url.length = length;
    return 0;
}

static int on_header_field(llhttp_t* parser, const char* at, size_t length) {
    uvhttp_connection_t* conn = (uvhttp_connection_t*)parser->data;
    if (conn->header_count > 0 && conn->headers[conn->header_count - 1][1].at == NULL) {
        conn->headers[conn->header_count - 1][1].at = at;
        conn->headers[conn->header_count - 1][1].length = 0;
    }
    
    if (conn->header_count < MAX_HEADERS) {
        conn->headers[conn->header_count][0].at = at;
        conn->headers[conn->header_count][0].length = length;
        conn->headers[conn->header_count][1].at = NULL;
        conn->headers[conn->header_count][1].length = 0;
    }
    return 0;
}

static int on_header_value(llhttp_t* parser, const char* at, size_t length) {
    uvhttp_connection_t* conn = (uvhttp_connection_t*)parser->data;
    if (conn->header_count < MAX_HEADERS) {
        conn->headers[conn->header_count][1].at = at;
        conn->headers[conn->header_count][1].length = length;
        conn->header_count++;
    }
    return 0;
}

static int on_headers_complete(llhttp_t* parser) {
    uvhttp_connection_t* conn = (uvhttp_connection_t*)parser->data;
    const char* method_str = llhttp_method_name(llhttp_get_method(parser));
    conn->method.at = method_str;
    conn->method.length = strlen(method_str);

    if (conn->server->config.max_body_size > 0 && parser->content_length > conn->server->config.max_body_size) {
        llhttp_set_error_reason(parser, "Body size exceeds limit");
        return HPE_USER;
    }
    
    uvhttp_request_t request = { .connection = conn };
    if (conn->server->config.on_headers) {
        conn->server->config.on_headers(&request);
    }
    return 0;
}

static int on_body(llhttp_t* parser, const char* at, size_t length) {
    uvhttp_connection_t* conn = (uvhttp_connection_t*)parser->data;
    if (conn->server->config.on_body_chunk) {
        uvhttp_request_t request = { .connection = conn };
        uvhttp_str_t chunk = { .at = at, .length = length };
        conn->server->config.on_body_chunk(&request, &chunk);
    }
    return 0;
}

static int on_message_complete(llhttp_t* parser) {
    uvhttp_connection_t* conn = (uvhttp_connection_t*)parser->data;
    uvhttp_request_t request = { .connection = conn };
    if (conn->server->config.on_complete) {
        conn->server->config.on_complete(&request);
    }
    return 0;
}

#endif // UVHTTP_IMPL