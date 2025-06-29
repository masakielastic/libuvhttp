#ifndef UVHTTP_H
#define UVHTTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <uv.h>

// Forward declarations
struct http_server_s;
struct http_request_s;
struct http_response_s;
struct http_server_config_s;

// Request handler callback type
typedef void (*http_request_handler_t)(struct http_request_s* request);

// HTTP server structure (opaque)
typedef struct http_server_s http_server_t;

// HTTP request structure (opaque)
typedef struct http_request_s http_request_t;

// HTTP response structure (opaque)
typedef struct http_response_s http_response_t;

// HTTP server configuration structure
typedef struct http_server_config_s {
    const char* host;
    int port;
    http_request_handler_t handler;
    int tls_enabled;
    const char* cert_file;
    const char* key_file;
} http_server_config_t;

// Server management functions
http_server_t* http_server_create(const http_server_config_t* config);
int http_server_listen(http_server_t* server);
void http_server_destroy(http_server_t* server);
uv_loop_t* http_server_loop(http_server_t* server);


// Request functions
const char* http_request_method(http_request_t* request);
const char* http_request_target(http_request_t* request);
const char* http_request_header(http_request_t* request, const char* name);
const char* http_request_body(http_request_t* request);
size_t http_request_body_length(http_request_t* request);
void* http_request_get_user_data(http_request_t* request);
void http_request_set_user_data(http_request_t* request, void* user_data);


// Response functions
http_response_t* http_response_init(void);
void http_response_status(http_response_t* response, int status);
void http_response_header(http_response_t* response, const char* name, const char* value);
void http_response_body(http_response_t* response, const char* body, size_t length);
int http_respond(http_request_t* request, http_response_t* response);
void http_response_destroy(http_response_t* response);

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
#include <time.h>

#define MAX_HEADERS 64

// Internal structures
struct http_server_s {
    uv_tcp_t tcp;
    uv_loop_t* loop;
    SSL_CTX* ssl_ctx;
    http_request_handler_t handler;
    const char* host;
    int port;
    int tls_enabled;
};

typedef struct {
    uv_tcp_t tcp;
    SSL* ssl;
    BIO* read_bio;
    BIO* write_bio;
    llhttp_t parser;
    llhttp_settings_t parser_settings;
    int handshake_complete;
    http_server_t* server;
    
    char* method;
    char* url;
    char* headers[MAX_HEADERS][2];
    int header_count;
    char* current_header_field;
    char* body;
    size_t body_length;
    size_t body_capacity;

    http_response_t* pending_response;
    void* user_data;
} http_connection_t;

struct http_request_s {
    http_connection_t* connection;
};

struct http_response_s {
    int status_code;
    char* headers[MAX_HEADERS][2];
    int header_count;
    char* body;
    size_t body_length;
};

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

static void flush_write_bio(http_connection_t* conn, uv_write_cb cb);
static int handle_tls_handshake(http_connection_t* conn);

// --- Function Implementations ---

const char* http_request_method(http_request_t* request) { return request->connection->method; }
const char* http_request_target(http_request_t* request) { return request->connection->url; }
const char* http_request_body(http_request_t* request) { return request->connection->body; }
size_t http_request_body_length(http_request_t* request) { return request->connection->body_length; }
void* http_request_get_user_data(http_request_t* request) { return request->connection->user_data; }
void http_request_set_user_data(http_request_t* request, void* user_data) { request->connection->user_data = user_data; }

const char* http_request_header(http_request_t* request, const char* name) {
    for (int i = 0; i < request->connection->header_count; i++) {
        if (strcasecmp(request->connection->headers[i][0], name) == 0) {
            return request->connection->headers[i][1];
        }
    }
    return NULL;
}

http_response_t* http_response_init(void) {
    http_response_t* response = (http_response_t*)calloc(1, sizeof(http_response_t));
    response->status_code = 200;
    return response;
}

void http_response_status(http_response_t* response, int status) { response->status_code = status; }

void http_response_header(http_response_t* response, const char* name, const char* value) {
    if (response->header_count < MAX_HEADERS) {
        response->headers[response->header_count][0] = strdup(name);
        response->headers[response->header_count][1] = strdup(value);
        response->header_count++;
    }
}

void http_response_body(http_response_t* response, const char* body, size_t length) {
    response->body = (char*)malloc(length);
    memcpy(response->body, body, length);
    response->body_length = length;
}

void http_response_destroy(http_response_t* response) {
    for (int i = 0; i < response->header_count; i++) {
        free(response->headers[i][0]);
        free(response->headers[i][1]);
    }
    if (response->body) free(response->body);
    free(response);
}

int http_respond(http_request_t* request, http_response_t* response) {
    http_connection_t* conn = request->connection;
    
    char status_line[128];
    snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d OK\r\n", response->status_code);

    size_t headers_len = 0;
    for (int i = 0; i < response->header_count; i++) {
        headers_len += strlen(response->headers[i][0]) + 2 + strlen(response->headers[i][1]) + 2;
    }

    char content_len_header[64];
    snprintf(content_len_header, sizeof(content_len_header), "Content-Length: %zu\r\n", response->body_length);

    size_t total_len = strlen(status_line) + headers_len + strlen(content_len_header) + 2 + response->body_length;
    char* response_buf = (char*)malloc(total_len + 1);
    char* p = response_buf;

    strcpy(p, status_line);
    p += strlen(status_line);

    for (int i = 0; i < response->header_count; i++) {
        p += sprintf(p, "%s: %s\r\n", response->headers[i][0], response->headers[i][1]);
    }

    strcpy(p, content_len_header);
    p += strlen(content_len_header);

    strcpy(p, "\r\n");
    p += 2;

    if (response->body && response->body_length > 0) {
        memcpy(p, response->body, response->body_length);
    }
    response_buf[total_len] = '\0';

    if (conn->server->tls_enabled) {
        SSL_write(conn->ssl, response_buf, total_len);
        flush_write_bio(conn, on_final_write_cb);
        free(response_buf);
    } else {
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
        uv_buf_t buf = uv_buf_init(response_buf, total_len);
        req->data = response_buf;
        uv_write(req, (uv_stream_t*)&conn->tcp, &buf, 1, on_final_write_cb);
    }

    return 0;
}

http_server_t* http_server_create(const http_server_config_t* config) {
    http_server_t* server = (http_server_t*)calloc(1, sizeof(http_server_t));
    server->loop = uv_default_loop();
    server->host = config->host ? strdup(config->host) : "127.0.0.1";
    server->port = config->port;
    server->handler = config->handler;
    server->tls_enabled = config->tls_enabled;

    if (server->tls_enabled) {
        SSL_library_init();
        SSL_load_error_strings();
        server->ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (SSL_CTX_use_certificate_file(server->ssl_ctx, config->cert_file, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(server->ssl_ctx, config->key_file, SSL_FILETYPE_PEM) <= 0) {
            fprintf(stderr, "Failed to load TLS certificate/key\n");
            free(server);
            return NULL;
        }
    }
    return server;
}

int http_server_listen(http_server_t* server) {
    uv_tcp_init(server->loop, &server->tcp);
    struct sockaddr_in addr;
    uv_ip4_addr(server->host, server->port, &addr);
    uv_tcp_bind(&server->tcp, (const struct sockaddr*)&addr, 0);
    int r = uv_listen((uv_stream_t*)&server->tcp, 128, on_new_connection);
    if (r) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return 1;
    }
    server->tcp.data = server;
    return uv_run(server->loop, UV_RUN_DEFAULT);
}

void http_server_destroy(http_server_t* server) {
    if (server->ssl_ctx) SSL_CTX_free(server->ssl_ctx);
    if(server->host) free((void*)server->host);
    free(server);
}

uv_loop_t* http_server_loop(http_server_t* server) { return server->loop; }

static void on_new_connection(uv_stream_t* server_stream, int status) {
    if (status < 0) {
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        return;
    }
    http_server_t* server = (http_server_t*)server_stream->data;
    http_connection_t* conn = (http_connection_t*)calloc(1, sizeof(http_connection_t));
    conn->server = server;
    uv_tcp_init(server->loop, &conn->tcp);
    conn->tcp.data = conn;

    if (uv_accept(server_stream, (uv_stream_t*)&conn->tcp) == 0) {
        if (server->tls_enabled) {
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
    http_connection_t* conn = (http_connection_t*)handle->data;
    if (conn->ssl) SSL_free(conn->ssl);
    if (conn->method) free(conn->method);
    if (conn->url) free(conn->url);
    for (int i = 0; i < conn->header_count; i++) {
        free(conn->headers[i][0]);
        free(conn->headers[i][1]);
    }
    if (conn->current_header_field) free(conn->current_header_field);
    if (conn->body) free(conn->body);
    free(conn);
}

static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    http_connection_t* conn = (http_connection_t*)stream->data;
    if (nread > 0) {
        if (conn->server->tls_enabled) {
            BIO_write(conn->read_bio, buf->base, nread);
            if (!conn->handshake_complete) {
                if (handle_tls_handshake(conn) < 0) {
                    uv_close((uv_handle_t*)stream, on_close);
                    goto cleanup;
                }
                if (!conn->handshake_complete) goto cleanup;
            }
            
            char read_buf[4096];
            int bytes_read;
            while ((bytes_read = SSL_read(conn->ssl, read_buf, sizeof(read_buf))) > 0) {
                llhttp_execute(&conn->parser, read_buf, bytes_read);
            }
            flush_write_bio(conn, on_transient_write_cb);
        } else {
            llhttp_execute(&conn->parser, buf->base, nread);
        }
    } else if (nread < 0) {
        uv_close((uv_handle_t*)stream, on_close);
    }
cleanup:
    if (buf->base) free(buf->base);
}

static void on_final_write_cb(uv_write_t* req, int status) {
    if (req->data) {
        free(req->data);
    }
    uv_close((uv_handle_t*)req->handle, on_close);
    free(req);
}

static void on_transient_write_cb(uv_write_t* req, int status) {
    if (req->data) {
        free(req->data);
    }
    free(req);
}

static void flush_write_bio(http_connection_t* conn, uv_write_cb cb) {
    int pending = BIO_pending(conn->write_bio);
    if (pending > 0) {
        char* buf_data = (char*)malloc(pending);
        int bytes_read = BIO_read(conn->write_bio, buf_data, pending);
        if (bytes_read > 0) {
            uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
            uv_buf_t buf = uv_buf_init(buf_data, bytes_read);
            req->data = buf_data;
            uv_write(req, (uv_stream_t*)&conn->tcp, &buf, 1, cb);
        } else {
            free(buf_data);
        }
    }
}

static int handle_tls_handshake(http_connection_t* conn) {
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

static int on_message_begin(llhttp_t* parser) { return 0; }
static int on_url(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    conn->url = (char*)malloc(length + 1);
    memcpy(conn->url, at, length);
    conn->url[length] = '\0';
    return 0;
}
static int on_header_field(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    if (conn->current_header_field) free(conn->current_header_field);
    conn->current_header_field = (char*)malloc(length + 1);
    memcpy(conn->current_header_field, at, length);
    conn->current_header_field[length] = '\0';
    return 0;
}
static int on_header_value(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    if (conn->current_header_field && conn->header_count < MAX_HEADERS) {
        conn->headers[conn->header_count][0] = conn->current_header_field;
        conn->current_header_field = NULL;
        conn->headers[conn->header_count][1] = (char*)malloc(length + 1);
        memcpy(conn->headers[conn->header_count][1], at, length);
        conn->headers[conn->header_count][1][length] = '\0';
        conn->header_count++;
    }
    return 0;
}
static int on_headers_complete(llhttp_t* parser) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    const char* method_str = llhttp_method_name(llhttp_get_method(parser));
    conn->method = strdup(method_str);
    return 0;
}
static int on_body(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    if (!conn->body) {
        conn->body = (char*)malloc(length);
        conn->body_capacity = length;
    } else if (conn->body_length + length > conn->body_capacity) {
        conn->body_capacity = (conn->body_length + length) * 2;
        conn->body = (char*)realloc(conn->body, conn->body_capacity);
    }
    memcpy(conn->body + conn->body_length, at, length);
    conn->body_length += length;
    return 0;
}
static int on_message_complete(llhttp_t* parser) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    http_request_t request = { .connection = conn };
    conn->server->handler(&request);
    return 0;
}

#endif // UVHTTP_IMPL

