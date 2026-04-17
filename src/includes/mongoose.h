#ifndef MONGOOSE_H
#define MONGOOSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MG_MAX_HEADERS 64
#define MG_EV_HTTP_MSG 0x1E9

#define mg_str(s) ((mg_str){s, sizeof(s) - 1})

typedef enum {
    MG_HTTP_GET,
    MG_HTTP_POST,
    MG_HTTP_PUT,
    MG_HTTP_DELETE,
    MG_HTTP_OPTIONS
} HttpMethod;

typedef struct {
    const char* name;
    const char* value;
} HttpHeader;

typedef struct {
    HttpMethod method;
    char uri[1024];
    char query_string[1024];
    char body[8192];
    size_t body_len;
    HttpHeader headers[MG_MAX_HEADERS];
    int num_headers;
    char remote_addr[64];
    char cookie[4096];
} HttpRequest;

typedef struct {
    int status_code;
    const char* status_message;
    HttpHeader headers[MG_MAX_HEADERS];
    int num_headers;
    const char* body;
    size_t body_len;
} HttpResponse;

typedef struct mg_str {
    char* buf;
    size_t len;
} mg_str;

typedef struct {
    char name[64];
    char value[512];
} HttpHeaderParsed;

typedef struct mg_http_message {
    HttpMethod method;
    mg_str uri;
    mg_str query;
    mg_str query_string;
    mg_str body;
    HttpHeaderParsed headers[MG_MAX_HEADERS];
    int num_headers;
} mg_http_message;

typedef struct mg_mgr {
    int listen_fd;
    void* next;
} mg_mgr;

typedef struct mg_connection {
    int fd;
    struct sockaddr_in addr;
    void* tls_ctx;
} mg_connection;

typedef struct mg_tls_opts {
    struct mg_str cert;
    struct mg_str key;
} mg_tls_opts;

#define MG_EV_ACCEPT 0x01
#define MG_TLS_OPENSSL 1

typedef void (*mg_event_handler_t)(struct mg_connection*, int, void*);

void mg_mgr_init(mg_mgr*);
void mg_http_listen(mg_mgr*, const char*, mg_event_handler_t, void*);
void mg_mgr_poll(mg_mgr*, int);
void mg_mgr_free(mg_mgr*);
void mg_tls_init(struct mg_connection*, struct mg_tls_opts*);

int mg_http_get_var(const mg_str* body, const char* name, char* out, size_t len);
mg_str* mg_http_get_header(const mg_str* hm, const char* name);
struct mg_str mg_str_n(const char* s, size_t len);
struct mg_http_message* mg_http_get_message(struct mg_connection* c);

bool mg_match(mg_str uri, mg_str pattern, int* caps);
int mg_vcasecmp(const mg_str* a, const char* b);
void mg_http_reply(struct mg_connection* c, int status_code, const char* headers, const char* body_fmt, ...);

const char* mg_get_header(HttpRequest* req, const char* name);
const char* mg_get_cookie(HttpRequest* req, const char* name);
void mg_set_header(HttpResponse* res, const char* name, const char* value);
void mg_set_cookie(HttpResponse* res, const char* name, const char* value, int max_age);
void mg_send_json(HttpResponse* res, int status, const char* json_str);
void mg_send_file(HttpResponse* res, const char* filepath);
void mg_redirect(HttpResponse* res, const char* location);

int mg_url_decode(const char* src, size_t src_len, char* dst, size_t dst_len);
char* mg_get_param(HttpRequest* req, const char* name);

#endif
