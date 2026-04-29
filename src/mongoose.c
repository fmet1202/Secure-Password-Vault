#include "mongoose.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MG_BUF_SIZE 8192
#define MG_MAX_CLIENTS 100

typedef struct ClientData {
    int fd;
    char buffer[MG_BUF_SIZE];
    size_t buf_len;
    mg_http_message hm;
    SSL* ssl;
    struct mg_connection* mc;
} ClientData;

static SSL_CTX* g_ssl_ctx = NULL;

static volatile bool g_running = false;
static __thread SSL* g_current_ssl = NULL;

typedef struct {
    int listen_fd;
    void* connections;
} mg_mgr_internal;

static const char* status_message(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 500: return "Internal Server Error";
        default: return "Unknown";
    }
}

static const char* mime_type(const char* path) {
    const char* ext = strrchr(path, '.');
    if (!ext) return "text/plain";
    ext++;
    if (strcmp(ext, "html") == 0) return "text/html";
    if (strcmp(ext, "css") == 0) return "text/css";
    if (strcmp(ext, "js") == 0) return "application/javascript";
    if (strcmp(ext, "json") == 0) return "application/json";
    if (strcmp(ext, "png") == 0) return "image/png";
    if (strcmp(ext, "jpg") == 0 || strcmp(ext, "jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, "ico") == 0) return "image/x-icon";
    return "text/plain";
}

static int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

int mg_url_decode(const char* src, size_t src_len, char* dst, size_t dst_len) {
    size_t i, j = 0;
    for (i = 0; i < src_len && j < dst_len - 1; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            dst[j++] = (char)((hex_to_int(src[i+1]) << 4) | hex_to_int(src[i+2]));
            i += 2;
        } else if (src[i] == '+') {
            dst[j++] = ' ';
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
    return (int)j;
}

static HttpMethod parse_method(const char* m) {
    if (strcmp(m, "GET") == 0) return MG_HTTP_GET;
    if (strcmp(m, "POST") == 0) return MG_HTTP_POST;
    if (strcmp(m, "PUT") == 0) return MG_HTTP_PUT;
    if (strcmp(m, "DELETE") == 0) return MG_HTTP_DELETE;
    if (strcmp(m, "OPTIONS") == 0) return MG_HTTP_OPTIONS;
    return MG_HTTP_GET;
}

static bool parse_http_message(ClientData* cd, mg_http_message* hm) {
    char* buf = cd->buffer;
    size_t len = cd->buf_len;
    
    char method[16] = {0}, uri[1024] = {0};
    if (sscanf(buf, "%15s %1023s", method, uri) < 2) return false;
    
    hm->method = parse_method(method);
    hm->uri.buf = strdup(uri);
    hm->uri.len = strlen(uri);
    
    hm->num_headers = 0;
    char* line_start = buf;
    char* line_end;
    
    while ((line_end = strstr(line_start, "\r\n")) != NULL && hm->num_headers < MG_MAX_HEADERS) {
        if (line_end == line_start) {
            break;
        }
        
        char* colon = strchr(line_start, ':');
        if (colon && colon < line_end) {
            size_t name_len = (size_t)(colon - line_start);
            if (name_len < sizeof(hm->headers[0].name)) {
                memcpy(hm->headers[hm->num_headers].name, line_start, name_len);
                hm->headers[hm->num_headers].name[name_len] = '\0';
                
                colon++;
                while (*colon == ' ' && colon < line_end) colon++;
                
                size_t value_len = (size_t)(line_end - colon);
                if (value_len < sizeof(hm->headers[0].value)) {
                    memcpy(hm->headers[hm->num_headers].value, colon, value_len);
                    hm->headers[hm->num_headers].value[value_len] = '\0';
                    hm->num_headers++;
                }
            }
        }
        
        line_start = line_end + 2;
    }
    
    char* body_start = strstr(buf, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        size_t body_len = len - (size_t)(body_start - buf);
        hm->body.buf = strndup(body_start, body_len);
        hm->body.len = body_len;
    } else {
        hm->body.buf = strdup("");
        hm->body.len = 0;
    }
    
    return true;
}

struct mg_str mg_str_n(const char* s, size_t len) {
    struct mg_str result;
    result.buf = (char*)s;
    result.len = len;
    return result;
}

bool mg_match(mg_str uri, mg_str pattern, int* caps) {
    (void)caps;
    if (pattern.buf[0] == '*') {
        return true;
    }
    if (pattern.len == 1 && pattern.buf[0] == '/') {
        return uri.len == 1 && uri.buf[0] == '/';
    }
    if (uri.len >= pattern.len && strncmp(uri.buf, pattern.buf, pattern.len) == 0) {
        return uri.len == pattern.len || uri.buf[pattern.len] == '?' || uri.buf[pattern.len] == '/';
    }
    return false;
}

int mg_vcasecmp(const mg_str* a, const char* b) {
    if (!a || !a->buf) return -1;
    size_t b_len = strlen(b);
    if (a->len != b_len) return (int)(a->len - b_len);
    return strncasecmp(a->buf, b, b_len);
}

mg_str* mg_http_get_header(const mg_str* hm, const char* name) {
    (void)hm;
    (void)name;
    return NULL;
}

int mg_http_get_var(const mg_str* body, const char* name, char* out, size_t len) {
    if (!body || !body->buf || !name || !out) return -1;
    
    size_t name_len = strlen(name);
    const char* start = body->buf;
    const char* end = body->buf + body->len;
    
    while (start < end) {
        const char* eq = strchr(start, '=');
        if (!eq || eq >= end) break;
        
        const char* amp = strchr(eq, '&');
        if (!amp) amp = end;
        
        size_t var_name_len = (size_t)(eq - start);
        if (var_name_len == name_len && strncmp(start, name, name_len) == 0) {
            size_t val_len = (size_t)(amp - eq - 1);
            if (val_len >= len) val_len = len - 1;
            
            mg_url_decode(eq + 1, val_len, out, len);
            return (int)val_len;
        }
        
        start = amp + 1;
    }
    
    out[0] = '\0';
    return -1;
}

void mg_printf(struct mg_connection* c, const char* fmt, ...) {
    char buf[65536];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    if (len > 0) {
        if (g_current_ssl) {
            SSL_write(g_current_ssl, buf, len);
        } else {
            send(c->fd, buf, (size_t)len, 0);
        }
    }
}

void mg_http_reply(struct mg_connection* c, int status_code, const char* headers, const char* body_fmt, ...) {
    char header[4096];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n%s\r\n",
        status_code, status_message(status_code), headers ? headers : "");
    
    va_list args;
    va_start(args, body_fmt);
    char body[16384] = {0};
    vsnprintf(body, sizeof(body), body_fmt ? body_fmt : "", args);
    va_end(args);
    
    char response[20480];
    int offset = 0;
    offset += snprintf(response + offset, sizeof(response) - offset, "%s", header);
    if (body[0]) {
        offset += snprintf(response + offset, sizeof(response) - offset, "Content-Length: %zu\r\n\r\n", strlen(body));
        offset += snprintf(response + offset, sizeof(response) - offset, "%s", body);
    } else {
        offset += snprintf(response + offset, sizeof(response) - offset, "\r\n");
    }
    
    if (g_current_ssl) {
        SSL_write(g_current_ssl, response, offset);
    } else {
        send(c->fd, response, (size_t)offset, 0);
    }
}

static void* handle_connection(void* arg) {
    ClientData* cd = (ClientData*)arg;
    extern mg_event_handler_t g_current_handler;
    extern bool g_use_https;
    
    mg_connection mc = { .fd = cd->fd };
    
    if (g_use_https && g_current_handler) {
        g_current_handler(&mc, 1, NULL);
        
        SSL* ssl = (SSL*)mc.tls_ctx;
        if (ssl) {
            cd->ssl = ssl;
            g_current_ssl = ssl;
            cd->buf_len = (size_t)SSL_read(ssl, cd->buffer, MG_BUF_SIZE - 1);
        }
        
        if (cd->buf_len > 0) {
            parse_http_message(cd, &cd->hm);
            mg_http_message* hm = &cd->hm;
            g_current_handler(&mc, 0x1E9, hm);
        }
        g_current_ssl = NULL;
    } else if (cd->buf_len > 0) {
        parse_http_message(cd, &cd->hm);
        mg_http_message* hm = &cd->hm;
        if (g_current_handler) {
            g_current_handler(&mc, 0x1E9, hm);
        }
    }
    
    if (mc.tls_ctx) SSL_free((SSL*)mc.tls_ctx);
    close(cd->fd);
    if (cd->hm.uri.buf) free((void*)cd->hm.uri.buf);
    if (cd->hm.body.buf) free((void*)cd->hm.body.buf);
    free(cd);
    return NULL;
}

mg_event_handler_t g_current_handler = NULL;
int g_port = 8443;
bool g_use_https = false;

void mg_tls_init(struct mg_connection* c, struct mg_tls_opts* opts) {
    (void)opts;
    c->tls_ctx = NULL;
    if (g_ssl_ctx && c->fd >= 0) {
        SSL* ssl = SSL_new(g_ssl_ctx);
        if (ssl) {
            SSL_set_fd(ssl, c->fd);
            int ret = SSL_accept(ssl);
            if (ret <= 0) {
                int err = SSL_get_error(ssl, ret);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    SSL_free(ssl);
                    return;
                }
            }
            c->tls_ctx = ssl;
        }
    }
}

static void init_ssl_ctx(const char* cert, const char* key) {
    if (g_ssl_ctx) return;
    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (g_ssl_ctx) {
        SSL_CTX_use_certificate_file(g_ssl_ctx, cert, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(g_ssl_ctx, key, SSL_FILETYPE_PEM);
    }
}

void mg_mgr_init(mg_mgr* mgr) {
    mg_mgr_internal* m = (mg_mgr_internal*)calloc(1, sizeof(mg_mgr_internal));
    mgr->listen_fd = -1;
    mgr->next = m;
}

void mg_http_listen(mg_mgr* mgr, const char* url, mg_event_handler_t handler, void* user_data) {
    (void)user_data;
    
    g_port = 8443;
    g_use_https = false;
    
    if (strncmp(url, "https://", 8) == 0) {
        g_use_https = true;
        init_ssl_ctx("cert.pem", "key.pem");
    }
    sscanf(url, "%*[^:]://%*[^:]:%d", &g_port);
    
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return;
    
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)g_port);
    
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listen_fd);
        return;
    }
    
    if (listen(listen_fd, MG_MAX_CLIENTS) < 0) {
        close(listen_fd);
        return;
    }
    
    mgr->listen_fd = listen_fd;
    g_current_handler = handler;
    
    printf("[SERVER] Mongoose listening on %s://0.0.0.0:%d\n", g_use_https ? "https" : "http", g_port);
}

void mg_mgr_poll(mg_mgr* mgr, int timeout_ms) {
    (void)timeout_ms;
    
    if (mgr->listen_fd < 0) return;
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    struct timeval tv = {0};
    tv.tv_usec = 100000;
    
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET((unsigned)mgr->listen_fd, &fds);
    
    if (select(mgr->listen_fd + 1, &fds, NULL, NULL, &tv) > 0) {
        int client_fd = accept(mgr->listen_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd >= 0) {
            ClientData* cd = calloc(1, sizeof(ClientData));
            if (cd) {
                cd->fd = client_fd;
                
                if (!g_use_https) {
                    cd->buf_len = (size_t)read(client_fd, cd->buffer, MG_BUF_SIZE - 1);
                    if (cd->buf_len > 0) {
                        pthread_t thread;
                        pthread_create(&thread, NULL, handle_connection, cd);
                        pthread_detach(thread);
                    } else {
                        close(client_fd);
                        free(cd);
                    }
                } else {
                    pthread_t thread;
                    pthread_create(&thread, NULL, handle_connection, cd);
                    pthread_detach(thread);
                }
            } else {
                close(client_fd);
            }
        }
    }
}

void mg_mgr_free(mg_mgr* mgr) {
    if (mgr->listen_fd >= 0) {
        close(mgr->listen_fd);
    }
    free(mgr->next);
}

const char* mg_get_header(HttpRequest* req, const char* name) {
    for (int i = 0; i < req->num_headers; i++) {
        if (strcasecmp(req->headers[i].name, name) == 0) {
            return req->headers[i].value;
        }
    }
    return NULL;
}

const char* mg_get_cookie(HttpRequest* req, const char* name) {
    static char value[256] = {0};
    char pattern[300] = {0};
    snprintf(pattern, sizeof(pattern), "%s=", name);
    
    char* cookie_start = strstr(req->cookie, pattern);
    if (!cookie_start) return NULL;
    
    cookie_start += strlen(pattern);
    char* cookie_end = strchr(cookie_start, ';');
    size_t len = cookie_end ? (size_t)(cookie_end - cookie_start) : strlen(cookie_start);
    if (len >= sizeof(value)) len = sizeof(value) - 1;
    
    memcpy(value, cookie_start, len);
    value[len] = '\0';
    return value;
}

void mg_set_header(HttpResponse* res, const char* name, const char* value) {
    if (res->num_headers < MG_MAX_HEADERS) {
        res->headers[res->num_headers].name = name;
        res->headers[res->num_headers].value = value;
        res->num_headers++;
    }
}

void mg_set_cookie(HttpResponse* res, const char* name, const char* value, int max_age) {
    char cookie[512];
    if (max_age > 0) {
        snprintf(cookie, sizeof(cookie), "%s=%s; HttpOnly; Secure; SameSite=Strict; Max-Age=%d", name, value, max_age);
    } else {
        snprintf(cookie, sizeof(cookie), "%s=%s; HttpOnly; Secure; SameSite=Strict", name, value);
    }
    mg_set_header(res, "Set-Cookie", strdup(cookie));
}

void mg_send_json(HttpResponse* res, int status, const char* json_str) {
    res->status_code = status;
    res->status_message = status_message(status);
    res->body = json_str;
    res->body_len = strlen(json_str);
    mg_set_header(res, "Content-Type", "application/json");
    mg_set_header(res, "Cache-Control", "no-store");
}

void mg_send_file(HttpResponse* res, const char* filepath) {
    struct stat st;
    if (stat(filepath, &st) == 0 && S_ISREG(st.st_mode)) {
        FILE* f = fopen(filepath, "rb");
        if (f) {
            char* content = malloc((size_t)st.st_size);
            fread(content, 1, (size_t)st.st_size, f);
            fclose(f);
            res->status_code = 200;
            res->status_message = "OK";
            res->body = content;
            res->body_len = (size_t)st.st_size;
            mg_set_header(res, "Content-Type", mime_type(filepath));
        }
    }
}

void mg_redirect(HttpResponse* res, const char* location) {
    res->status_code = 302;
    res->status_message = "Found";
    mg_set_header(res, "Location", location);
}

char* mg_get_param(HttpRequest* req, const char* name) {
    static char value[1024] = {0};
    memset(value, 0, sizeof(value));
    
    char* data = req->body;
    size_t data_len = req->body_len;
    
    if (req->query_string[0]) {
        data = req->query_string;
        data_len = strlen(req->query_string);
    }
    
    char* found = strstr(data, name);
    if (!found) return NULL;
    
    found += strlen(name);
    if (*found != '=') return NULL;
    found++;
    
    char* end = strchr(found, '&');
    size_t len = end ? (size_t)(end - found) : strlen(found);
    if (len >= sizeof(value)) len = sizeof(value) - 1;
    
    mg_url_decode(found, len, value, sizeof(value));
    return value;
}
