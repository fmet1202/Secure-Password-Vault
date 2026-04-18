#include "mongoose.h"
#include "securevault.h"

#ifdef method
#undef method
#endif

#define SEC_HEADERS "Content-Security-Policy: default-src 'self' 'unsafe-inline' https://cdn.simplecss.org\r\n" \
                    "X-Frame-Options: DENY\r\n" \
                    "X-Content-Type-Options: nosniff\r\n" \
                    "Cache-Control: no-store, max-age=0\r\n" \
                    "Strict-Transport-Security: max-age=31536000\r\n"

static struct mg_str s_cert;
static struct mg_str s_key;

static char* read_file(const char* filepath) {
    FILE* f = fopen(filepath, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* buf = calloc(1, length + 1);
    if (buf) fread(buf, 1, length, f);
    fclose(f);
    return buf;
}

static char* render_template(const char* tmpl, const char* key, const char* val) {
    if (!tmpl || !key || !val) return tmpl ? strdup(tmpl) : NULL;
    const char* pos = strstr(tmpl, key);
    if (!pos) return strdup(tmpl);
    
    size_t pre_len = pos - tmpl;
    size_t key_len = strlen(key);
    size_t val_len = strlen(val);
    size_t post_len = strlen(pos + key_len);
    
    char* res = calloc(1, pre_len + val_len + post_len + 1);
    if (!res) return NULL;
    
    memcpy(res, tmpl, pre_len);
    memcpy(res + pre_len, val, val_len);
    memcpy(res + pre_len + val_len, pos + key_len, post_len);
    return res;
}

static char* get_flash_message(struct mg_http_message *hm) {
    char buf[256] = {0};
    if (mg_http_get_var(&hm->query, "err", buf, sizeof(buf)) > 0) {
        char* out = calloc(1, 512);
        snprintf(out, 512, "<p style='color: #fff; background: #d9534f; padding: 10px; border-radius: 5px;'>%s</p>", buf);
        return out;
    }
    if (mg_http_get_var(&hm->query, "msg", buf, sizeof(buf)) > 0) {
        char* out = calloc(1, 512);
        snprintf(out, 512, "<p style='color: #fff; background: #5cb85c; padding: 10px; border-radius: 5px;'>%s</p>", buf);
        return out;
    }
    return strdup("");
}

static char* web_render_vault(LoggedInUser* session, const char* csrf_token, const char* search_query) {
    char uid_str[16]; snprintf(uid_str, sizeof(uid_str), "%d", session->user_id);
    PGresult* res = NULL;
    
    if (search_query && strlen(search_query) > 0) {
        char search_pattern[512];
        snprintf(search_pattern, sizeof(search_pattern), "%%%s%%", search_query);
        
        const char* params[2] = { uid_str, search_pattern };
        res = PQexecParams(db_get_conn(),
            "SELECT id, site, username, encrypted_password, iv, tag FROM vault_entries "
            "WHERE user_id = $1 AND (site ILIKE $2 OR username ILIKE $2) ORDER BY site ASC",
            2, NULL, params, NULL, NULL, 1);
    } else {
        const char* params[1] = { uid_str };
        res = PQexecParams(db_get_conn(),
            "SELECT id, site, username, encrypted_password, iv, tag FROM vault_entries "
            "WHERE user_id = $1 ORDER BY site ASC",
            1, NULL, params, NULL, NULL, 1);
    }
        
    char rows_html[16384] = {0};
    int offset = 0;
    
    if (PQntuples(res) == 0) {
        offset += snprintf(rows_html, sizeof(rows_html), "<tr><td colspan='4'>No entries found.</td></tr>");
    }
    
    for (int i = 0; i < PQntuples(res); i++) {
        int id = ntohl(*(uint32_t*)PQgetvalue(res, i, 0));
        char site[256]={0}, user[256]={0};
        
        int slen = PQgetlength(res, i, 1); if (slen > 255) slen = 255;
        int ulen = PQgetlength(res, i, 2); if (ulen > 255) ulen = 255;
        memcpy(site, PQgetvalue(res, i, 1), slen); site[slen] = '\0';
        memcpy(user, PQgetvalue(res, i, 2), ulen); user[ulen] = '\0';
        
        int ct_len = PQgetlength(res, i, 3);
        uint8_t* ct = (uint8_t*)PQgetvalue(res, i, 3);
        uint8_t* iv = (uint8_t*)PQgetvalue(res, i, 4);
        uint8_t* tag = (uint8_t*)PQgetvalue(res, i, 5);
        
        uint8_t pt[256] = {0};
        if (ct_len < 256 && crypto_aead_decrypt(ct, ct_len, tag, session->derived_key, iv, pt)) {
            offset += snprintf(rows_html + offset, sizeof(rows_html) - offset,
                "<tr><td><strong>%s</strong></td><td>%s</td><td>********</td>"
                "<td><a href='/vault/edit?id=%d' style='margin-right:10px;'>Edit</a>"
                "<form action='/vault/delete' method='POST' style='display:inline;'>"
                "<input type='hidden' name='csrf_token' value='%s'>"
                "<input type='hidden' name='entry_id' value='%d'>"
                "<button type='submit' style='background: #d9534f; border:none;'>Delete</button></form></td></tr>", 
                site, user, id, csrf_token, id);
        } else {
            offset += snprintf(rows_html + offset, sizeof(rows_html) - offset,
                "<tr><td><strong>%s</strong></td><td>%s</td><td><em>[Decryption Error]</em></td>"
                "<td><form action='/vault/delete' method='POST' style='display:inline;'>"
                "<input type='hidden' name='csrf_token' value='%s'>"
                "<input type='hidden' name='entry_id' value='%d'>"
                "<button type='submit' style='background: #d9534f; border:none;'>Delete</button></form></td></tr>", 
                site, user, csrf_token, id);
        }
        OPENSSL_cleanse(pt, sizeof(pt));
    }
    PQclear(res);
    return strdup(rows_html);
}

static bool is_route(struct mg_http_message *hm, const char *path) {
    size_t len = strlen(path);
    return hm->uri.len == len && memcmp(hm->uri.buf, path, len) == 0;
}

static bool is_post(struct mg_http_message *hm) {
    return hm->method == MG_HTTP_POST;
}

static void log_request(struct mg_http_message *hm) {
    char uri_str[256] = {0};
    size_t ulen = hm->uri.len < 255 ? hm->uri.len : 255;
    memcpy(uri_str, hm->uri.buf, ulen);
    printf("\n[HTTP] %s %s\n", is_post(hm) ? "POST" : "GET", uri_str);
}

static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_ACCEPT) {
        struct mg_tls_opts opts; memset(&opts, 0, sizeof(opts)); 
        opts.cert = s_cert; opts.key = s_key;
        mg_tls_init(c, &opts);
    }
    else if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        char session_cookie[65] = {0}, session_csrf[65] = {0};
        LoggedInUser session = {0};
        
        log_request(hm);
        session_extract_cookie(hm, session_cookie, sizeof(session_cookie));
        bool is_authed = session_validate(session_cookie, &session, session_csrf);

        char headers[512];
        snprintf(headers, sizeof(headers), "%sContent-Type: text/html\r\n", SEC_HEADERS);

        if (is_route(hm, "/") || is_route(hm, "/login")) {
            if (is_post(hm)) {
                char user[256]={0}, pass[256]={0};
                mg_http_get_var(&hm->body, "username", user, sizeof(user));
                mg_http_get_var(&hm->body, "password", pass, sizeof(pass));
                
                LoggedInUser tmp_sess = {0};
                if (auth_login(user, pass, &tmp_sess)) {
                    char token[65], csrf[65];
                    if (session_create(tmp_sess.user_id, tmp_sess.derived_key, token, csrf)) {
                        char out_hdrs[512];
                        snprintf(out_hdrs, sizeof(out_hdrs), 
                            "%sLocation: /vault?msg=Login+successful\r\n"
                            "Set-Cookie: session_id=%s; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600\r\n", 
                            SEC_HEADERS, token);
                        mg_http_reply(c, 302, out_hdrs, "");
                    } else {
                        mg_http_reply(c, 302, "Location: /login?err=Server+Error\r\n", "");
                    }
                    OPENSSL_cleanse(tmp_sess.derived_key, AES_KEY_SIZE);
                } else {
                    mg_http_reply(c, 302, "Location: /login?err=Invalid+Username+or+Password\r\n", "");
                }
                OPENSSL_cleanse(pass, sizeof(pass));
            } else {
                if (is_authed) { mg_http_reply(c, 302, "Location: /vault\r\n", ""); return; }
                char* html = read_file("assets/login.html");
                char* flash = get_flash_message(hm);
                char* final = render_template(html, "{{MESSAGE}}", flash);
                mg_http_reply(c, 200, headers, "%s", final ? final : "File missing");
                free(html); free(flash); free(final);
            }
        }
        else if (is_route(hm, "/register")) {
            if (is_post(hm)) {
                char user[256]={0}, pass[256]={0};
                mg_http_get_var(&hm->body, "username", user, sizeof(user));
                mg_http_get_var(&hm->body, "password", pass, sizeof(pass));
                if (auth_register(user, pass)) {
                    mg_http_reply(c, 302, "Location: /login?msg=Registration+successful.+Please+log+in.\r\n", "");
                } else {
                    mg_http_reply(c, 302, "Location: /register?err=Registration+failed.+Username+may+be+taken.\r\n", "");
                }
                OPENSSL_cleanse(pass, sizeof(pass));
            } else {
                char* html = read_file("assets/register.html");
                char* flash = get_flash_message(hm);
                char* final = render_template(html, "{{MESSAGE}}", flash);
                mg_http_reply(c, 200, headers, "%s", final ? final : "File missing");
                free(html); free(flash); free(final);
            }
        }
        else if (is_route(hm, "/vault")) {
            if (!is_authed) { mg_http_reply(c, 302, "Location: /login?err=Please+log+in\r\n", ""); return; }
            
            char search_query[256] = {0};
            mg_http_get_var(&hm->query, "q", search_query, sizeof(search_query));
            
            char* html = read_file("assets/vault.html");
            char* flash = get_flash_message(hm);
            char* rows = web_render_vault(&session, session_csrf, search_query);
            
            char* t1 = render_template(html, "{{MESSAGE}}", flash);
            char* t2 = render_template(t1, "{{VAULT_ENTRIES}}", rows);
            char* final = render_template(t2, "{{CSRF_TOKEN}}", session_csrf);
            
            mg_http_reply(c, 200, headers, "%s", final ? final : "File missing");
            free(html); free(flash); free(rows); free(t1); free(t2); free(final);
        }
        else if (is_route(hm, "/vault/add")) {
            if (!is_authed) { mg_http_reply(c, 302, "Location: /login\r\n", ""); return; }
            if (is_post(hm)) {
                char site[256]={0}, user[256]={0}, pass[256]={0}, csrf[65]={0};
                mg_http_get_var(&hm->body, "site", site, sizeof(site));
                mg_http_get_var(&hm->body, "site_user", user, sizeof(user));
                mg_http_get_var(&hm->body, "site_pass", pass, sizeof(pass));
                mg_http_get_var(&hm->body, "csrf_token", csrf, sizeof(csrf));
                
                if (csrf_validate(session_csrf, csrf)) {
                    if (vault_add(&session, site, user, pass)) {
                        mg_http_reply(c, 302, "Location: /vault?msg=Entry+added+successfully\r\n", "");
                    } else {
                        mg_http_reply(c, 302, "Location: /vault/add?err=Failed+to+save+entry\r\n", "");
                    }
                } else {
                    mg_http_reply(c, 302, "Location: /vault/add?err=Security+Validation+Failed+(CSRF)\r\n", "");
                }
                OPENSSL_cleanse(pass, sizeof(pass));
            } else {
                char* html = read_file("assets/add_entry.html");
                char* flash = get_flash_message(hm);
                char* t1 = render_template(html, "{{MESSAGE}}", flash);
                char* final = render_template(t1, "{{CSRF_TOKEN}}", session_csrf);
                mg_http_reply(c, 200, headers, "%s", final ? final : "File missing");
                free(html); free(flash); free(t1); free(final);
            }
        }
        else if (is_route(hm, "/vault/edit")) {
            if (!is_authed) { mg_http_reply(c, 302, "Location: /login\r\n", ""); return; }
            if (is_post(hm)) {
                char id_str[16]={0}, site[256]={0}, user[256]={0}, pass[256]={0}, csrf[65]={0};
                mg_http_get_var(&hm->body, "entry_id", id_str, sizeof(id_str));
                mg_http_get_var(&hm->body, "site", site, sizeof(site));
                mg_http_get_var(&hm->body, "site_user", user, sizeof(user));
                mg_http_get_var(&hm->body, "site_pass", pass, sizeof(pass));
                mg_http_get_var(&hm->body, "csrf_token", csrf, sizeof(csrf));
                
                if (csrf_validate(session_csrf, csrf)) {
                    if (vault_update(&session, atoi(id_str), site, user, pass)) {
                        mg_http_reply(c, 302, "Location: /vault?msg=Entry+updated+successfully\r\n", "");
                    } else {
                        mg_http_reply(c, 302, "Location: /vault?err=Update+failed\r\n", "");
                    }
                } else {
                    mg_http_reply(c, 302, "Location: /vault?err=CSRF+Validation+Failed\r\n", "");
                }
                OPENSSL_cleanse(pass, sizeof(pass));
            } else {
                char id_str[16]={0};
                mg_http_get_var(&hm->query, "id", id_str, sizeof(id_str));
                char site[256]={0}, user[256]={0}, pass[256]={0};
                
                if (vault_get_entry(&session, atoi(id_str), site, user, pass)) {
                    char* html = read_file("assets/edit_entry.html");
                    char* flash = get_flash_message(hm);
                    char *t0 = render_template(html, "{{MESSAGE}}", flash);
                    char *t1 = render_template(t0, "{{ID}}", id_str);
                    char *t2 = render_template(t1, "{{SITE}}", site);
                    char *t3 = render_template(t2, "{{USER}}", user);
                    char *t4 = render_template(t3, "{{PASS}}", pass);
                    char *final = render_template(t4, "{{CSRF_TOKEN}}", session_csrf);
                    mg_http_reply(c, 200, headers, "%s", final ? final : "File missing");
                    free(html); free(flash); free(t0); free(t1); free(t2); free(t3); free(t4); free(final);
                } else {
                    mg_http_reply(c, 302, "Location: /vault?err=Entry+not+found\r\n", "");
                }
                OPENSSL_cleanse(pass, sizeof(pass));
            }
        }
        else if (is_route(hm, "/vault/delete")) {
            if (!is_authed) { mg_http_reply(c, 302, "Location: /login\r\n", ""); return; }
            if (is_post(hm)) {
                char id_str[16]={0}, csrf[65]={0};
                mg_http_get_var(&hm->body, "entry_id", id_str, sizeof(id_str));
                mg_http_get_var(&hm->body, "csrf_token", csrf, sizeof(csrf));
                if (csrf_validate(session_csrf, csrf)) {
                    vault_delete(&session, atoi(id_str));
                    mg_http_reply(c, 302, "Location: /vault?msg=Entry+deleted\r\n", "");
                } else {
                    mg_http_reply(c, 302, "Location: /vault?err=CSRF+Validation+Failed\r\n", "");
                }
            } else {
                mg_http_reply(c, 302, "Location: /vault\r\n", "");
            }
        }
        else if (is_route(hm, "/api/generate")) {
            if (!is_authed) { mg_http_reply(c, 401, "", "Unauthorized"); return; }
            char secure_pass[21]; 
            crypto_generate_password(secure_pass, sizeof(secure_pass));
            mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "%s", secure_pass);
            OPENSSL_cleanse(secure_pass, sizeof(secure_pass));
        }
        else if (is_route(hm, "/logout")) {
            session_destroy(session_cookie);
            char out_hdrs[512];
            snprintf(out_hdrs, sizeof(out_hdrs), 
                "%s"
                "Location: /login?msg=You+have+been+logged+out.\r\n"
                "Set-Cookie: session_id=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0\r\n", SEC_HEADERS);
            mg_http_reply(c, 302, out_hdrs, "");
        }
        else {
            mg_http_reply(c, 404, headers, "Not Found");
        }
        
        if (is_authed) OPENSSL_cleanse(session.derived_key, AES_KEY_SIZE);
    }
}

int main(void) {
    char* cert_data = read_file("cert.pem");
    char* key_data = read_file("key.pem");
    if (!cert_data || !key_data) {
        printf("[ERROR] cert.pem or key.pem not found. Run the openssl command first!\n");
        return 1;
    }
    
    s_cert.buf = cert_data;
    s_cert.len = strlen(cert_data);
    s_key.buf = key_data;
    s_key.len = strlen(key_data);

    if (!db_init("dbname=securevault_db user=vault_user password=vault_password host=localhost")) return 1;

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, "https://0.0.0.0:8443", ev_handler, NULL);
    printf("SecureVault Web started on https://127.0.0.1:8443\n");

    for (;;) mg_mgr_poll(&mgr, 1000);

    mg_mgr_free(&mgr);
    db_close();
    free(cert_data);
    free(key_data);
    return 0;
}