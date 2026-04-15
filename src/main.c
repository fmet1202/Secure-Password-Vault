#include "mongoose.h"
#include "securevault.h"

#define SEC_HEADERS "Content-Security-Policy: default-src 'self'\r\n" \
                    "X-Frame-Options: DENY\r\n" \
                    "X-Content-Type-Options: nosniff\r\n" \
                    "Cache-Control: no-store, max-age=0\r\n"

static char* read_file(const char* filepath) {
    FILE* f = fopen(filepath, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* buf = calloc(1, (size_t)length + 1);
    if (buf) fread(buf, 1, (size_t)length, f);
    fclose(f);
    return buf;
}

static char* render_template(const char* tmpl, const char* key, const char* val) {
    const char* pos = strstr(tmpl, key);
    if (!pos) return strdup(tmpl);
    
    size_t pre_len = (size_t)(pos - tmpl);
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

static char* web_render_vault(LoggedInUser* session, const char* csrf_token) {
    char uid_str[16];
    snprintf(uid_str, sizeof(uid_str), "%d", session->user_id);
    const char* params[1] = { uid_str };
    PGresult* res = PQexecParams(db_get_conn(),
        "SELECT id, site, username, encrypted_password, iv, tag FROM vault_entries WHERE user_id = $1",
        1, NULL, params, NULL, NULL, 1);
        
    char rows_html[16384] = {0};
    int offset = 0;
    
    for (int i = 0; i < PQntuples(res); i++) {
        int id = ntohl(*(uint32_t*)PQgetvalue(res, i, 0));
        char site[256]={0}, user[256]={0};
        
        int slen = PQgetlength(res, i, 1); if (slen > 255) slen = 255;
        int ulen = PQgetlength(res, i, 2); if (ulen > 255) ulen = 255;
        memcpy(site, PQgetvalue(res, i, 1), (size_t)slen);
        memcpy(user, PQgetvalue(res, i, 2), (size_t)ulen);
        
        int ct_len = PQgetlength(res, i, 3);
        uint8_t* ct = (uint8_t*)PQgetvalue(res, i, 3);
        uint8_t* iv = (uint8_t*)PQgetvalue(res, i, 4);
        uint8_t* tag = (uint8_t*)PQgetvalue(res, i, 5);
        
        uint8_t pt[256] = {0};
        if (ct_len < 256 && crypto_aead_decrypt(ct, (size_t)ct_len, tag, session->derived_key, iv, pt)) {
            offset += snprintf(rows_html + offset, sizeof(rows_html) - offset,
                "<tr><td>%s</td><td>%s</td><td>%s</td>"
                "<td><form action='/vault/delete' method='POST' style='margin:0;'>"
                "<input type='hidden' name='csrf_token' value='%s'>"
                "<input type='hidden' name='entry_id' value='%d'>"
                "<button type='submit'>Delete</button></form></td></tr>", 
                site, user, pt, csrf_token, id);
        }
        OPENSSL_cleanse(pt, sizeof(pt));
    }
    PQclear(res);
    return strdup(rows_html);
}

static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        
        char session_cookie[65] = {0};
        char session_csrf[65] = {0};
        LoggedInUser session = {0};
        
        session_extract_cookie(hm, session_cookie, sizeof(session_cookie));
        bool is_authed = session_validate(session_cookie, &session, session_csrf);

        char headers[512];
        snprintf(headers, sizeof(headers), "%sContent-Type: text/html\r\n", SEC_HEADERS);

        if (mg_match(hm->uri, mg_str("/"), NULL) || mg_match(hm->uri, mg_str("/login"), NULL)) {
            if (hm->method == MG_HTTP_POST) {
                char user[256]={0}, pass[256]={0};
                mg_http_get_var(&hm->body, "username", user, sizeof(user));
                mg_http_get_var(&hm->body, "password", pass, sizeof(pass));
                
                LoggedInUser tmp_sess = {0};
                if (auth_login(user, pass, &tmp_sess)) {
                    char token[65], csrf[65];
                    if (session_create(tmp_sess.user_id, tmp_sess.derived_key, token, csrf)) {
                        char out_hdrs[512];
                        snprintf(out_hdrs, sizeof(out_hdrs), 
                            "Location: /vault\r\nSet-Cookie: session_id=%s; HttpOnly; SameSite=Strict; Path=/\r\n", token);
                        mg_http_reply(c, 302, out_hdrs, "");
                    } else {
                        mg_http_reply(c, 500, headers, "Session Error");
                    }
                    OPENSSL_cleanse(tmp_sess.derived_key, AES_KEY_SIZE);
                } else {
                    mg_http_reply(c, 401, headers, "Invalid credentials");
                }
                OPENSSL_cleanse(pass, sizeof(pass));
            } else {
                char* html = read_file("assets/login.html");
                mg_http_reply(c, 200, headers, "%s", html ? html : "File missing");
                free(html);
            }
        }
        else if (mg_match(hm->uri, mg_str("/register"), NULL)) {
            if (hm->method == MG_HTTP_POST) {
                char user[256]={0}, pass[256]={0};
                mg_http_get_var(&hm->body, "username", user, sizeof(user));
                mg_http_get_var(&hm->body, "password", pass, sizeof(pass));
                if (auth_register(user, pass)) {
                    mg_http_reply(c, 302, "Location: /login\r\n", "");
                } else {
                    mg_http_reply(c, 400, headers, "Registration failed");
                }
                OPENSSL_cleanse(pass, sizeof(pass));
            } else {
                char* html = read_file("assets/register.html");
                mg_http_reply(c, 200, headers, "%s", html ? html : "File missing");
                free(html);
            }
        }
        else if (mg_match(hm->uri, mg_str("/vault"), NULL)) {
            if (!is_authed) { mg_http_reply(c, 302, "Location: /login\r\n", ""); return; }
            
            char* html = read_file("assets/vault.html");
            char* rows = web_render_vault(&session, session_csrf);
            char* final1 = render_template(html, "{{VAULT_ENTRIES}}", rows);
            char* final_html = render_template(final1, "{{CSRF_TOKEN}}", session_csrf);
            
            mg_http_reply(c, 200, headers, "%s", final_html);
            free(html); free(rows); free(final1); free(final_html);
        }
        else if (mg_match(hm->uri, mg_str("/vault/add"), NULL)) {
            if (!is_authed) { mg_http_reply(c, 302, "Location: /login\r\n", ""); return; }
            
            if (hm->method == MG_HTTP_POST) {
                char site[256]={0}, user[256]={0}, pass[256]={0}, csrf[65]={0};
                mg_http_get_var(&hm->body, "site", site, sizeof(site));
                mg_http_get_var(&hm->body, "site_user", user, sizeof(user));
                mg_http_get_var(&hm->body, "site_pass", pass, sizeof(pass));
                mg_http_get_var(&hm->body, "csrf_token", csrf, sizeof(csrf));
                
                if (csrf_validate(session_csrf, csrf)) {
                    vault_add(&session, site, user, pass);
                    mg_http_reply(c, 302, "Location: /vault\r\n", "");
                } else {
                    mg_http_reply(c, 403, headers, "CSRF Failed");
                }
                OPENSSL_cleanse(pass, sizeof(pass));
            } else {
                char* html = read_file("assets/add_entry.html");
                char* final_html = render_template(html, "{{CSRF_TOKEN}}", session_csrf);
                mg_http_reply(c, 200, headers, "%s", final_html);
                free(html); free(final_html);
            }
        }
        else if (mg_match(hm->uri, mg_str("/vault/delete"), NULL)) {
            if (!is_authed) { mg_http_reply(c, 302, "Location: /login\r\n", ""); return; }
            if (hm->method == MG_HTTP_POST) {
                char id_str[16]={0}, csrf[65]={0};
                mg_http_get_var(&hm->body, "entry_id", id_str, sizeof(id_str));
                mg_http_get_var(&hm->body, "csrf_token", csrf, sizeof(csrf));
                
                if (csrf_validate(session_csrf, csrf)) {
                    vault_delete(&session, atoi(id_str));
                }
            }
            mg_http_reply(c, 302, "Location: /vault\r\n", "");
        }
        else if (mg_match(hm->uri, mg_str("/logout"), NULL)) {
            session_destroy(session_cookie);
            mg_http_reply(c, 302, "Location: /login\r\nSet-Cookie: session_id=; Max-Age=0; Path=/\r\n", "");
        }
        else {
            mg_http_reply(c, 404, headers, "Not Found");
        }
        
        if (is_authed) OPENSSL_cleanse(session.derived_key, AES_KEY_SIZE);
    }
}

int main(void) {
    if (!db_init("dbname=securevault_db user=vault_user password=vault_password host=localhost")) return 1;

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, "http://0.0.0.0:8000", ev_handler, NULL);
    printf("SecureVault Web started on http://localhost:8000\n");

    for (;;) mg_mgr_poll(&mgr, 1000);

    mg_mgr_free(&mgr);
    db_close();
    return 0;
}
