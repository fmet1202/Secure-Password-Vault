#include "securevault.h"
#include "mongoose.h"

static void bin_to_hex(const uint8_t* bin, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) snprintf(hex + (i * 2), 3, "%02x", bin[i]);
}

bool session_create(int user_id, const uint8_t* derived_key, char* out_token, char* out_csrf) {
    uint8_t tok_bin[32], csrf_bin[32];
    if (!crypto_random_bytes(tok_bin, 32) || !crypto_random_bytes(csrf_bin, 32)) return false;
    
    bin_to_hex(tok_bin, 32, out_token);
    bin_to_hex(csrf_bin, 32, out_csrf);
    
    char uid_str[16];
    snprintf(uid_str, sizeof(uid_str), "%d", user_id);
    
    const char* params[4] = { out_token, uid_str, (char*)derived_key, out_csrf };
    int lengths[4] = { 64, (int)strlen(uid_str), AES_KEY_SIZE, 64 };
    int formats[4] = { 0, 0, 1, 0 };
    
    PGresult* res = PQexecParams(db_get_conn(),
        "INSERT INTO sessions (session_token, user_id, derived_key, csrf_token, expires_at) "
        "VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour')",
        4, NULL, params, lengths, formats, 0);
        
    bool success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    return success;
}

bool session_validate(const char* token, LoggedInUser* out_session, char* out_csrf) {
    if (!token || strlen(token) != 64) return false;
    
    const char* params[1] = { token };
    PGresult* res = PQexecParams(db_get_conn(),
        "SELECT user_id, derived_key, csrf_token FROM sessions "
        "WHERE session_token = $1 AND expires_at > NOW()",
        1, NULL, params, NULL, NULL, 1);
        
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
        out_session->user_id = ntohl(*(uint32_t*)PQgetvalue(res, 0, 0));
        memcpy(out_session->derived_key, PQgetvalue(res, 0, 1), AES_KEY_SIZE);
        out_session->active = true;
        
        int csrf_len = PQgetlength(res, 0, 2);
        if (csrf_len == 64) {
            memcpy(out_csrf, PQgetvalue(res, 0, 2), 64);
            out_csrf[64] = '\0';
        }
        PQclear(res);
        return true;
    }
    PQclear(res);
    return false;
}

void session_destroy(const char* token) {
    if (!token || strlen(token) != 64) return;
    const char* params[1] = { token };
    PGresult* res = PQexecParams(db_get_conn(), "DELETE FROM sessions WHERE session_token = $1", 1, NULL, params, NULL, NULL, 0);
    PQclear(res);
}

void session_extract_cookie(struct mg_http_message* hm, char* token_out, size_t max_len) {
    token_out[0] = '\0';
    struct mg_str *cookie = mg_http_get_header(&hm->body, "Cookie");
    if (cookie != NULL) {
        const char *p = strstr(cookie->buf, "session_id=");
        if (p && p < cookie->buf + cookie->len) {
            p += 11;
            size_t i = 0;
            while (p < cookie->buf + cookie->len && *p != ';' && i < max_len - 1) {
                token_out[i++] = *p++;
            }
            token_out[i] = '\0';
        }
    }
}
