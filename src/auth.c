#include "securevault.h"

static const char* DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$xU5z8m29bQY2X1xQG5dY8A$3c1s+L9KxXGkF7zY/9x3KxQZkF7zY/9x3KxQZkF7zY8";

bool auth_register(const char* username, const char* password) {
    if (strlen(username) == 0 || strlen(username) >= MAX_INPUT_LEN) {
        printf("[AUTH ERR] Invalid username length.\n");
        return false;
    }
    if (strlen(password) < MIN_PASS_LEN || strlen(password) >= MAX_INPUT_LEN) {
        printf("[AUTH ERR] Password must be between %d and %d characters.\n", MIN_PASS_LEN, MAX_INPUT_LEN);
        return false;
    }

    printf("[AUTH LOG] Attempting to register user...\n");
    
    char hash[128] = {0};
    uint8_t salt[SALT_SIZE];
    
    if (!crypto_random_bytes(salt, SALT_SIZE)) return false;
    if (!crypto_hash_password(password, hash, sizeof(hash))) return false;
    
    const char* params[3] = { username, hash, (char*)salt };
    int lengths[3] = { 0, 0, SALT_SIZE }; 
    int formats[3] = { 0, 0, 1 };         
    
    PGresult* res = PQexecParams(db_get_conn(),
        "INSERT INTO users (username, password_hash, salt) VALUES ($1, $2, $3)",
        3, NULL, params, lengths, formats, 0);
        
    bool success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    if (success) printf("[AUTH LOG] User registered successfully.\n");
    else printf("[AUTH ERR] DB Insert Failed. User may already exist.\n");
    
    PQclear(res);
    OPENSSL_cleanse(hash, sizeof(hash));
    return success;
}

bool auth_login(const char* username, const char* password, LoggedInUser* session) {
    printf("[AUTH LOG] Attempting login...\n");
    
    const char* params[1] = { username };
    PGresult* res = PQexecParams(db_get_conn(),
        "SELECT id, password_hash, salt FROM users WHERE username = $1",
        1, NULL, params, NULL, NULL, 1); 
        
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
        crypto_verify_password(password, DUMMY_HASH);
        printf("[AUTH ERR] Invalid username or password.\n");
        PQclear(res);
        return false;
    }
    
    int user_id = ntohl(*(uint32_t*)PQgetvalue(res, 0, 0));
    
    int hash_len = PQgetlength(res, 0, 1);
    char hash_buf[256] = {0};
    if (hash_len >= (int)sizeof(hash_buf)) hash_len = sizeof(hash_buf) - 1;
    memcpy(hash_buf, PQgetvalue(res, 0, 1), hash_len);
    hash_buf[hash_len] = '\0';
    
    uint8_t* salt = (uint8_t*)PQgetvalue(res, 0, 2);
    
    bool valid = crypto_verify_password(password, hash_buf);
    OPENSSL_cleanse(hash_buf, sizeof(hash_buf));
    
    if (valid) {
        session->user_id = user_id;
        strncpy(session->username, username, sizeof(session->username) - 1);
        crypto_derive_key(password, salt, SALT_SIZE, session->derived_key);
        session->active = true;
        
        PQclear(res);
        printf("[AUTH LOG] Login successful.\n");
        return true;
    }
    
    printf("[AUTH ERR] Invalid username or password.\n");
    PQclear(res);
    return false;
}

void auth_logout(LoggedInUser* session) {
    if (session->active) {
        OPENSSL_cleanse(session->derived_key, AES_KEY_SIZE);
        session->active = false;
        session->user_id = 0;
        memset(session->username, 0, sizeof(session->username));
        printf("[AUTH LOG] Logged out successfully. Memory wiped.\n");
    }
}
