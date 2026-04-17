#ifndef SECUREVAULT_H
#define SECUREVAULT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <argon2.h>

#define AES_KEY_SIZE 32
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16
#define SALT_SIZE 16
#define PBKDF2_ITERATIONS 600000

#define ARGON2_T 3
#define ARGON2_M 65536
#define ARGON2_P 4

#define MIN_PASS_LEN 8
#define MAX_INPUT_LEN 255

typedef struct {
    bool active;
    int user_id;
    char username[256];
    uint8_t derived_key[AES_KEY_SIZE];
} LoggedInUser;

extern LoggedInUser* g_current_session;

extern PGconn* g_db_conn;
bool db_init(const char* conninfo);
PGconn* db_get_conn(void);
void db_close(void);

bool crypto_random_bytes(uint8_t* buf, size_t len);
bool crypto_hash_password(const char* pwd, char* encoded_hash, size_t out_len);
bool crypto_verify_password(const char* pwd, const char* encoded_hash);
bool crypto_derive_key(const char* pwd, const uint8_t* salt, size_t salt_len, uint8_t* key_out);
bool crypto_aead_encrypt(const uint8_t* pt, size_t pt_len, const uint8_t* key, const uint8_t* iv, uint8_t* ct, uint8_t* tag);
bool crypto_aead_decrypt(const uint8_t* ct, size_t ct_len, const uint8_t* tag, const uint8_t* key, const uint8_t* iv, uint8_t* pt);

bool auth_register(const char* username, const char* password);
bool auth_login(const char* username, const char* password, LoggedInUser* session);
void auth_logout(LoggedInUser* session);

bool vault_add(LoggedInUser* session, const char* site, const char* username, const char* password);
void vault_view(LoggedInUser* session);
bool vault_delete(LoggedInUser* session, int entry_id);
bool vault_get_entry(LoggedInUser* session, int entry_id, char* site, char* username, char* password);
bool vault_update(LoggedInUser* session, int entry_id, const char* site, const char* username, const char* password);

void crypto_generate_password(char* buffer, size_t length);

struct mg_http_message;
bool session_create(int user_id, const uint8_t* derived_key, char* out_token, char* out_csrf);
bool session_validate(const char* token, LoggedInUser* out_session, char* out_csrf);
void session_destroy(const char* token);
void session_extract_cookie(struct mg_http_message* hm, char* token_out, size_t max_len);
bool csrf_validate(const char* expected, const char* provided);

#endif
