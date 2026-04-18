#include "securevault.h"

bool vault_add(LoggedInUser* session, const char* site, const char* username, const char* password) {
    uint8_t iv[GCM_IV_SIZE];
    uint8_t tag[GCM_TAG_SIZE];
    uint8_t ct[256] = {0};
    
    size_t pass_len = strlen(password);
    if (pass_len >= sizeof(ct)) {
        printf("[VAULT ERR] Password too long.\n");
        return false;
    }
    
    if (!crypto_random_bytes(iv, GCM_IV_SIZE)) return false;
    
    if (!crypto_aead_encrypt((uint8_t*)password, pass_len, session->derived_key, iv, ct, tag)) {
        printf("[VAULT ERR] AES-GCM encryption failed.\n");
        return false;
    }
    
    char uid_str[16];
    snprintf(uid_str, sizeof(uid_str), "%d", session->user_id);
    
    const char* params[6] = { uid_str, site, username, (char*)ct, (char*)iv, (char*)tag };
    int lengths[6] = { 0, 0, 0, (int)pass_len, GCM_IV_SIZE, GCM_TAG_SIZE };
    int formats[6] = { 0, 0, 0, 1, 1, 1 };
    
    PGresult* res = PQexecParams(db_get_conn(),
        "INSERT INTO vault_entries (user_id, site, username, encrypted_password, iv, tag) "
        "VALUES ($1, $2, $3, $4, $5, $6)",
        6, NULL, params, lengths, formats, 0);
        
    bool success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    if (success) {
        printf("[VAULT LOG] Successfully added entry for %s.\n", site);
    } else {
        printf("[VAULT ERR] DB Insert Failed: %s\n", PQerrorMessage(db_get_conn()));
    }
    
    PQclear(res);
    OPENSSL_cleanse(ct, sizeof(ct));
    return success;
}

void vault_view(LoggedInUser* session) {
    char uid_str[16];
    snprintf(uid_str, sizeof(uid_str), "%d", session->user_id);
    
    const char* params[1] = { uid_str };
    PGresult* res = PQexecParams(db_get_conn(),
        "SELECT id, site, username, encrypted_password, iv, tag FROM vault_entries WHERE user_id = $1",
        1, NULL, params, NULL, NULL, 1);
        
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("[VAULT ERR] Failed to fetch entries: %s\n", PQerrorMessage(db_get_conn()));
        PQclear(res);
        return;
    }
    
    int rows = PQntuples(res);
    printf("\n--- YOUR VAULT (%d entries) ---\n", rows);
    printf("%-5s | %-20s | %-20s | %-20s\n", "ID", "Site", "Username", "Password");
    printf("----------------------------------------------------------------------\n");
    
    for (int i = 0; i < rows; i++) {
        int id = ntohl(*(uint32_t*)PQgetvalue(res, i, 0));
        
        char site[256] = {0}, user[256] = {0};
        int site_len = PQgetlength(res, i, 1);
        int user_len = PQgetlength(res, i, 2);
        if (site_len >= 256) site_len = 255;
        if (user_len >= 256) user_len = 255;
        memcpy(site, PQgetvalue(res, i, 1), site_len);
        memcpy(user, PQgetvalue(res, i, 2), user_len);
        
        uint8_t* ct = (uint8_t*)PQgetvalue(res, i, 3);
        uint8_t* iv = (uint8_t*)PQgetvalue(res, i, 4);
        uint8_t* tag = (uint8_t*)PQgetvalue(res, i, 5);
        int ct_len = PQgetlength(res, i, 3);
        
        uint8_t pt[256] = {0};
        if (crypto_aead_decrypt(ct, ct_len, tag, session->derived_key, iv, pt)) {
            printf("%-5d | %-20s | %-20s | %-20s\n", id, site, user, (char*)pt);
        } else {
            printf("%-5d | %-20s | %-20s |[DECRYPT ERROR]\n", id, site, user);
        }
        OPENSSL_cleanse(pt, sizeof(pt));
    }
    printf("----------------------------------------------------------------------\n\n");
    PQclear(res);
}

bool vault_delete(LoggedInUser* session, int entry_id) {
    char uid_str[16], entry_str[16];
    snprintf(uid_str, sizeof(uid_str), "%d", session->user_id);
    snprintf(entry_str, sizeof(entry_str), "%d", entry_id);
    
    const char* params[2] = { entry_str, uid_str };
    PGresult* res = PQexecParams(db_get_conn(),
        "DELETE FROM vault_entries WHERE id = $1 AND user_id = $2",
        2, NULL, params, NULL, NULL, 0);
        
    int affected = atoi(PQcmdTuples(res));
    bool success = (PQresultStatus(res) == PGRES_COMMAND_OK && affected > 0);
    
    if (success) {
        printf("[VAULT LOG] Entry %d deleted successfully.\n", entry_id);
    } else {
        printf("[VAULT ERR] Could not delete entry %d (does not exist or not owned by you).\n", entry_id);
    }
    
    PQclear(res);
    return success;
}

bool vault_get_entry(LoggedInUser* session, int entry_id, char* site, char* username, char* password) {
    char uid_str[16], id_str[16];
    snprintf(uid_str, sizeof(uid_str), "%d", session->user_id);
    snprintf(id_str, sizeof(id_str), "%d", entry_id);
    
    const char* params[2] = { id_str, uid_str };
    PGresult* res = PQexecParams(db_get_conn(),
        "SELECT site, username, encrypted_password, iv, tag FROM vault_entries WHERE id = $1 AND user_id = $2",
        2, NULL, params, NULL, NULL, 1);
        
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
        PQclear(res);
        return false;
    }
    
    int slen = PQgetlength(res, 0, 0); if (slen > 255) slen = 255;
    int ulen = PQgetlength(res, 0, 1); if (ulen > 255) ulen = 255;
    memcpy(site, PQgetvalue(res, 0, 0), (size_t)slen); site[slen] = '\0';
    memcpy(username, PQgetvalue(res, 0, 1), (size_t)ulen); username[ulen] = '\0';
    
    uint8_t* ct = (uint8_t*)PQgetvalue(res, 0, 2);
    uint8_t* iv = (uint8_t*)PQgetvalue(res, 0, 3);
    uint8_t* tag = (uint8_t*)PQgetvalue(res, 0, 4);
    int ct_len = PQgetlength(res, 0, 2);
    
    if (ct_len >= 256 || !crypto_aead_decrypt(ct, (size_t)ct_len, tag, session->derived_key, iv, (uint8_t*)password)) {
        strcpy(password, "DECRYPTION_ERROR");
    }
    
    PQclear(res);
    return true;
}

bool vault_update(LoggedInUser* session, int entry_id, const char* site, const char* username, const char* password) {
    uint8_t iv[GCM_IV_SIZE], tag[GCM_TAG_SIZE], ct[256] = {0};
    size_t pass_len = strlen(password);
    
    if (pass_len >= sizeof(ct) || !crypto_random_bytes(iv, GCM_IV_SIZE)) return false;
    if (!crypto_aead_encrypt((uint8_t*)password, pass_len, session->derived_key, iv, ct, tag)) return false;
    
    char uid_str[16], id_str[16];
    snprintf(uid_str, sizeof(uid_str), "%d", session->user_id);
    snprintf(id_str, sizeof(id_str), "%d", entry_id);
    
    const char* params[7] = { site, username, (char*)ct, (char*)iv, (char*)tag, id_str, uid_str };
    int lengths[7] = { (int)strlen(site), (int)strlen(username), (int)pass_len, GCM_IV_SIZE, GCM_TAG_SIZE, 0, 0 };
    int formats[7] = { 0, 0, 1, 1, 1, 0, 0 }; 
    
    PGresult* res = PQexecParams(db_get_conn(),
        "UPDATE vault_entries SET site=$1, username=$2, encrypted_password=$3, iv=$4, tag=$5 "
        "WHERE id=$6 AND user_id=$7",
        7, NULL, params, lengths, formats, 0);
        
    int affected = atoi(PQcmdTuples(res));
    bool success = (PQresultStatus(res) == PGRES_COMMAND_OK && affected > 0);
    
    if (!success) {
        printf("[VAULT ERR] Update failed for Entry %d. Rows affected: %d. Error: %s\n", entry_id, affected, PQerrorMessage(db_get_conn()));
    } else {
        printf("[VAULT LOG] Successfully updated Entry %d\n", entry_id);
    }
    
    PQclear(res);
    OPENSSL_cleanse(ct, sizeof(ct)); 
    return success;
}
