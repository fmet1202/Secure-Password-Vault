#include "securevault.h"

bool crypto_random_bytes(uint8_t* buf, size_t len) {
    return RAND_bytes(buf, len) == 1;
}

bool crypto_hash_password(const char* pwd, char* encoded_hash, size_t out_len) {
    uint8_t salt[SALT_SIZE];
    if (!crypto_random_bytes(salt, sizeof(salt))) return false;
    
    int res = argon2id_hash_encoded(ARGON2_T, ARGON2_M, ARGON2_P, pwd, strlen(pwd), salt, sizeof(salt), 32, encoded_hash, out_len);
    return res == ARGON2_OK;
}

bool crypto_verify_password(const char* pwd, const char* encoded_hash) {
    return argon2id_verify(encoded_hash, pwd, strlen(pwd)) == ARGON2_OK;
}

bool crypto_derive_key(const char* pwd, const uint8_t* salt, size_t salt_len, uint8_t* key_out) {
    int res = PKCS5_PBKDF2_HMAC(pwd, strlen(pwd), salt, salt_len, PBKDF2_ITERATIONS, EVP_sha256(), AES_KEY_SIZE, key_out);
    return res == 1;
}

bool crypto_aead_encrypt(const unsigned char* pt, size_t pt_len, const unsigned char* key, const unsigned char* iv, unsigned char* ct, unsigned char* tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ciphertext_len = 0;
    if (!ctx) return false;
    
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) goto err;
    if (1 != EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len)) goto err;
    ciphertext_len = len;
    
    if (1 != EVP_EncryptFinal_ex(ctx, ct + len, &len)) goto err;
    ciphertext_len += len;
    
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag)) goto err;
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

bool crypto_aead_decrypt(const unsigned char* ct, size_t ct_len, const unsigned char* tag, const unsigned char* key, const unsigned char* iv, unsigned char* pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plaintext_len = 0, ret = 0;
    if (!ctx) return false;
    
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) goto err;
    if (1 != EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len)) goto err;
    plaintext_len = len;
    
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag)) goto err;
    
    ret = EVP_DecryptFinal_ex(ctx, pt + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret > 0) {
        plaintext_len += len;
        pt[plaintext_len] = '\0'; 
        return true;
    }
    
    OPENSSL_cleanse(pt, ct_len);
    return false;
err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

void crypto_generate_password(char* buffer, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    uint8_t rand_bytes[length];
    
    if (!crypto_random_bytes(rand_bytes, length)) {
        strcpy(buffer, "ErrorGenerating!");
        return;
    }
    
    for(size_t i = 0; i < length - 1; i++) {
        buffer[i] = charset[rand_bytes[i] % (sizeof(charset) - 1)];
    }
    buffer[length - 1] = '\0';
}
