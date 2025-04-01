#include "crypto_windows.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stdlib.h>

// Initialize OpenSSL (call this once at program start)
bool emv_crypto_init() {
    OPENSSL_init_crypto(0, NULL);
    return true;
}

// RSA Key Functions
EMV_RSA_Key emv_rsa_create_key(const unsigned char* modulus, size_t mod_len,
                              const unsigned char* exponent, size_t exp_len) 
{
    EMV_RSA_Key key = { NULL, false };
    
    BIGNUM *n = BN_bin2bn(modulus, mod_len, NULL);
    BIGNUM *e = BN_bin2bn(exponent, exp_len, NULL);
    
    if (n && e) {
        RSA* rsa = RSA_new();
        if (rsa && RSA_set0_key(rsa, n, e, NULL)) {
            EVP_PKEY* pkey = EVP_PKEY_new();
            if (pkey && EVP_PKEY_assign_RSA(pkey, rsa)) {
                key.openssl_key = pkey;
                return key;
            }
            RSA_free(rsa);
        }
        BN_free(n);
        BN_free(e);
    }
    
    return key;
}

int emv_rsa_sign(const EMV_RSA_Key *key, 
                const uint8_t *hash, size_t hash_len,
                uint8_t *sig, size_t *sig_len) 
{
    if (!key || !key->openssl_key) return -1;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    
    if (!EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, (EVP_PKEY*)key->openssl_key)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    if (!EVP_DigestSign(ctx, sig, sig_len, hash, hash_len)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    EVP_MD_CTX_free(ctx);
    return 0;
}

bool emv_rsa_verify(const EMV_RSA_Key *key,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *signature, size_t sig_len) 
{
    if (!key || !key->openssl_key) return false;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool result = false;
    
    if (ctx && 
        EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, (EVP_PKEY*)key->openssl_key) &&
        EVP_DigestVerify(ctx, signature, sig_len, hash, hash_len)) {
        result = true;
    }
    
    EVP_MD_CTX_free(ctx);
    return result;
}

// Add to crypto_windows.c
void emv_hash_update(ByteBuffer *hash, const unsigned char *data, size_t len)
{
    if (!hash || !hash->data || !data || !len)
        return;
        
    // This is a proper crypto hash update, not just buffer concatenation
    // We need to recreate the hash context, add the original + new data
    
    unsigned char *temp_data = malloc(hash->length + len);
    if (!temp_data)
        return;
        
    // Concatenate original hash and new data
    memcpy(temp_data, hash->data, hash->length);
    memcpy(temp_data + hash->length, data, len);
    
    // Free the old hash data
    free(hash->data);
    
    // Calculate new hash (determine algorithm by hash length)
    if (hash->length == SHA_DIGEST_LENGTH) {
        // SHA-1
        ByteBuffer new_hash = emv_sha1_hash(temp_data, hash->length + len);
        hash->data = new_hash.data;
        hash->length = new_hash.length;
    } else {
        // SHA-256
        ByteBuffer new_hash = emv_sha256_hash(temp_data, hash->length + len);
        hash->data = new_hash.data;
        hash->length = new_hash.length;
    }
    
    free(temp_data);
}

void emv_rsa_free_key(EMV_RSA_Key *key) {
    if (key && key->openssl_key) {
        EVP_PKEY_free((EVP_PKEY*)key->openssl_key);
        key->openssl_key = NULL;
    }
}

// Hash Functions
ByteBuffer emv_sha1_hash(const unsigned char *data, size_t len) {
    ByteBuffer result = { NULL, SHA_DIGEST_LENGTH };
    result.data = malloc(SHA_DIGEST_LENGTH);
    if (result.data) {
        SHA1(data, len, result.data);
    }
    return result;
}

ByteBuffer emv_sha256_hash(const unsigned char *data, size_t len) {
    ByteBuffer result = { NULL, SHA256_DIGEST_LENGTH };
    result.data = malloc(SHA256_DIGEST_LENGTH);
    if (result.data) {
        SHA256(data, len, result.data);
    }
    return result;
}

// Helper function to free ByteBuffer
void emv_free_buffer(ByteBuffer *buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->length = 0;
    }
}
