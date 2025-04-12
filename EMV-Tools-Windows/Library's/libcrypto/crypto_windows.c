#include "crypto_windows.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

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

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) return key;

    BIGNUM* n = BN_bin2bn(modulus, mod_len, NULL);
    BIGNUM* e = BN_bin2bn(exponent, exp_len, NULL);

    if (n && e) {
        // Add parameters to the builder
        if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {

            // Create parameter array
            OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
            if (params) {
                // Create context and key
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                if (ctx) {
                    EVP_PKEY* pkey = NULL;
                    if (EVP_PKEY_fromdata_init(ctx) > 0 &&
                        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0) {
                        key.openssl_key = pkey;
                        key.is_private = false;
                    }
                    EVP_PKEY_CTX_free(ctx);
                }
                OSSL_PARAM_free(params);
            }
        }
    }

    // Clean up
    if (n) BN_free(n);
    if (e) BN_free(e);
    OSSL_PARAM_BLD_free(bld);

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

// In crypto_windows.c
void emv_hash_update(ByteBuffer* hash, const unsigned char* data, size_t len)
{
    if (!hash || !hash->data || !data || !len)
        return;

    // Create new combined buffer
    unsigned char* new_data = malloc(hash->length + len);
    if (!new_data)
        return;

    // Copy data
    memcpy(new_data, hash->data, hash->length);
    memcpy(new_data + hash->length, data, len);

    // Free old hash data
    unsigned char* old_data = hash->data;

    // Create new hash
    ByteBuffer new_hash;
    if (hash->length == SHA_DIGEST_LENGTH) {
        new_hash = emv_sha1_hash(new_data, hash->length + len);
    }
    else {
        new_hash = emv_sha256_hash(new_data, hash->length + len);
    }

    free(new_data);
    free(old_data);

    // Update original hash
    hash->data = new_hash.data;
    hash->length = new_hash.length;
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
