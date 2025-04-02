#ifndef EMV_CRYPTO_WINDOWS_H
#define EMV_CRYPTO_WINDOWS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32

typedef struct {
    unsigned char* data;
    size_t length;
} ByteBuffer;

typedef struct {
    void* openssl_key;  // EVP_PKEY*
    bool is_private;
} EMV_RSA_Key;

// Initialization
bool emv_crypto_init();

// RSA Functions
EMV_RSA_Key emv_rsa_create_key(const unsigned char* modulus, size_t mod_len,
                              const unsigned char* exponent, size_t exp_len);
int emv_rsa_sign(const EMV_RSA_Key *key, 
                const uint8_t *hash, size_t hash_len,
                uint8_t *sig, size_t *sig_len);
bool emv_rsa_verify(const EMV_RSA_Key *key,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *signature, size_t sig_len);
void emv_rsa_free_key(EMV_RSA_Key *key);

// Hash Functions
ByteBuffer emv_sha1_hash(const unsigned char *data, size_t len);
ByteBuffer emv_sha256_hash(const unsigned char *data, size_t len);
void emv_free_buffer(ByteBuffer *buf);

#ifdef __cplusplus
}
#endif

#endif // EMV_CRYPTO_WINDOWS_H
