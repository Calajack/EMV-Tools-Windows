#ifndef EMV_CRYPTO_WINDOWS_H
#define EMV_CRYPTO_WINDOWS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Define hash algorithm constants (avoid conflicting with OpenSSL) 
#ifndef HASH_ALGORITHMS_DEFINED
#define HASH_ALGORITHMS_DEFINED
    enum crypto_algo_hash {
        HASH_SHA_1 = 0,
        HASH_SHA_256 = 1
    };

    enum crypto_algo_pk {
        PK_RSA = 0
    };
#endif

    // ByteBuffer structure for data handling
    typedef struct {
        unsigned char* data;
        size_t length;
    } ByteBuffer;

    // RSA key structure
    typedef struct {
        void* openssl_key;  // EVP_PKEY* (opaque pointer to avoid OpenSSL header deps)
        bool is_private;
    } EMV_RSA_Key;

    // Initialization
    bool emv_crypto_init(void);
    void emv_crypto_cleanup(void);

    // RSA Functions
    EMV_RSA_Key emv_rsa_create_key(const unsigned char* modulus, size_t mod_len,
        const unsigned char* exponent, size_t exp_len);
    int emv_rsa_sign(const EMV_RSA_Key* key,
        const uint8_t* hash, size_t hash_len,
        uint8_t* sig, size_t* sig_len);
    bool emv_rsa_verify(const EMV_RSA_Key* key,
        const unsigned char* hash, size_t hash_len,
        const unsigned char* signature, size_t sig_len);
    void emv_rsa_free_key(EMV_RSA_Key* key);

    // Hash Functions
    ByteBuffer emv_sha1_hash(const unsigned char* data, size_t len);
    ByteBuffer emv_sha256_hash(const unsigned char* data, size_t len);
    void emv_hash_update(ByteBuffer* hash, const unsigned char* data, size_t len);
    void emv_free_buffer(ByteBuffer* buf);

    // Certificate Operations
    bool emv_verify_certificate(const EMV_RSA_Key* ca_key,
        const unsigned char* cert, size_t cert_len,
        unsigned char* recovered, size_t* recovered_len);

    // Key Import/Export
    bool emv_export_key(const EMV_RSA_Key* key,
        unsigned char** modulus, size_t* mod_len,
        unsigned char** exponent, size_t* exp_len);
    bool emv_import_key(const unsigned char* modulus, size_t mod_len,
        const unsigned char* exponent, size_t exp_len,
        EMV_RSA_Key* key);

#ifdef __cplusplus
}
#endif

#endif // EMV_CRYPTO_WINDOWS_H
