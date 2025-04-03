#ifndef EMV_PKI_H
#define EMV_PKI_H

#include "emv_pk.h"
#include "emv_tags.h"
#include "emv_defs.h"
#include "crypto_windows.h"
#include "tlv.h"
#include <openssl/evp.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


// EMV Public Key Structure (Windows-optimized)
typedef struct {
    uint8_t rid[5];         // Application Provider Identifier
    uint8_t index;          // Key index
    uint32_t expiry;        // YYMMDD format
    EVP_PKEY* pkey;         // OpenSSL key handle
    uint8_t hash[32];       // SHA-256 max
    uint8_t hash_algo;      // HASH_SHA1 or HASH_SHA256
} emv_pk_t;

// Certificate recovery
// Fix the function declarations in emv_pki.h
struct emv_pk_t* emv_pki_recover_issuer_cert(const struct emv_pk* ca_pk, const struct tlvdb* db);
struct emv_pk_t* emv_pki_recover_icc_cert(const struct emv_pk* ca_pk, const struct tlvdb* db, unsigned char* pan, size_t pan_len);
struct emv_pk_t* emv_pki_recover_icc_pe_cert(const struct emv_pk* ca_pk, const struct tlvdb* db);

// Cryptographic operations
struct emv_pk_t* emv_pki_perform_cda(const emv_pk_t* enc_pk,
                            const struct tlvdb db,
                            const tlv_t* pdol_data_tlv);




// Memory management
void emv_pk_free(emv_pk_t* pk);

#ifdef __cplusplus
}
#endif

#endif // EMV_PKI_H
