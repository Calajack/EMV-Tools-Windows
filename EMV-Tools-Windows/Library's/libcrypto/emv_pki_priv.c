#include "emv_pki_priv.h"
#include "emv_pk.h"
#include "crypto_windows.h"
#include <windows.h>
#include "emv_defs.h"
#include "emv_tags.h"
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <openssl/types.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

struct emv_pk *emv_pki_make_ca(const EMV_RSA_Key *cp,
        const unsigned char *rid, unsigned char index,
        unsigned int expire, enum crypto_algo_hash hash_algo)
{
    if (!rid || !cp || !cp->openssl_key)
        return NULL;

    // Get modulus from RSA key
    BIGNUM* n = NULL, * e = NULL;
    if (!EVP_PKEY_get_bn_param((EVP_PKEY*)cp->openssl_key, OSSL_PKEY_PARAM_RSA_N, &n) ||
        !EVP_PKEY_get_bn_param((EVP_PKEY*)cp->openssl_key, OSSL_PKEY_PARAM_RSA_E, &e) ||
        !n || !e) {
        if (n) BN_free(n);
        if (e) BN_free(e);
        return NULL;
    }
    
    size_t modlen = BN_num_bytes(n);
    size_t explen = BN_num_bytes(e);
    
    if (modlen == 0 || explen == 0 || explen > 3)
        return NULL;

    struct emv_pk *pk = emv_pk_new(modlen, explen);
    if (!pk)
        return NULL;

    memcpy(pk->rid, rid, 5);
    pk->index = index;
    pk->expire = expire;
    pk->pk_algo = PK_RSA; // Only RSA supported in this implementation
    pk->hash_algo = hash_algo;
    
    BN_bn2bin(n, pk->modulus);
    BN_bn2bin(e, pk->exp);

    // Calculate hash
    ByteBuffer hash;
    switch(hash_algo) {
        case HASH_SHA_1:
            hash = emv_sha1_hash(pk->rid, sizeof(pk->rid));
            break;
        case HASH_SHA_256:
            hash = emv_sha256_hash(pk->rid, sizeof(pk->rid));
            break;
        default:
            emv_pk_free(pk);
            return NULL;
    }

    if (!hash.data || hash.length == 0) {
        emv_pk_free(pk);
        return NULL;
    }

    // Continue hashing other fields
    emv_hash_update(&hash, &pk->index, 1);
    emv_hash_update(&hash, pk->modulus, pk->mlen);
    emv_hash_update(&hash, pk->exp, pk->elen);

    if (hash.length > sizeof(pk->hash)) {
        emv_free_buffer(&hash);
        emv_pk_free(pk);
        return NULL;
    }

    memcpy(pk->hash, hash.data, hash.length);
    emv_free_buffer(&hash);
    BN_free(n);
    BN_free(e);

    return pk;
}

static struct tlvdb *emv_pki_sign_message(const EMV_RSA_Key *cp,
        tlv_tag_t cert_tag, tlv_tag_t rem_tag,
        const unsigned char *msg, size_t msg_len,
        ... /* A list of tlv pointers, end with NULL */)
{
    if (!cp || !cp->openssl_key || !msg)
        return NULL;

    size_t tmp_len = EVP_PKEY_size((EVP_PKEY*)cp->openssl_key);
    unsigned char *tmp = malloc(tmp_len);
    if (!tmp)
        return NULL;

    // Prepare the message with padding
    tmp[0] = 0x6A;
    tmp[tmp_len - 1] = 0xBC;

    ByteBuffer hash = emv_sha1_hash(NULL, 0); // Initialize with SHA-1
    if (!hash.data) {
        free(tmp);
        return NULL;
    }

    size_t hash_len = hash.length;
    size_t part_len = tmp_len - 2 - hash_len;
    const unsigned char *rem = NULL;
    size_t rem_len = 0;

    if (part_len < msg_len) {
        memcpy(tmp + 1, msg, part_len);
        rem = msg + part_len;
        rem_len = msg_len - part_len;
    } else {
        memcpy(tmp + 1, msg, msg_len);
        memset(tmp + 1 + msg_len, 0xBB, part_len - msg_len);
    }

    // Update hash with message parts
    emv_hash_update(&hash, tmp + 1, part_len);
    if (rem)
        emv_hash_update(&hash, rem, rem_len);

    // Process additional TLVs from varargs
    va_list vl;
    va_start(vl, msg_len);
    while (true) {
        const struct tlv *add_tlv = va_arg(vl, const struct tlv *);
        if (!add_tlv)
            break;
        emv_hash_update(&hash, add_tlv->value, add_tlv->len);
    }
    va_end(vl);

    // Copy hash to temp buffer
    memcpy(tmp + 1 + part_len, hash.data, hash_len);
    emv_free_buffer(&hash);

    // Sign the message
    size_t cert_len;
    unsigned char *cert = malloc(tmp_len);
    if (!cert) {
        free(tmp);
        return NULL;
    }

    if (emv_rsa_sign(cp, tmp, tmp_len, cert, &cert_len) != 0) {
        free(tmp);
        free(cert);
        return NULL;
    }
    free(tmp);

    struct tlvdb *db = tlvdb_fixed(cert_tag, cert_len, cert);
    free(cert);
    if (!db)
        return NULL;

    if (rem) {
        struct tlvdb *rdb = tlvdb_fixed(rem_tag, rem_len, rem);
        if (!rdb) {
            tlvdb_free(db);
            return NULL;
        }
        tlvdb_add(db, rdb);
    }

    return db;
}

// [Rest of the functions (emv_pki_sign_key, emv_pki_sign_issuer_cert, etc.) 
// would follow the same pattern as the original but adapted to use the Windows/OpenSSL implementation]

static struct tlvdb *emv_pki_sign_key(const EMV_RSA_Key *cp,
    struct emv_pk *ipk,
    unsigned char msgtype,
    size_t pan_len,
    tlv_tag_t cert_tag,
    tlv_tag_t exp_tag,
    tlv_tag_t rem_tag,
    const struct tlv *add_tlv)
{
// Parameter validation
if (!cp || !ipk || !ipk->modulus || !ipk->exp || pan_len == 0) {
    return NULL;
}

// Secure allocation
size_t msg_len = 1 + pan_len + 2 + 3 + 1 + 1 + 1 + 1 + ipk->mlen;
unsigned char *msg = malloc(msg_len);
if (!msg) return NULL;

unsigned pos = 0;
msg[pos++] = msgtype;

// Handle PAN (with null check)
if (ipk->pan) {
    memcpy(msg + pos, ipk->pan, pan_len);
} else {
    memset(msg + pos, 0, pan_len);
}
pos += pan_len;

// Expiry date (YYMM format)
msg[pos++] = (ipk->expire >> 8) & 0xff;   // Month
msg[pos++] = (ipk->expire >> 16) & 0xff;  // Year

// Serial number (with null check)
if (ipk->serial) {
    memcpy(msg + pos, ipk->serial, 3);
} else {
    memset(msg + pos, 0, 3);
}
pos += 3;

// Algorithm identifiers
msg[pos++] = ipk->hash_algo;
msg[pos++] = ipk->pk_algo;
msg[pos++] = (unsigned char)ipk->mlen;
msg[pos++] = (unsigned char)ipk->elen;

// Modulus
memcpy(msg + pos, ipk->modulus, ipk->mlen);
pos += ipk->mlen;

// Create exponent TLV
struct tlv exp_tlv = {
    .tag = exp_tag,
    .len = ipk->elen,
    .value = ipk->exp
};

// Sign the message
struct tlvdb *db = emv_pki_sign_message(cp,
        cert_tag, rem_tag,
        msg, pos,
        &exp_tlv,
        add_tlv,
        NULL);

// Secure cleanup
SecureZeroMemory(msg, msg_len);
free(msg);

return db;
}

struct tlvdb *emv_pki_sign_issuer_cert(const EMV_RSA_Key *cp, struct emv_pk *issuer_pk)
{
    if (!cp || !issuer_pk)
        return NULL;
        
    return emv_pki_sign_key(cp, issuer_pk, 2, 4, 0x90, 0x9F32, 0x92, NULL);
}

struct tlvdb *emv_pki_sign_icc_cert(const EMV_RSA_Key *cp, struct emv_pk *icc_pk, const struct tlv *sda_tlv)
{
    if (!cp || !icc_pk)
        return NULL;
        
    return emv_pki_sign_key(cp, icc_pk, 4, 10, 0x9F46, 0x9F47, 0x9F48, sda_tlv);
}

struct tlvdb *emv_pki_sign_icc_pe_cert(const EMV_RSA_Key *cp, struct emv_pk *icc_pe_pk)
{
    if (!cp || !icc_pe_pk)
        return NULL;
        
    return emv_pki_sign_key(cp, icc_pe_pk, 4, 10, 0x9F2D, 0x9F2E, 0x9F2F, NULL);
}

struct tlvdb *emv_pki_sign_dac(const EMV_RSA_Key *cp, const struct tlv *dac_tlv, const struct tlv *sda_tlv)
{
    if (!cp || !dac_tlv)
        return NULL;

    unsigned pos = 0;
    unsigned char *msg = malloc(1 + 1 + dac_tlv->len);
    if (!msg)
        return NULL;

    msg[pos++] = 3;
    msg[pos++] = HASH_SHA_1;
    memcpy(msg + pos, dac_tlv->value, dac_tlv->len);
    pos += dac_tlv->len;

    struct tlvdb *db = emv_pki_sign_message(cp,
            0x93, 0,
            msg, pos,
            sda_tlv,
            NULL);

    free(msg);
    return db;
}

struct tlvdb *emv_pki_sign_idn(const EMV_RSA_Key *cp, const struct tlv *idn_tlv, const struct tlv *dyn_tlv)
{
    if (!cp || !idn_tlv)
        return NULL;

    unsigned pos = 0;
    unsigned char *msg = malloc(1 + 1 + 1 + 1 + idn_tlv->len);
    if (!msg)
        return NULL;

    msg[pos++] = 5;
    msg[pos++] = HASH_SHA_1;
    msg[pos++] = idn_tlv->len + 1;
    msg[pos++] = idn_tlv->len;
    memcpy(msg + pos, idn_tlv->value, idn_tlv->len);
    pos += idn_tlv->len;

    struct tlvdb *db = emv_pki_sign_message(cp,
            0x9F4B, 0,
            msg, pos,
            dyn_tlv,
            NULL);

    free(msg);
    return db;
}
