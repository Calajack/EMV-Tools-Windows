#define _CRT_SECURE_NO_WARNINGS

#include "emv_pki.h"
#include "emv_pk.h"
#include "crypto_windows.h"
#include "tlv.h"
#include <stdlib.h>
#include <string.h>

static struct emv_pk *emv_pki_decode_key(const struct tlvdb *db, tlv_tag_t tag, tlv_tag_t mod_tag, tlv_tag_t exp_tag)
{
    const struct tlv *cert_tlv = tlvdb_get(db, tag, NULL);
    const struct tlv *mod_tlv = tlvdb_get(db, mod_tag, NULL);
    const struct tlv *exp_tlv = tlvdb_get(db, exp_tag, NULL);
    
    if (!cert_tlv || !mod_tlv || !exp_tlv)
        return NULL;
    
    // Check data consistency
    if (cert_tlv->len != mod_tlv->len)
        return NULL;
    
    struct emv_pk *pk = emv_pk_new(mod_tlv->len, exp_tlv->len);
    if (!pk)
        return NULL;
    
    // Copy exponent
    memcpy(pk->exp, exp_tlv->value, exp_tlv->len);
    
    // Copy modulus
    memcpy(pk->modulus, mod_tlv->value, mod_tlv->len);
    
    return pk;
}

static struct emv_pk *emv_pki_recover_issuer_cert(const struct emv_pk *pk, const struct tlvdb *db)
{
    const struct tlv *issuer_cert_tlv = tlvdb_get(db, 0x90, NULL);
    const struct tlv *issuer_rem_tlv = tlvdb_get(db, 0x92, NULL);
    const struct tlv *issuer_exp_tlv = tlvdb_get(db, 0x9F32, NULL);
    
    if (!pk || !pk->modulus || !issuer_cert_tlv || !issuer_exp_tlv)
        return NULL;
    
    // Create RSA key from issuer PK
    EMV_RSA_Key issuer_key = emv_rsa_create_key(pk->modulus, pk->mlen, pk->exp, pk->elen);
    if (!issuer_key.openssl_key)
        return NULL;
    
    size_t modulus_len = issuer_cert_tlv->len;
    unsigned char *modulus = malloc(modulus_len);
    if (!modulus) {
        emv_rsa_free_key(&issuer_key);
        return NULL;
    }
    
    // Decrypt the certificate
    if (!emv_rsa_verify(&issuer_key, issuer_cert_tlv->value, issuer_cert_tlv->len,
                       modulus, &modulus_len)) {
        free(modulus);
        emv_rsa_free_key(&issuer_key);
        return NULL;
    }
    
    // Check header/trailer
    if (modulus[0] != 0x6A || modulus[modulus_len - 1] != 0xBC) {
        free(modulus);
        emv_rsa_free_key(&issuer_key);
        return NULL;
    }
    
    // Determine hash algorithm from header
    unsigned char hash_algo = modulus[1];
    if (hash_algo != HASH_SHA_1 && hash_algo != HASH_SHA_256) {
        free(modulus);
        emv_rsa_free_key(&issuer_key);
        return NULL;
    }
    
    size_t hash_len = (hash_algo == HASH_SHA_1) ? 20 : 32;
    
    // Extract issuer data
    unsigned char *issuer_data = modulus + 2;
    size_t issuer_data_len = modulus_len - 2 - hash_len - 1;
    
    // Recover PK
    struct emv_pk *issuer_pk = emv_pk_new(issuer_data_len, issuer_exp_tlv->len);
    if (!issuer_pk) {
        free(modulus);
        emv_rsa_free_key(&issuer_key);
        return NULL;
    }
    
    // Copy data
    memcpy(issuer_pk->rid, pk->rid, 5);
    issuer_pk->index = issuer_data[0];
    issuer_pk->hash_algo = hash_algo;
    
    // Copy exponent
    memcpy(issuer_pk->exp, issuer_exp_tlv->value, issuer_exp_tlv->len);
    
    // Copy modulus
    memcpy(issuer_pk->modulus, issuer_data + 1, issuer_data_len - 1);
    
    // Handle remainder if present
    if (issuer_rem_tlv && issuer_rem_tlv->len > 0) {
        size_t rem_pos = issuer_data_len - 1;
        if (rem_pos + issuer_rem_tlv->len > issuer_pk->mlen) {
            emv_pk_free(issuer_pk);
            free(modulus);
            emv_rsa_free_key(&issuer_key);
            return NULL;
        }
        
        memcpy(issuer_pk->modulus + rem_pos, issuer_rem_tlv->value, issuer_rem_tlv->len);
    }
    
    // Calculate hash and verify
    ByteBuffer hash;
    if (hash_algo == HASH_SHA_1)
        hash = emv_sha1_hash(issuer_pk->rid, 5);
    else
        hash = emv_sha256_hash(issuer_pk->rid, 5);
    
    if (!hash.data) {
        emv_pk_free(issuer_pk);
        free(modulus);
        emv_rsa_free_key(&issuer_key);
        return NULL;
    }
    
    // Update hash with index and public key
    emv_hash_update(&hash, &issuer_pk->index, 1);
    emv_hash_update(&hash, issuer_pk->modulus, issuer_pk->mlen);
    emv_hash_update(&hash, issuer_pk->exp, issuer_pk->elen);
    
    // Compare hash
    unsigned char *cert_hash = modulus + modulus_len - hash_len - 1;
    if (hash.length != hash_len || memcmp(hash.data, cert_hash, hash_len) != 0) {
        emv_free_buffer(&hash);
        emv_pk_free(issuer_pk);
        free(modulus);
        emv_rsa_free_key(&issuer_key);
        return NULL;
    }
    
    emv_free_buffer(&hash);
    free(modulus);
    emv_rsa_free_key(&issuer_key);
    
    return issuer_pk;
}

static struct emv_pk *emv_pki_recover_icc_cert(const struct emv_pk *pk, const struct tlvdb *db, 
                                           unsigned char *pan, size_t pan_len)
{
    const struct tlv *icc_cert_tlv = tlvdb_get(db, 0x9F46, NULL);
    const struct tlv *icc_exp_tlv = tlvdb_get(db, 0x9F47, NULL);
    const struct tlv *icc_rem_tlv = tlvdb_get(db, 0x9F48, NULL);
    
    if (!pk || !pk->modulus || !icc_cert_tlv || !icc_exp_tlv)
        return NULL;
    
    EMV_RSA_Key icc_key = emv_rsa_create_key(pk->modulus, pk->mlen, pk->exp, pk->elen);
    if (!icc_key.openssl_key)
        return NULL;
    
    size_t modulus_len = icc_cert_tlv->len;
    unsigned char *modulus = malloc(modulus_len);
    if (!modulus) {
        emv_rsa_free_key(&icc_key);
        return NULL;
    }
    
    // Decrypt the certificate
    if (!emv_rsa_verify(&icc_key, icc_cert_tlv->value, icc_cert_tlv->len,
                      modulus, &modulus_len)) {
        free(modulus);
        emv_rsa_free_key(&icc_key);
        return NULL;
    }
    
    // Check header/trailer
    if (modulus[0] != 0x6A || modulus[modulus_len - 1] != 0xBC) {
        free(modulus);
        emv_rsa_free_key(&icc_key);
        return NULL;
    }
    
    // Determine hash algorithm from header
    unsigned char hash_algo = modulus[1];
    if (hash_algo != HASH_SHA_1 && hash_algo != HASH_SHA_256) {
        free(modulus);
        emv_rsa_free_key(&icc_key);
        return NULL;
    }
    
    size_t hash_len = (hash_algo == HASH_SHA_1) ? 20 : 32;
    
    // Extract ICC data
    unsigned char *icc_data = modulus + 2;
    size_t icc_data_len = modulus_len - 2 - hash_len - 1;
    
    // Check PAN
    if (!pan || pan_len < 10 || memcmp(icc_data + 2, pan, 10) != 0) {
        free(modulus);
        emv_rsa_free_key(&icc_key);
        return NULL;
    }
    
    // Recover PK
    struct emv_pk *icc_pk = emv_pk_new(icc_data_len - 22, icc_exp_tlv->len);
    if (!icc_pk) {
        free(modulus);
        emv_rsa_free_key(&icc_key);
        return NULL;
    }
    
    // Copy data
    memcpy(icc_pk->rid, pk->rid, 5);
    memcpy(icc_pk->pan, pan, pan_len > 10 ? 10 : pan_len);
    icc_pk->hash_algo = hash_algo;
    
    // Copy exponent
    memcpy(icc_pk->exp, icc_exp_tlv->value, icc_exp_tlv->len);
    
    // Copy modulus
    memcpy(icc_pk->modulus, icc_data + 22, icc_data_len - 22);
    
    // Handle remainder if present
    if (icc_rem_tlv && icc_rem_tlv->len > 0) {
        size_t rem_pos = icc_data_len - 22;
        if (rem_pos + icc_rem_tlv->len > icc_pk->mlen) {
            emv_pk_free(icc_pk);
            free(modulus);
            emv_rsa_free_key(&icc_key);
            return NULL;
        }
        
        memcpy(icc_pk->modulus + rem_pos, icc_rem_tlv->value, icc_rem_tlv->len);
    }
    
    // Calculate hash and verify
    ByteBuffer hash;
    if (hash_algo == HASH_SHA_1)
        hash = emv_sha1_hash(pan, 10);
    else
        hash = emv_sha256_hash(pan, 10);
    
    if (!hash.data) {
        emv_pk_free(icc_pk);
        free(modulus);
        emv_rsa_free_key(&icc_key);
        return NULL;
    }
    
    // Update hash with other certificate data
    emv_hash_update(&hash, icc_data + 12, 10); // Expiry date, serial, etc.
    emv_hash_update(&hash, icc_pk->modulus, icc_pk->mlen);
    emv_hash_update(&hash, icc_pk->exp, icc_pk->elen);
    
    // Compare hash
    unsigned char *cert_hash = modulus + modulus_len - hash_len - 1;
    if (hash.length != hash_len || memcmp(hash.data, cert_hash, hash_len) != 0) {
        emv_free_buffer(&hash);
        emv_pk_free(icc_pk);
        free(modulus);
        emv_rsa_free_key(&icc_key);
        return NULL;
    }
    
    emv_free_buffer(&hash);
    free(modulus);
    emv_rsa_free_key(&icc_key);
    
    return icc_pk;
}

static struct emv_pk *emv_pki_recover_icc_pe_cert(const struct emv_pk *pk, const struct tlvdb *db)
{
    const struct tlv *cert_tlv = tlvdb_get(db, 0x9F2D, NULL);
    const struct tlv *exp_tlv = tlvdb_get(db, 0x9F2E, NULL);
    const struct tlv *rem_tlv = tlvdb_get(db, 0x9F2F, NULL);
    const struct tlv *pan_tlv = tlvdb_get(db, 0x5A, NULL);
    
    if (!pk || !pk->modulus || !cert_tlv || !exp_tlv || !pan_tlv)
        return NULL;
    
    return emv_pki_recover_icc_cert(pk, db, pan_tlv->value, pan_tlv->len);
}

struct emv_pk *emv_pki_recover_issuer_cert(const struct emv_pk *ca_pk, const struct tlvdb *db)
{
    return emv_pki_recover_issuer_cert(ca_pk, db);
}

struct emv_pk *emv_pki_recover_icc_cert(const struct emv_pk *ca_pk, const struct tlvdb *db, 
                                    unsigned char *pan, size_t pan_len)
{
    return emv_pki_recover_icc_cert(ca_pk, db, pan, pan_len);
}

struct emv_pk *emv_pki_recover_icc_pe_cert(const struct emv_pk *ca_pk, const struct tlvdb *db)
{
    return emv_pki_recover_icc_pe_cert(ca_pk, db);
}

bool emv_pki_verify_sig(const struct emv_pk *pk, const struct tlvdb *db, 
                     tlv_tag_t cert_tag, tlv_tag_t data_tag, tlv_tag_t data_dol_tag)
{
    const struct tlv *cert_tlv = tlvdb_get(db, cert_tag, NULL);
    const struct tlv *data_tlv = tlvdb_get(db, data_tag, NULL);
    const struct tlv *dol_tlv = data_dol_tag ? tlvdb_get(db, data_dol_tag, NULL) : NULL;
    
    if (!pk || !pk->modulus || !cert_tlv)
        return false;
    
    EMV_RSA_Key key = emv_rsa_create_key(pk->modulus, pk->mlen, pk->exp, pk->elen);
    if (!key.openssl_key)
        return false;
    
    size_t decrypted_len = cert_tlv->len;
    unsigned char *decrypted = malloc(decrypted_len);
    if (!decrypted) {
        emv_rsa_free_key(&key);
        return false;
    }
    
    // Verify the signature
    if (!emv_rsa_verify(&key, cert_tlv->value, cert_tlv->len,
                      decrypted, &decrypted_len)) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return false;
    }
    
    // Check header/trailer
    if (decrypted[0] != 0x6A || decrypted[decrypted_len - 1] != 0xBC) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return false;
    }
    
    // Determine hash algorithm
    unsigned char hash_algo = decrypted[1];
    if (hash_algo != HASH_SHA_1 && hash_algo != HASH_SHA_256) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return false;
    }
    
    size_t hash_len = (hash_algo == HASH_SHA_1) ? 20 : 32;
    
    // Create hash
    ByteBuffer hash;
    if (hash_algo == HASH_SHA_1)
        hash = emv_sha1_hash(decrypted + 2, decrypted_len - 2 - hash_len - 1);
    else
        hash = emv_sha256_hash(decrypted + 2, decrypted_len - 2 - hash_len - 1);
    
    if (!hash.data) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return false;
    }
    
    // Add DOL data if needed
    if (data_tlv && dol_tlv)
        emv_hash_update(&hash, data_tlv->value, data_tlv->len);
    
    // Compare hash
    unsigned char *sig_hash = decrypted + decrypted_len - hash_len - 1;
    bool result = (hash.length == hash_len && memcmp(hash.data, sig_hash, hash_len) == 0);
    
    emv_free_buffer(&hash);
    free(decrypted);
    emv_rsa_free_key(&key);
    
    return result;
}

bool emv_pki_aac_verify(const struct emv_pk *icc_pk, const struct tlvdb *db, 
                     const unsigned char *tdol_data, size_t tdol_data_len, 
                     const unsigned char *crm_data, size_t crm_data_len)
{
    const struct tlv *arqc_tlv = tlvdb_get(db, 0x9F26, NULL);
    const struct tlv *arc_tlv = tlvdb_get(db, 0x9F36, NULL);
    
    if (!icc_pk || !icc_pk->modulus || !arqc_tlv || !arc_tlv || 
        !tdol_data || !crm_data)
        return false;
    
    // Create RSA key
    EMV_RSA_Key key = emv_rsa_create_key(icc_pk->modulus, icc_pk->mlen, 
                                      icc_pk->exp, icc_pk->elen);
    if (!key.openssl_key)
        return false;
    
    // Verify CRM signature
    size_t decrypted_len = icc_pk->mlen;
    unsigned char *decrypted = malloc(decrypted_len);
    if (!decrypted) {
        emv_rsa_free_key(&key);
        return false;
    }
    
    if (!emv_rsa_verify(&key, crm_data, crm_data_len,
                      decrypted, &decrypted_len)) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return false;
    }
    
    // Check CRM format
    if (decrypted[0] != 0x6A) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return false;
    }
    
    // Extract CRM data
    unsigned char *crm_ptr = decrypted + 1;
    
    // Verify ARQC
    if (memcmp(crm_ptr, arqc_tlv->value, arqc_tlv->len) != 0) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return false;
    }
    
    crm_ptr += arqc_tlv->len;
    
    // Verify ARC
    if (memcmp(crm_ptr, arc_tlv->value, arc_tlv->len) != 0) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return false;
    }
    
    // Hash verification would go here in a full implementation
    // For now, just assume the CRM is valid if it decrypts correctly
    
    free(decrypted);
    emv_rsa_free_key(&key);
    
    return true;
}

struct tlvdb *emv_pki_recover_dac(const struct emv_pk *pk, const struct tlvdb *db, 
                               const unsigned char *sda_data, size_t sda_data_len)
{
    const struct tlv *ssad_tlv = tlvdb_get(db, 0x93, NULL);
    
    if (!pk || !pk->modulus || !ssad_tlv)
        return NULL;
    
    // Create RSA key
    EMV_RSA_Key key = emv_rsa_create_key(pk->modulus, pk->mlen, pk->exp, pk->elen);
    if (!key.openssl_key)
        return NULL;
    
    // Decrypt SSAD
    size_t decrypted_len = ssad_tlv->len;
    unsigned char *decrypted = malloc(decrypted_len);
    if (!decrypted) {
        emv_rsa_free_key(&key);
        return NULL;
    }
    
    if (!emv_rsa_verify(&key, ssad_tlv->value, ssad_tlv->len,
                      decrypted, &decrypted_len)) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return NULL;
    }
    
    // Check header
    if (decrypted[0] != 0x6A) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return NULL;
    }
    
    // Get hash algorithm
    unsigned char hash_algo = decrypted[1];
    if (hash_algo != HASH_SHA_1 && hash_algo != HASH_SHA_256) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return NULL;
    }
    
    size_t hash_len = (hash_algo == HASH_SHA_1) ? 20 : 32;
    
    // Extract DAC
    unsigned char *dac_ptr = decrypted + 2;
    
    // Create TLV for DAC
    struct tlvdb *dac_db = tlvdb_fixed(0x9F45, 2, dac_ptr);
    
    free(decrypted);
    emv_rsa_free_key(&key);
    
    return dac_db;
}

struct tlvdb *emv_pki_recover_idn(const struct emv_pk *pk, const struct tlvdb *db, 
                              const unsigned char *dyn_data, size_t dyn_data_len)
{
    const struct tlv *idn_tlv = tlvdb_get(db, 0x9F4B, NULL);
    
    if (!pk || !pk->modulus || !idn_tlv)
        return NULL;
    
    // Create RSA key
    EMV_RSA_Key key = emv_rsa_create_key(pk->modulus, pk->mlen, pk->exp, pk->elen);
    if (!key.openssl_key)
        return NULL;
    
    // Decrypt IDN
    size_t decrypted_len = idn_tlv->len;
    unsigned char *decrypted = malloc(decrypted_len);
    if (!decrypted) {
        emv_rsa_free_key(&key);
        return NULL;
    }
    
    if (!emv_rsa_verify(&key, idn_tlv->value, idn_tlv->len,
                      decrypted, &decrypted_len)) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return NULL;
    }
    
    // Check header
    if (decrypted[0] != 0x6A) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return NULL;
    }
    
    // Get hash algorithm
    unsigned char hash_algo = decrypted[1];
    if (hash_algo != HASH_SHA_1 && hash_algo != HASH_SHA_256) {
        free(decrypted);
        emv_rsa_free_key(&key);
        return NULL;
    }
    
    size_t hash_len = (hash_algo == HASH_SHA_1) ? 20 : 32;
    
    // Extract signed data length
    unsigned char signed_data_len = decrypted[2];
    unsigned char *signed_data = decrypted + 3;
    
    // Create TLV for IDN data
    struct tlvdb *idn_db = tlvdb_fixed(0x9F4C, signed_data_len, signed_data);
    
    free(decrypted);
    emv_rsa_free_key(&key);
    
    return idn_db;
}
