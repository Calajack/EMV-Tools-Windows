#ifndef EMV_PKI_PRIV_H
#define EMV_PKI_PRIV_H

#include "emv_pk.h"
#include "crypto_windows.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations for TLV structures (adjust if you have actual definitions)
struct tlv;
struct tlvdb;

/**
 * Creates a CA public key structure from RSA components
 * @param cp RSA key container
 * @param rid 5-byte RID (Registered Application Provider Identifier)
 * @param index Key index
 * @param expire Expiry date in YYMMDD format
 * @param hash_algo Hash algorithm (HASH_SHA_1 or HASH_SHA_256)
 * @return Newly allocated EMV public key structure
 */
struct emv_pk *emv_pki_make_ca(const EMV_RSA_Key *cp,
                              const unsigned char *rid,
                              unsigned char index,
                              unsigned int expire,
                              unsigned char hash_algo);

/**
 * Signs an Issuer Certificate
 * @param cp CA private key
 * @param issuer_pk Issuer public key to certify
 * @return TLV database containing certificate
 */
struct tlvdb *emv_pki_sign_issuer_cert(const EMV_RSA_Key *cp,
                                     struct emv_pk *issuer_pk);

/**
 * Signs an ICC Certificate
 * @param cp CA private key
 * @param icc_pk ICC public key to certify
 * @param sda_tlv Signed Static Application Data (may be NULL)
 * @return TLV database containing certificate
 */
struct tlvdb *emv_pki_sign_icc_cert(const EMV_RSA_Key *cp,
                                  struct emv_pk *icc_pk,
                                  const struct tlv *sda_tlv);

/**
 * Signs an ICC PIN Encipherment Certificate
 * @param cp CA private key
 * @param icc_pe_pk ICC PE public key to certify
 * @return TLV database containing certificate
 */
struct tlvdb *emv_pki_sign_icc_pe_cert(const EMV_RSA_Key *cp,
                                     struct emv_pk *icc_pe_pk);

/**
 * Signs a Dynamic Application Cryptogram (DAC)
 * @param cp CA private key
 * @param dac_tlv DAC data to sign
 * @param sda_tlv Signed Static Application Data (may be NULL)
 * @return TLV database containing signature
 */
struct tlvdb *emv_pki_sign_dac(const EMV_RSA_Key *cp,
                             const struct tlv *dac_tlv,
                             const struct tlv *sda_tlv);

/**
 * Signs an Issuer Discretionary Data (IDN)
 * @param cp CA private key
 * @param idn_tlv IDN data to sign
 * @param dyn_tlv Dynamic Authentication Data (may be NULL)
 * @return TLV database containing signature
 */
struct tlvdb *emv_pki_sign_idn(const EMV_RSA_Key *cp,
                             const struct tlv *idn_tlv,
                             const struct tlv *dyn_tlv);

#ifdef __cplusplus
}
#endif

#endif /* EMV_PKI_PRIV_H */