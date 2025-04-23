// emv_certificate_ops.h - High-level certificate operations
#ifndef EMV_CERTIFICATE_OPS_H
#define EMV_CERTIFICATE_OPS_H

#include "emv_pk.h"
#include "crypto_windows.h"
#include "tlv.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Certificate generation operations
    bool emv_generate_certificate_chain(const EMV_RSA_Key* ca_key,
        const unsigned char* rid,
        unsigned char index,
        unsigned int expire,
        const char* issuer_output_file,
        const char* icc_output_file,
        const char* cardholder_info_file);

    // Certificate recovery and verification
    bool emv_recover_and_verify_certificates(const struct tlvdb* db,
        const char* ca_key_file,
        const char* modulus_file,
        const char* issuer_output_file,
        const char* icc_output_file);

    // Extract and save certificate information
    bool emv_extract_certificate_info(const struct tlvdb* db, const char* output_file);

    // Generate and save static/dynamic authentication data
    bool emv_generate_ssad(const EMV_RSA_Key* issuer_key,
        const struct tlvdb* static_data_db,
        const char* ssad_output_file);

    bool emv_generate_sdad(const EMV_RSA_Key* icc_key,
        const struct tlvdb* dynamic_data_db,
        const char* sdad_output_file);

    // Verify static/dynamic authentication data
    bool emv_verify_ssad(const struct tlvdb* db,
        const char* ca_key_file,
        const char* results_file);

    bool emv_verify_sdad(const struct tlvdb* db,
        const struct tlvdb* dynamic_data_db,
        const char* ca_key_file,
        const char* results_file);

    // Operations involving cryptograms
    bool emv_verify_arqc(const struct tlvdb* db,
        const EMV_RSA_Key* issuer_key,
        const char* results_file);

    bool emv_generate_arpc(const EMV_RSA_Key* issuer_key,
        const unsigned char* arqc,
        size_t arqc_len,
        const unsigned char* arc,
        size_t arc_len,
        const char* output_file);

#ifdef __cplusplus
}
#endif

#endif // EMV_CERTIFICATE_OPS_H
