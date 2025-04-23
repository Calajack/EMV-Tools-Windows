// emv_file_utils.h - File utilities for EMV certificate and data management
#ifndef EMV_FILE_UTILS_H
#define EMV_FILE_UTILS_H

#include "tlv.h"
#include "emv_pk.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	// Default file paths
#define EMV_MODULUS_FILE        "emv_modulus.txt"
#define EMV_CA_CERTS_FILE       "emv_ca_certs.txt"
#define EMV_ISSUER_CERTS_FILE   "emv_issuer_certs.txt"
#define EMV_ICC_CERTS_FILE      "emv_icc_certs.txt"
#define EMV_ICC_PRIVATE_FILE    "emv_icc_private.txt"
#define EMV_ISSUER_PRIVATE_FILE "emv_issuer_private.txt"
#define EMV_CARD_DATA_FILE      "emv_card_data.txt"
#define EMV_CRM_FILE            "emv_crm_data.txt"
#define EMV_SSAD_FILE           "emv_ssad.txt"
#define EMV_SDAD_FILE           "emv_sdad.txt"

// Certificate and modulus export functions
	bool emv_export_certificate_to_file(const struct emv_pk* pk, const char* filename);
	bool emv_export_modulus_to_file(const struct emv_pk* pk, const char* filename);

	// Append a modulus to the modulus file
	bool emv_append_modulus_to_file(const struct emv_pk* pk, const char* filename);

	// Find a modulus in the specified file by RID and index
	struct emv_pk* emv_find_modulus_in_file(const char* filename, const unsigned char* rid, unsigned char index);

	// Export TLV database items to a file
	bool emv_export_tlv_data_to_file(const struct tlvdb* db, const char* filename);

	// Export cardholder data to a file
	bool emv_export_cardholder_data_to_file(const struct tlvdb* db, const char* filename);

	// Import data from a file to a TLV database
	struct tlvdb* emv_import_tlv_data_from_file(const char* filename);

	// Export cryptogram data to a file
	bool emv_export_cryptogram_to_file(const struct tlvdb* db, const char* filename);

	// Export a binary buffer to a file in hexadecimal format
	bool emv_export_binary_to_file(const unsigned char* data, size_t data_len, const char* filename);

	// Import hexadecimal data from a file to a binary buffer
	unsigned char* emv_import_binary_from_file(const char* filename, size_t* data_len);

	// Helper function to format a TLV to a file
	void format_tlv_to_file(const struct tlv* tlv, void* data);

#ifdef __cplusplus
}
#endif

#endif // EMV_FILE_UTILS_H
