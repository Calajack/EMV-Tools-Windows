// emv_operations.h - High-level operations for EMV Tools
#ifndef EMV_OPERATIONS_H
#define EMV_OPERATIONS_H

#include "scard_common.h"
#include "tlv.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Perform a complete EMV transaction with card dump and certificate recovery
 * 
 * @param reader_name Reader name to connect to
 * @param aid Application ID to select (hex string)
 * @param amount Transaction amount (or NULL for no amount)
 * @param online Whether to request online authorization
 * @param output_dir Directory to store output files
 * @return true if successful
 */
bool emv_perform_transaction(const char *reader_name, 
                          const char *aid,
                          const char *amount,
                          bool online,
                          const char *output_dir);

/**
 * @brief Extract all certificates from TLV data and save to files
 * 
 * @param tlv_data_file File containing TLV data (can be NULL to use internal data)
 * @param ca_key_file CA key file for certificate recovery (can be NULL)
 * @param output_dir Directory to store output files
 * @return true if successful
 */
bool emv_extract_certificates(const char *tlv_data_file,
                           const char *ca_key_file,
                           const char *output_dir);

/**
 * @brief Generate a certificate chain for EMV testing
 * 
 * @param rid RID to use (hex string)
 * @param index CA key index
 * @param output_dir Directory to store output files
 * @return true if successful
 */
bool emv_generate_test_certificates(const char *rid,
                                 unsigned char index,
                                 const char *output_dir);

/**
 * @brief Verify authentication on EMV card data
 * 
 * @param tlv_data_file File containing TLV data (can be NULL to use internal data)
 * @param ca_key_file CA key file for certificate recovery (can be NULL)
 * @param dynamic_data_file File containing dynamic data for DDA (can be NULL)
 * @param output_dir Directory to store output files
 * @return true if successful
 */
bool emv_verify_authentication(const char *tlv_data_file,
                            const char *ca_key_file,
                            const char *dynamic_data_file,
                            const char *output_dir);

/**
 * @brief Process EMV cryptograms
 * 
 * @param tlv_data_file File containing TLV data (can be NULL to use internal data)
 * @param arc Authorization Response Code (hex string)
 * @param output_dir Directory to store output files
 * @return true if successful
 */
bool emv_process_cryptograms(const char *tlv_data_file,
                          const char *arc,
                          const char *output_dir);

/**
 * @brief Dump card data to files
 * 
 * @param reader_name Reader name to connect to
 * @param aid Application ID to select (hex string, can be NULL to scan for AIDs)
 * @param output_dir Directory to store output files
 * @return true if successful
 */
bool emv_dump_card_data(const char *reader_name,
                      const char *aid,
                      const char *output_dir);

#ifdef __cplusplus
}
#endif

#endif // EMV_OPERATIONS_H