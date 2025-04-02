// emv_commands.h - High-level EMV command wrappers
#ifndef EMV_COMMANDS_H
#define EMV_COMMANDS_H

#define _CRT_SECURE_NO_WARNINGS

#include "scard_common.h"
#include "tlv.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SELECT application by AID
 * @param scard Smart card context
 * @param aid Application ID
 * @param aid_len Length of AID
 * @return TLV database with response or NULL on error
 */
struct tlvdb *emv_select(struct sc *scard, const unsigned char *aid, size_t aid_len);

/**
 * GET PROCESSING OPTIONS
 * @param scard Smart card context
 * @param pdol_data_tlv PDOL data TLV (can be NULL)
 * @return TLV database with response or NULL on error
 */
struct tlvdb *emv_get_processing_options(struct sc *scard, const struct tlvdb *pdol_data_tlv);

/**
 * READ RECORD
 * @param scard Smart card context
 * @param sfi Short File Identifier
 * @param record_no Record number
 * @return TLV database with response or NULL on error
 */
struct tlvdb *emv_read_record(struct sc *scard, unsigned char sfi, unsigned char record_no);

/**
 * GET DATA
 * @param scard Smart card context
 * @param tag Tag to request
 * @return TLV database with response or NULL on error
 */
struct tlvdb *emv_get_data(struct sc *scard, tlv_tag_t tag);

/**
 * INTERNAL AUTHENTICATE
 * @param scard Smart card context
 * @param data_tlv Data for authentication
 * @return TLV database with response or NULL on error
 */
struct tlvdb *emv_internal_authenticate(struct sc *scard, const struct tlvdb *data_tlv);

/**
 * GENERATE AC (Application Cryptogram)
 * @param scard Smart card context
 * @param ref_control Reference control
 * @param cdol_data_tlv CDOL data TLV
 * @return TLV database with response or NULL on error
 */
struct tlvdb *emv_generate_ac(struct sc *scard, unsigned char ref_control, const struct tlvdb *cdol_data_tlv);

/**
 * GET CHALLENGE
 * @param scard Smart card context
 * @return TLV database with response or NULL on error
 */
struct tlvdb *emv_get_challenge(struct sc *scard);

/**
 * VERIFY PIN
 * @param scard Smart card context
 * @param pin PIN data (encoded according to EMV rules)
 * @param pin_len Length of PIN data
 * @return TLV database with response or NULL on error
 */
struct tlvdb *emv_verify_pin(struct sc *scard, const unsigned char *pin, size_t pin_len);

/**
 * Read all records from application
 * @param scard Smart card context
 * @param psn PSN value from processing options
 * @param pinfo Processing info from FCI
 * @return TLV database with all records or NULL on error
 */
struct tlvdb *emv_read_records(struct sc *scard, unsigned char psn, const struct tlvdb *pinfo);

#ifdef __cplusplus
}
#endif

#endif // EMV_COMMANDS_H
