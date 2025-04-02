// emv_commands.c - High-level EMV command implementations
#include "emv_commands.h"
#include "apdu.h"  // Make sure this can be found
#include "scard_common.h"
#include "tlv.h"
#include "dol.h"
#include <stdlib.h>
#include <string.h>

#define _CRT_SECURE_NO_WARNINGS

// Helper for converting APDU response to TLV database
static struct tlvdb *apdu_to_tlvdb(struct apdu_response *apdu)
{
    if (!apdu || apdu->sw != 0x9000)
        return NULL;
    
    struct tlvdb *db = tlvdb_parse(apdu->data, apdu->len);
    apdu_response_free(apdu);
    
    return db;
}

struct tlvdb *emv_select(struct sc *scard, const unsigned char *aid, size_t aid_len)
{
    if (!scard || !aid || aid_len == 0 || aid_len > 16)
        return NULL;
    
    // Build SELECT command APDU
    struct apdu_cmd select_cmd = {
        .cla = 0x00,
        .ins = 0xA4,
        .p1 = 0x04,  // Select by name
        .p2 = 0x00,  // First or only occurrence
        .lc = aid_len,
        .data = aid,
        .le = 0x00   // Get all response data
    };
    
    struct apdu_response *apdu = sc_transmit_apdu(scard, &select_cmd);
    return apdu_to_tlvdb(apdu);
}

struct tlvdb *emv_get_processing_options(struct sc *scard, const struct tlvdb *pdol_data_tlv)
{
    if (!scard)
        return NULL;
    
    // Get PDOL data if provided
    unsigned char pdol_data[256];
    size_t pdol_data_len = 0;
    
    if (pdol_data_tlv) {
        // Use provided PDOL data
        pdol_data_len = pdol_data_tlv->tag.len;
        if (pdol_data_len > sizeof(pdol_data))
            return NULL;
        
        memcpy(pdol_data, pdol_data_tlv->tag.value, pdol_data_len);
    } else {
        // Default minimal PDOL data
        pdol_data[0] = 0x83;  // Command template
        pdol_data[1] = 0x00;  // Empty
        pdol_data_len = 2;
    }
    
    // Build GET PROCESSING OPTIONS command APDU
    struct apdu_cmd gpo_cmd = {
        .cla = 0x80,
        .ins = 0xA8,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = pdol_data_len,
        .data = pdol_data,
        .le = 0x00   // Get all response data
    };
    
    struct apdu_response *apdu = sc_transmit_apdu(scard, &gpo_cmd);
    return apdu_to_tlvdb(apdu);
}

struct tlvdb *emv_read_record(struct sc *scard, unsigned char sfi, unsigned char record_no)
{
    if (!scard || record_no == 0)
        return NULL;
    
    // Build READ RECORD command APDU
    struct apdu_cmd read_cmd = {
        .cla = 0x00,
        .ins = 0xB2,
        .p1 = record_no,
        .p2 = (sfi << 3) | 0x04,  // SFI in high 5 bits, 0x04 means SFI is present
        .lc = 0,
        .data = NULL,
        .le = 0x00   // Get all response data
    };
    
    struct apdu_response *apdu = sc_transmit_apdu(scard, &read_cmd);
    return apdu_to_tlvdb(apdu);
}

struct tlvdb *emv_get_data(struct sc *scard, tlv_tag_t tag)
{
    if (!scard)
        return NULL;
    
    // Only 2-byte tags supported by GET DATA
    if ((tag & 0xFFFF0000) != 0)
        return NULL;
    
    // Build GET DATA command APDU
    struct apdu_cmd get_data_cmd = {
        .cla = 0x80,
        .ins = 0xCA,
        .p1 = (tag >> 8) & 0xFF,
        .p2 = tag & 0xFF,
        .lc = 0,
        .data = NULL,
        .le = 0x00   // Get all response data
    };
    
    struct apdu_response *apdu = sc_transmit_apdu(scard, &get_data_cmd);
    return apdu_to_tlvdb(apdu);
}

struct tlvdb *emv_internal_authenticate(struct sc *scard, const struct tlvdb *data_tlv)
{
    if (!scard || !data_tlv)
        return NULL;
    
    // Build INTERNAL AUTHENTICATE command APDU
    struct apdu_cmd auth_cmd = {
        .cla = 0x00,
        .ins = 0x88,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = data_tlv->tag.len,
        .data = data_tlv->tag.value,
        .le = 0x00   // Get all response data
    };
    
    struct apdu_response *apdu = sc_transmit_apdu(scard, &auth_cmd);
    return apdu_to_tlvdb(apdu);
}

struct tlvdb *emv_generate_ac(struct sc *scard, unsigned char ref_control, const struct tlvdb *cdol_data_tlv)
{
    if (!scard || !cdol_data_tlv)
        return NULL;
    
    // Build GENERATE AC command APDU
    struct apdu_cmd gen_ac_cmd = {
        .cla = 0x80,
        .ins = 0xAE,
        .p1 = ref_control,  // Reference control (AC type)
        .p2 = 0x00,
        .lc = cdol_data_tlv->tag.len,
        .data = cdol_data_tlv->tag.value,
        .le = 0x00   // Get all response data
    };
    
    struct apdu_response *apdu = sc_transmit_apdu(scard, &gen_ac_cmd);
    return apdu_to_tlvdb(apdu);
}

struct tlvdb *emv_get_challenge(struct sc *scard)
{
    if (!scard)
        return NULL;
    
    // Build GET CHALLENGE command APDU
    struct apdu_cmd challenge_cmd = {
        .cla = 0x00,
        .ins = 0x84,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = 0,
        .data = NULL,
        .le = 0x00   // Get all response data
    };
    
    struct apdu_response *apdu = sc_transmit_apdu(scard, &challenge_cmd);
    return apdu_to_tlvdb(apdu);
}

struct tlvdb *emv_verify_pin(struct sc *scard, const unsigned char *pin, size_t pin_len)
{
    if (!scard || !pin || pin_len == 0 || pin_len > 16)
        return NULL;
    
    // Build VERIFY command APDU
    struct apdu_cmd verify_cmd = {
        .cla = 0x00,
        .ins = 0x20,
        .p1 = 0x00,
        .p2 = 0x80,  // PIN verification
        .lc = pin_len,
        .data = pin,
        .le = 0x00
    };
    
    struct apdu_response *apdu = sc_transmit_apdu(scard, &verify_cmd);
    return apdu_to_tlvdb(apdu);
}

struct tlvdb *emv_read_records(struct sc *scard, unsigned char psn, const struct tlvdb *pinfo)
{
    if (!scard || !pinfo)
        return NULL;
    
    struct tlvdb *result = NULL;
    const struct tlv *afl_tlv = tlvdb_get(pinfo, 0x94, NULL);  // Application File Locator
    
    if (!afl_tlv || afl_tlv->len % 4 != 0)
        return NULL;
    
    // Process AFL records
    for (size_t i = 0; i < afl_tlv->len; i += 4) {
        unsigned char sfi = afl_tlv->value[i] >> 3;
        unsigned char start = afl_tlv->value[i + 1];
        unsigned char end = afl_tlv->value[i + 2];
        unsigned char offline_auth = afl_tlv->value[i + 3];
        
        for (unsigned char record = start; record <= end; record++) {
            struct tlvdb *record_db = emv_read_record(scard, sfi, record);
            if (record_db) {
                if (!result)
                    result = record_db;
                else
                    tlvdb_add(result, record_db);
            }
        }
    }
    
    return result;
}
