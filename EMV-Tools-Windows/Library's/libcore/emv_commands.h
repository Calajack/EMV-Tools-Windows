#ifndef EMV_COMMANDS_H
#define EMV_COMMANDS_H

#include "tlv.h"
#include <stdint.h>
#include <winscard.h>

#ifdef __cplusplus
extern "C" {
#endif

// APDU response structure
typedef struct {
    uint8_t* data;
    size_t len;
    uint16_t sw;
} emv_response_t;

// Command builders
emv_response_t* emv_get_challenge(SCARDHANDLE hCard);
tlvdb_t* emv_select(SCARDHANDLE hCard, const tlv_t* aid_tlv);
emv_response_t* emv_read_record(SCARDHANDLE hCard, uint8_t sfi, uint8_t record);
tlvdb_t* emv_gpo(SCARDHANDLE hCard, const tlv_t* pdol_data_tlv);

// Transaction commands
tlvdb_t* emv_generate_ac(SCARDHANDLE hCard, uint8_t type, const tlv_t* crm_tlv);
tlvdb_t* emv_internal_authenticate(SCARDHANDLE hCard, const tlv_t* data_tlv);

// Memory management
void emv_free_response(emv_response_t* resp);

#ifdef __cplusplus
}
#endif

#endif // EMV_COMMANDS_H