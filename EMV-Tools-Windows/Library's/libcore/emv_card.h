// emv_card.h
#ifndef EMV_CARD_H
#define EMV_CARD_H

#include "scard_common.h"
#include "tlv.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define EMV_OK              0
#define EMV_ERR_CONNECT    -1
#define EMV_ERR_SELECT     -2
#define EMV_ERR_GPO        -3
#define EMV_ERR_READ       -4
#define EMV_ERR_DATA       -5
#define EMV_ERR_PROTOCOL   -6

// Card context structure
typedef struct {
    struct sc *scard;          // PC/SC context
    struct tlvdb *select_db;   // SELECT response data
    struct tlvdb *gpo_db;      // GPO response data
    struct tlvdb *records_db;  // Application records
    char reader_name[256];     // Reader name
    unsigned char aid[16];     // Selected AID
    size_t aid_len;            // AID length
    bool connected;            // Connection status
} EMV_Card;

// Initialize the EMV card subsystem
bool emv_card_init();

// Connect to a card in the specified reader
int emv_card_connect(EMV_Card *card, const char *reader_name);

// Disconnect from the card
void emv_card_disconnect(EMV_Card *card);

// Discover available applications on the card
int emv_card_discover_applications(EMV_Card *card, struct tlvdb **applications);

// Select a specific AID
int emv_card_select_application(EMV_Card *card, const unsigned char *aid, size_t aid_len);

// Get processing options
int emv_card_get_processing_options(EMV_Card *card);

// Read all application records
int emv_card_read_records(EMV_Card *card);

// Get all card data in one operation
int emv_card_read_all_data(EMV_Card *card, const unsigned char *aid, size_t aid_len);

// Get a specific data element by tag
const struct tlv *emv_card_get_data(EMV_Card *card, uint32_t tag);

// Free all data associated with the card
void emv_card_free(EMV_Card *card);

// Error handling
const char *emv_card_get_error_message(int error_code);

#ifdef __cplusplus
}
#endif

#endif // EMV_CARD_H