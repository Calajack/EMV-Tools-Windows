// emv_card.c
#include "emv_card.h"
#include "emv_commands.h"
#include "scard_common.h"
#include "tlv.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Initialize the EMV card subsystem
bool emv_card_init() {
    // Any global initialization needed
    return true;
}

// Connect to a card in the specified reader
int emv_card_connect(EMV_Card *card, const char *reader_name) {
    if (!card || !reader_name)
        return EMV_ERR_CONNECT;

    // Initialize card structure
    memset(card, 0, sizeof(EMV_Card));
    strncpy(card->reader_name, reader_name, sizeof(card->reader_name) - 1);
    
    // Establish PC/SC context
    SCARDCONTEXT hContext;
    LONG result = scard_establish_context(&hContext);
    if (result != SCARD_S_SUCCESS) {
        printf("Failed to establish smart card context: %s\n", pcsc_stringify_error(result));
        return EMV_ERR_CONNECT;
    }
    
    // Connect to card
    SCARDHANDLE hCard;
    DWORD dwActiveProtocol;
    result = scard_connect(hContext, reader_name, &hCard, &dwActiveProtocol);
    if (result != SCARD_S_SUCCESS) {
        printf("Failed to connect to card: %s\n", pcsc_stringify_error(result));
        scard_release_context(hContext);
        return EMV_ERR_CONNECT;
    }
    
    // Create SC structure for EMV commands
    card->scard = (struct sc*)malloc(sizeof(struct sc));
    if (!card->scard) {
        scard_disconnect(hCard, SCARD_LEAVE_CARD);
        scard_release_context(hContext);
        return EMV_ERR_CONNECT;
    }
    
    card->scard->hContext = hContext;
    card->scard->hCard = hCard;
    card->scard->dwActiveProtocol = dwActiveProtocol;
    card->connected = true;
    
    return EMV_OK;
}

// Disconnect from the card
void emv_card_disconnect(EMV_Card *card) {
    if (!card || !card->connected)
        return;
    
    if (card->scard) {
        scard_disconnect(card->scard->hCard, SCARD_LEAVE_CARD);
        scard_release_context(card->scard->hContext);
        free(card->scard);
        card->scard = NULL;
    }
    
    if (card->select_db) {
        tlvdb_free(card->select_db);
        card->select_db = NULL;
    }
    
    if (card->gpo_db) {
        tlvdb_free(card->gpo_db);
        card->gpo_db = NULL;
    }
    
    if (card->records_db) {
        tlvdb_free(card->records_db);
        card->records_db = NULL;
    }
    
    card->connected = false;
}

// Discover available applications on the card
int emv_card_discover_applications(EMV_Card *card, struct tlvdb **applications) {
    if (!card || !card->connected || !applications)
        return EMV_ERR_CONNECT;
    
    // Try PSE first
    unsigned char pse[] = {'1', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1'};
    struct tlvdb *pse_db = emv_select(card->scard, pse, sizeof(pse));
    
    if (pse_db) {
        // Process PSE to find AIDs
        *applications = pse_db;
        return EMV_OK;
    }
    
    // If PSE failed, try PPSE (for contactless)
    unsigned char ppse[] = {'2', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1'};
    struct tlvdb *ppse_db = emv_select(card->scard, ppse, sizeof(ppse));
    
    if (ppse_db) {
        // Process PPSE to find AIDs
        *applications = ppse_db;
        return EMV_OK;
    }
    
    return EMV_ERR_SELECT;
}

// Select a specific AID
int emv_card_select_application(EMV_Card *card, const unsigned char *aid, size_t aid_len) {
    if (!card || !card->connected || !aid || aid_len == 0 || aid_len > 16)
        return EMV_ERR_SELECT;
    
    // Free previous selection if any
    if (card->select_db) {
        tlvdb_free(card->select_db);
        card->select_db = NULL;
    }
    
    // Store the AID
    memcpy(card->aid, aid, aid_len);
    card->aid_len = aid_len;
    
    // Select application
    card->select_db = emv_select(card->scard, aid, aid_len);
    if (!card->select_db) {
        return EMV_ERR_SELECT;
    }
    
    return EMV_OK;
}

// Get processing options
int emv_card_get_processing_options(EMV_Card *card) {
    if (!card || !card->connected || !card->select_db)
        return EMV_ERR_GPO;
    
    // Free previous GPO data if any
    if (card->gpo_db) {
        tlvdb_free(card->gpo_db);
        card->gpo_db = NULL;
    }
    
    // Get processing options
    card->gpo_db = emv_get_processing_options(card->scard, NULL);
    if (!card->gpo_db) {
        return EMV_ERR_GPO;
    }
    
    return EMV_OK;
}

// Read all application records
int emv_card_read_records(EMV_Card *card) {
    if (!card || !card->connected || !card->select_db || !card->gpo_db)
        return EMV_ERR_READ;
    
    // Free previous records if any
    if (card->records_db) {
        tlvdb_free(card->records_db);
        card->records_db = NULL;
    }
    
    // Get AFL (Application File Locator)
    const struct tlv *afl_tlv = tlvdb_get(card->gpo_db, 0x94, NULL);
    if (!afl_tlv) {
        return EMV_ERR_DATA;
    }
    
    // Extract PAN for record reading if available
    unsigned char pan[10] = {0};
    size_t pan_len = 0;
    const struct tlv *pan_tlv = tlvdb_get(card->select_db, 0x5A, NULL);
    
    if (pan_tlv) {
        pan_len = pan_tlv->len > 10 ? 10 : pan_tlv->len;
        memcpy(pan, pan_tlv->value, pan_len);
    }
    
    // Read records according to AFL
    struct tlvdb *afl_db = tlvdb_fixed(0x94, afl_tlv->len, afl_tlv->value);
    card->records_db = emv_read_records(card->scard, pan[0], afl_db);
    tlvdb_free(afl_db);
    
    if (!card->records_db) {
        return EMV_ERR_READ;
    }
    
    return EMV_OK;
}

// Get all card data in one operation
int emv_card_read_all_data(EMV_Card *card, const unsigned char *aid, size_t aid_len) {
    int result;
    
    // Connect if not already connected
    if (!card->connected) {
        result = emv_card_connect(card, card->reader_name);
        if (result != EMV_OK)
            return result;
    }
    
    // Select application
    result = emv_card_select_application(card, aid, aid_len);
    if (result != EMV_OK)
        return result;
    
    // Get processing options
    result = emv_card_get_processing_options(card);
    if (result != EMV_OK)
        return result;
    
    // Read all records
    result = emv_card_read_records(card);
    return result;
}

// Get a specific data element by tag
const struct tlv *emv_card_get_data(EMV_Card *card, uint32_t tag) {
    if (!card)
        return NULL;
    
    // Check in SELECT response
    if (card->select_db) {
        const struct tlv *tlv = tlvdb_get(card->select_db, tag, NULL);
        if (tlv)
            return tlv;
    }
    
    // Check in GPO response
    if (card->gpo_db) {
        const struct tlv *tlv = tlvdb_get(card->gpo_db, tag, NULL);
        if (tlv)
            return tlv;
    }
    
    // Check in records
    if (card->records_db) {
        const struct tlv *tlv = tlvdb_get(card->records_db, tag, NULL);
        if (tlv)
            return tlv;
    }
    
    return NULL;
}

// Free all data associated with the card
void emv_card_free(EMV_Card *card) {
    if (!card)
        return;
    
    emv_card_disconnect(card);
}

// Error handling
const char *emv_card_get_error_message(int error_code) {
    switch (error_code) {
        case EMV_OK:
            return "Success";
        case EMV_ERR_CONNECT:
            return "Failed to connect to card or reader";
        case EMV_ERR_SELECT:
            return "Failed to select application";
        case EMV_ERR_GPO:
            return "Failed to get processing options";
        case EMV_ERR_READ:
            return "Failed to read card data";
        case EMV_ERR_DATA:
            return "Required data not found";
        case EMV_ERR_PROTOCOL:
            return "Protocol error";
        default:
            return "Unknown error";
    }
}