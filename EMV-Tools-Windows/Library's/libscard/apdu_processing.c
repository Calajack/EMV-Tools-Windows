#include "scard_common.h"
#include "apdu.h"
#include <winscard.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>

// Omnikey-specific timeout settings (milliseconds)
#define OMNIKEY_DEFAULT_TIMEOUT 3000

// Free APDU response memory
void apdu_response_free(struct apdu_response* response) {
    if (response) {
        if (response->data) {
            free(response->data);
        }
        free(response);
    }
}

// Transmit APDU command
struct apdu_response* sc_transmit_apdu(struct sc* scard, const struct apdu_cmd* cmd) {
    if (!scard || !cmd) return NULL;

    // Allocate response
    struct apdu_response* resp = malloc(sizeof(struct apdu_response));
    if (!resp) return NULL;

    // Initialize response
    resp->data = NULL;
    resp->len = 0;
    resp->sw = 0;

    // Build APDU
    uint8_t apdu[APDU_MAX_LEN];
    size_t apdu_len = 0;

    // APDU header
    apdu[apdu_len++] = cmd->cla;
    apdu[apdu_len++] = cmd->ins;
    apdu[apdu_len++] = cmd->p1;
    apdu[apdu_len++] = cmd->p2;

    // APDU data
    if (cmd->data && cmd->lc > 0) {
        // Make sure we don't overflow the buffer or have a size conversion issue
        uint8_t lc = (cmd->lc > 255) ? 255 : (uint8_t)cmd->lc;
        apdu[apdu_len++] = lc;

        if (apdu_len + lc > APDU_MAX_LEN) {
            free(resp);
            return NULL;
        }
        memcpy(apdu + apdu_len, cmd->data, lc);
        apdu_len += lc;
    }

    // Expected response length
    if (cmd->le > 0 || (cmd->data == NULL && cmd->lc == 0)) {
        apdu[apdu_len++] = cmd->le;
    }

    // Allocate response buffer - allow extra room for SW1SW2
    resp->data = malloc(APDU_MAX_LEN);
    if (!resp->data) {
        free(resp);
        return NULL;
    }

    // Transmit APDU
    DWORD resp_len = APDU_MAX_LEN;
    SCARD_IO_REQUEST ioReq = { scard->dwActiveProtocol, sizeof(SCARD_IO_REQUEST) };

    LONG result = SCardTransmit(scard->hCard, &ioReq, apdu, (DWORD)apdu_len,
        NULL, resp->data, &resp_len);

    if (result != SCARD_S_SUCCESS || resp_len < 2) {
        apdu_response_free(resp);
        return NULL;
    }

    // Extract status word
    resp->len = resp_len - 2;
    resp->sw = (resp->data[resp_len - 2] << 8) | resp->data[resp_len - 1];

    // Adjust data to exclude SW1SW2
    if (resp->len > 0) {
        // Reallocate to exact size
        uint8_t* new_data = malloc(resp->len);
        if (!new_data) {
            apdu_response_free(resp);
            return NULL;
        }
        memcpy(new_data, resp->data, resp->len);
        free(resp->data);
        resp->data = new_data;
    }
    else {
        free(resp->data);
        resp->data = NULL;
    }

    return resp;
}

// The function as referenced in the build errors - delegates to our defined function in winscard_impl.c
// This implementation uses an extern declaration to avoid duplication
extern int SCardSetTimeout(SCARDHANDLE hCard, DWORD dwTimeout);

// Support function for manual mode feeds
void manual_feed_response(const uint8_t* rsp, size_t len) {
    // Implementation would store data for manual mode
    // This is a stub to satisfy linking requirements
}
