#include "scard_common.h"
#include <winscard.h>

// Omnikey-specific timeout settings (milliseconds)
#define OMNIKEY_DEFAULT_TIMEOUT 3000

int scard_transmit_ex(SCardContext *ctx, 
                     const uint8_t *apdu, size_t apdu_len,
                     uint8_t *resp, size_t *resp_len,
                     DWORD timeout_ms) {
    if (!ctx) return SCARD_E_INVALID_PARAMETER;
    
    SCARD_IO_REQUEST ioReq = { ctx->dwProtocol, sizeof(SCARD_IO_REQUEST) };
    
    // Omnikey benefit: Supports extended timeouts
    SCardSetTimeout(ctx->hCard, timeout_ms ? timeout_ms : OMNIKEY_DEFAULT_TIMEOUT);
    
    return SCardTransmit(ctx->hCard, &ioReq, apdu, apdu_len, 
                        NULL, resp, (LPDWORD)resp_len);
}

// Omnikey-specific direct control
int scard_omnikey_set_led(SCardContext *ctx, uint8_t led_state) {
    if (!ctx) return SCARD_E_INVALID_PARAMETER;
    
    const uint8_t ctrl_code = 0x42;  // Omnikey LED control
    return SCardControl(ctx->hCard, ctrl_code, 
                       &led_state, 1, NULL, 0, NULL);
}

int SCard_transmit_ex(SCardContext *ctx, SCardManualContext *manual,
    const uint8_t *apdu, size_t apdu_len,
    uint8_t *resp, size_t *resp_len, 
    SCardInterfaceType ifd_type) {
if (ifd_type == SCARD_IFD_MANUAL) {
if (!manual || !manual->resp_count) return SCARD_E_NO_READERS_AVAILABLE;

// Pop from manual response queue
memcpy(resp, manual->responses[0], manual->resp_lens[0]);
*resp_len = manual->resp_lens[0];

// Shift remaining responses up
for (size_t i = 1; i < manual->resp_count; i++) {
memcpy(manual->responses[i-1], manual->responses[i], manual->resp_lens[i]);
manual->resp_lens[i-1] = manual->resp_lens[i];
}
manual->resp_count--;
return SCARD_SUCCESS;
}
else {
// Normal hardware transmission
return scard_transmit(ctx, apdu, apdu_len, resp, resp_len);
}
}
