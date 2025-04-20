// apdu.h - Should be placed in the libscard directory
#ifndef EMV_APDU_H
#define EMV_APDU_H

#include <stdint.h>
#include <stddef.h>
#include "scard_common.h"

#ifdef __cplusplus
extern "C" {
#endif

   

// APDU command structure
struct apdu_cmd {
    uint8_t cla;      // Class byte
    uint8_t ins;      // Instruction byte
    uint8_t p1;       // Parameter 1
    uint8_t p2;       // Parameter 2
    size_t lc;        // Length of command data
    const uint8_t *data;  // Command data
    uint8_t le;       // Expected response length
};

// APDU response structure
struct apdu_response {
    uint8_t *data;    // Response data
    size_t len;       // Length of response data
    uint16_t sw;      // Status word
};

// Function to free response memory
void apdu_response_free(struct apdu_response *response);

// Function to transmit APDU command
struct apdu_response *sc_transmit_apdu(struct sc *scard, const struct apdu_cmd *cmd);

#ifdef __cplusplus
}
#endif

#endif // EMV_APDU_H
