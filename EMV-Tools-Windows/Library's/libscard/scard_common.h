#pragma once
#ifndef SCARD_COMMON_H
#define SCARD_COMMON_H
#endif
#include <windows.h>
#include <winscard.h>
#include <stdint.h>  // For uint8_t, already defined here
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif

#define MAX_READERS 10
#define MAX_READERNAME 256

#define OMNIKEY_CTRL_LED     0x42
#define OMNIKEY_LED_OFF      0x00
#define OMNIKEY_LED_GREEN    0x01

    int scard_omnikey_set_led(SCARDCONTEXT* ctx, unsigned char* state);

// Error codes (Windows-aligned)
#define SCARD_SUCCESS 0
#define SCARD_ERR_INVALID_PARAM 0x80100004
#define SCARD_ERR_NO_SERVICE 0x8010001D

// APDU constants
#define APDU_MAX_LEN 256
#define SW1SW2_OK 0x9000

typedef enum {
    SCARD_IFD_AUTO = 0,    // Automatic detection
    SCARD_IFD_ICC,         // Chip (contact)
    SCARD_IFD_PICC,        // Contactless
    SCARD_IFD_MANUAL       // Manual entry mode
} SCardInterfaceType;

// Reader state structure
typedef struct {
    char reader_name[128];
    DWORD state;
    DWORD protocol;
} SCardReaderState;

// Manual input structure
typedef struct {
    uint8_t atr[32];
    size_t atr_len;
    uint8_t responses[16][256]; // Queue for manual responses
    size_t resp_lens[16];
    size_t resp_count;
} SCardManualContext;

typedef struct {
    SCARDCONTEXT hContext;
    SCARDHANDLE hCard;
    DWORD dwProtocol;
    uint8_t atr[32];
    size_t atr_len;
} SCardContext;

#ifdef __cplusplus
}
#endif

typedef enum {
    SCARD_MODE_NORMAL = 0,
    SCARD_MODE_EMULATE,
    SCARD_MODE_MANUAL
} SCardMode;

typedef struct {
    uint8_t (*emulate_cb)(const uint8_t *apdu, size_t apdu_len, 
                         uint8_t *resp, size_t *resp_len);
} SCardEmuContext;
