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
        SCARD_MODE_MANUAL,
        SCARD_MODE_EMU
    } SCardMode;

    // Context for EMU mode
    typedef struct {
        uint8_t(*emulate_cb)(const uint8_t* apdu, size_t apdu_len, uint8_t* resp, size_t* resp_len);
    } SCardEmuContext;

    // Context for MANUAL mode (define fields as needed)
    typedef struct {
        // Placeholder for manual mode state
        int dummy;
    } SCardManualContext;

    // Unified context structure
    typedef struct {
        SCARDCONTEXT hContext;
        SCARDHANDLE hCard;
        DWORD dwProtocol;
        uint8_t atr[64];
        size_t atr_len;
    } SCardContext;

    // Reader state (you may have this already)
    typedef struct {
        char reader_name[256];
        DWORD state;
        DWORD protocol;
    } SCardReaderState;

    // Function declarations
    SCardContext* scard_establish(DWORD scope);
    int scard_connect(SCardContext* ctx, LPCSTR reader, DWORD share_mode, DWORD preferred_protocols);
    int scard_disconnect(SCardContext* ctx);
    int scard_reconnect(SCardContext* ctx, DWORD share_mode, DWORD preferred_protocols, DWORD initialization);
    int scard_list_readers(SCardContext* ctx, SCardReaderState* readers, size_t* count);
    int scard_transmit(SCardContext* ctx, const uint8_t* apdu, size_t apdu_len, uint8_t* resp, size_t* resp_len);
    int scard_begin_transaction(SCardContext* ctx);
    int scard_end_transaction(SCardContext* ctx, DWORD disposition);
    void scard_free(SCardContext* ctx);

    // Emulator and mode functions
    int scard_set_mode(SCardMode mode);
    int scard_set_emu_callback(uint8_t(*cb)(const uint8_t*, size_t, uint8_t*, size_t*));

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

typedef enum {
    SCARD_MODE_NORMAL = 0,
    SCARD_MODE_EMULATE,
    SCARD_MODE_MANUAL
} SCardMode;

typedef struct {
    uint8_t (*emulate_cb)(const uint8_t *apdu, size_t apdu_len, 
                         uint8_t *resp, size_t *resp_len);
} SCardEmuContext;

#ifdef __cplusplus
}
#endif
