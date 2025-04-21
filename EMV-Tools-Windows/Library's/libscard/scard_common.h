#ifndef SCARD_COMMON_H
#define SCARD_COMMON_H

#include <windows.h>
#include <winscard.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_READERS 10
#define MAX_READERNAME 256

#define OMNIKEY_CTRL_LED     0x42
#define OMNIKEY_LED_OFF      0x00
#define OMNIKEY_LED_GREEN    0x01

    // Define custom attribute code not present in standard winscard.h
#define SCARD_ATTR_VENDOR_IFD_SERIAL_TIMEOUT 0x0A0004

// Error codes (Windows-aligned)
#define SCARD_SUCCESS 0
#define SCARD_ERR_INVALID_PARAM 0x80100004
#define SCARD_ERR_NO_SERVICE 0x8010001D

// APDU constants
#define APDU_MAX_LEN 256
#define SW1SW2_OK 0x9000

// Interface types
    typedef enum {
        SCARD_IFD_AUTO = 0,
        SCARD_IFD_ICC,
        SCARD_IFD_PICC,
        SCARD_IFD_MANUAL
    } SCardInterfaceType;

    // Smart card operation modes
    typedef enum {
        SCARD_MODE_NORMAL = 0,
        SCARD_MODE_EMULATE,
        SCARD_MODE_MANUAL
    } SCardMode;

    // The sc struct that the application code expects
#ifndef SC_STRUCT_DEFINED
#define SC_STRUCT_DEFINED
    typedef struct sc {
        SCARDCONTEXT hContext;
        SCARDHANDLE hCard;
        DWORD dwActiveProtocol;
    } sc;
#endif

    // Emulator context
    typedef struct {
        uint8_t(*emulate_cb)(const uint8_t* apdu, size_t apdu_len,
            uint8_t* resp, size_t* resp_len);
    } SCardEmuContext;

    // Manual context
    typedef struct {
        uint8_t atr[32];
        size_t atr_len;
        uint8_t responses[16][256];
        size_t resp_lens[16];
        size_t resp_count;
        int dummy;
    } SCardManualContext;

    // Reader state
    typedef struct {
        char reader_name[256];
        DWORD state;
        DWORD protocol;
    } SCardReaderState;

    // Context structure
    typedef struct {
        SCARDCONTEXT hContext;
        SCARDHANDLE hCard;
        DWORD dwProtocol;
        uint8_t atr[64];
        size_t atr_len;
    } SCardContext;

    // Function declarations - avoid duplicate/conflicting declarations

    // Function for EMV-Tools_Win.cpp
    SCardContext* scard_establish(DWORD scope);

    // Connect function for SCardContext
    int scard_connect_ctx(SCardContext* ctx, const char* reader, DWORD share_mode);

    // Omnikey LED control
    int scard_omnikey_set_led(SCardContext* ctx, unsigned char state);

    // Simplified PC/SC functions used by tool programs
    LONG scard_establish_context(SCARDCONTEXT* ctx);
    void scard_release_context(SCARDCONTEXT ctx);
    const char* pcsc_stringify_error(LONG code);
    LONG scard_connect(SCARDCONTEXT ctx, const char* reader, SCARDHANDLE* card, DWORD* protocol);
    void scard_disconnect(SCARDHANDLE card, DWORD disposition);
    bool scard_list_readers(SCARDCONTEXT hContext, char readers[][MAX_READERNAME], DWORD* reader_count, size_t max_readers, size_t max_len);

    // SCardContext functions
    int scard_disconnect_ctx(SCardContext* ctx);
    int scard_transmit(SCardContext* ctx, const uint8_t* apdu, size_t apdu_len, uint8_t* resp, size_t* resp_len);
    int scard_transmit_ex(SCardContext* ctx, const uint8_t* apdu, size_t apdu_len, uint8_t* resp, size_t* resp_len, DWORD timeout_ms);
    void scard_free(SCardContext* ctx);

    // EMU mode functions
    int scard_set_mode(SCardMode mode);
    int scard_set_emu_callback(uint8_t(*cb)(const uint8_t*, size_t, uint8_t*, size_t*));

    // Custom timeout function
    int SCardSetTimeout(SCARDHANDLE hCard, DWORD dwTimeout);

#ifdef __cplusplus
}
#endif

#endif /* SCARD_COMMON_H */
