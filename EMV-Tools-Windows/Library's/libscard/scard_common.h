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

// Emulator context
typedef struct {
    uint8_t (*emulate_cb)(const uint8_t *apdu, size_t apdu_len, 
                         uint8_t *resp, size_t *resp_len);
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

// Bridge structure used in the application code
typedef struct {
    SCARDCONTEXT hContext;
    SCARDHANDLE hCard;
    DWORD dwActiveProtocol;
} sc;

// Function declarations - this matches what the applications expect
int scard_omnikey_set_led(SCARDCONTEXT* ctx, unsigned char* state);

// EMV tool PC/SC compatibility functions
int scard_establish_context(sc **out);
int scard_release_context(sc *sc_ctx);
int scard_list_readers(sc *sc_ctx, char readers[][256], DWORD *readers_len);
int scard_connect(sc *sc_ctx, const char *reader, DWORD share_mode, DWORD *active_protocol);
int scard_disconnect(sc *sc_ctx);
int scard_transmit(sc *sc_ctx, const unsigned char *send_buf, size_t send_len, 
                  unsigned char *recv_buf, size_t *recv_len);

// EMU mode functions
int scard_set_mode(SCardMode mode);
int scard_set_emu_callback(uint8_t(*cb)(const uint8_t*, size_t, uint8_t*, size_t*));

#ifdef __cplusplus
}
#endif

#endif /* SCARD_COMMON_H */
