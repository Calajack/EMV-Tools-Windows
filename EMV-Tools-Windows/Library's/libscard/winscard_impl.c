#include "scard_common.h"
#include <winscard.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCARD_CHECK(fn, ...) \
    do { \
        LONG __rc = (fn)(__VA_ARGS__); \
        if (__rc != SCARD_S_SUCCESS) { \
            return __rc; \
        } \
    } while(0)

    // Implementation for EMV-Tools_Win.cpp
    SCardContext* scard_establish(DWORD scope) {
        SCardContext* ctx = (SCardContext*)calloc(1, sizeof(SCardContext));
        if (!ctx) return NULL;

        LONG rc = SCardEstablishContext(scope, NULL, NULL, &ctx->hContext);
        if (rc != SCARD_S_SUCCESS) {
            free(ctx);
            return NULL;
        }
        return ctx;
    }

    // Connect implementation for SCardContext
    int scard_connect_ctx(SCardContext* ctx, const char* reader, DWORD share_mode) {
        if (!ctx || !reader) return SCARD_E_INVALID_PARAMETER;

        // Disconnect if there's an existing connection
        if (ctx->hCard) {
            SCardDisconnect(ctx->hCard, SCARD_LEAVE_CARD);
            ctx->hCard = 0;
        }

        // Connect to the card
        LONG rc = SCardConnectA(ctx->hContext, reader, share_mode,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            &ctx->hCard, &ctx->dwProtocol);
        if (rc != SCARD_S_SUCCESS) return rc;

        // Get ATR
        DWORD atr_len = sizeof(ctx->atr);
        CHAR reader_name[MAX_READERNAME];
        DWORD reader_len = sizeof(reader_name);
        DWORD state;

        rc = SCardStatusA(ctx->hCard, reader_name, &reader_len,
            &state, &ctx->dwProtocol, ctx->atr, &atr_len);
        ctx->atr_len = (rc == SCARD_S_SUCCESS) ? atr_len : 0;

        return rc;
    }

    // Low-level implementation used by tools
    LONG scard_establish_context(SCARDCONTEXT* ctx) {
        if (!ctx) return SCARD_E_INVALID_PARAMETER;
        return SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, ctx);
    }

    void scard_release_context(SCARDCONTEXT ctx) {
        if (ctx) {
            SCardReleaseContext(ctx);
        }
    }

    const char* pcsc_stringify_error(LONG code) {
        static char buffer[256];

        switch (code) {
        case SCARD_S_SUCCESS:          return "Success";
        case SCARD_E_CANCELLED:        return "Command was cancelled";
        case SCARD_E_INVALID_HANDLE:   return "Invalid handle";
        case SCARD_E_INVALID_PARAMETER: return "Invalid parameter";
        case SCARD_E_INVALID_VALUE:    return "Invalid value";
        case SCARD_E_NO_MEMORY:        return "No memory";
        case SCARD_E_NO_SERVICE:       return "Smart card resource manager is not running";
        case SCARD_E_NO_SMARTCARD:     return "No smart card inserted";
        case SCARD_E_PROTO_MISMATCH:   return "Protocol mismatch";
        case SCARD_E_READER_UNAVAILABLE: return "Reader is unavailable";
        case SCARD_E_TIMEOUT:          return "Operation timed out";
        case SCARD_E_UNKNOWN_READER:   return "Reader not found";
        default:
            snprintf(buffer, sizeof(buffer), "Unknown error code 0x%lx", code);
            return buffer;
        }
    }

    LONG scard_connect(SCARDCONTEXT ctx, const char* reader, SCARDHANDLE* card, DWORD* protocol) {
        if (!ctx || !reader || !card || !protocol) return SCARD_E_INVALID_PARAMETER;
        return SCardConnectA(ctx, reader, SCARD_SHARE_EXCLUSIVE,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            card, protocol);
    }

    void scard_disconnect(SCARDHANDLE card, DWORD disposition) {
        if (card) {
            SCardDisconnect(card, disposition);
        }
    }

    bool scard_list_readers(SCARDCONTEXT hContext, char readers[][MAX_READERNAME],
        DWORD* reader_count, size_t max_readers, size_t max_len) {
        if (!hContext || !readers || !reader_count || max_readers == 0)
            return false;

        // Get list of readers
        DWORD dwReaders = SCARD_AUTOALLOCATE;
        LPSTR mszReaders = NULL;
        LONG result = SCardListReadersA(hContext, NULL, (LPSTR)&mszReaders, &dwReaders);

        if (result != SCARD_S_SUCCESS) {
            return false;
        }

        // Parse multi-string and copy to array
        DWORD count = 0;
        char* pReader = mszReaders;
        while (*pReader != '\0' && count < max_readers) {
            size_t len = strlen(pReader);
            if (len >= max_len) len = max_len - 1;

            memcpy(readers[count], pReader, len);
            readers[count][len] = '\0';

            count++;
            pReader += len + 1;
        }

        *reader_count = count;
        SCardFreeMemory(hContext, mszReaders);

        return true;
    }

    // Implementation for context-based disconnect
    int scard_disconnect_ctx(SCardContext* ctx) {
        if (!ctx) return SCARD_E_INVALID_PARAMETER;
        if (ctx->hCard == 0) return SCARD_S_SUCCESS;

        LONG rc = SCardDisconnect(ctx->hCard, SCARD_LEAVE_CARD);
        if (rc == SCARD_S_SUCCESS) {
            ctx->hCard = 0;
        }
        return rc;
    }

    // Omnikey LED control implementation
    int scard_omnikey_set_led(SCardContext* ctx, unsigned char state) {
        if (!ctx || ctx->hCard == 0) return SCARD_E_INVALID_PARAMETER;

        // Omnikey control code
        DWORD ioctl = SCARD_CTL_CODE(3500); // Vendor-specific IOCTL

        // LED control data
        unsigned char buffer[2] = { OMNIKEY_CTRL_LED, state };
        DWORD recv_len = 0;

        return SCardControl(ctx->hCard, ioctl, buffer, sizeof(buffer), NULL, 0, &recv_len);
    }

    // APDU transmission implementation
    int scard_transmit(SCardContext* ctx, const uint8_t* apdu, size_t apdu_len,
        uint8_t* resp, size_t* resp_len) {
        if (!ctx || !apdu || !resp || !resp_len || ctx->hCard == 0)
            return SCARD_E_INVALID_PARAMETER;

        SCARD_IO_REQUEST ioReq = { ctx->dwProtocol, sizeof(SCARD_IO_REQUEST) };
        return SCardTransmit(ctx->hCard, &ioReq, apdu, (DWORD)apdu_len,
            NULL, resp, (LPDWORD)resp_len);
    }

    // Extended APDU transmission with timeout
    int scard_transmit_ex(SCardContext* ctx, const uint8_t* apdu, size_t apdu_len,
        uint8_t* resp, size_t* resp_len, DWORD timeout_ms) {
        if (!ctx || !apdu || !resp || !resp_len || ctx->hCard == 0)
            return SCARD_E_INVALID_PARAMETER;

        // Set timeout if supported by reader
        SCardSetTimeout(ctx->hCard, timeout_ms);

        SCARD_IO_REQUEST ioReq = { ctx->dwProtocol, sizeof(SCARD_IO_REQUEST) };
        return SCardTransmit(ctx->hCard, &ioReq, apdu, (DWORD)apdu_len,
            NULL, resp, (LPDWORD)resp_len);
    }

    // Implementation of SCardSetTimeout
    int SCardSetTimeout(SCARDHANDLE hCard, DWORD dwTimeout) {
        return SCardSetAttrib(hCard, SCARD_ATTR_VENDOR_IFD_SERIAL_TIMEOUT,
            (LPCBYTE)&dwTimeout, sizeof(dwTimeout));
    }

    // Free SCardContext resources
    void scard_free(SCardContext* ctx) {
        if (!ctx) return;

        if (ctx->hCard) {
            SCardDisconnect(ctx->hCard, SCARD_LEAVE_CARD);
            ctx->hCard = 0;
        }

        if (ctx->hContext) {
            SCardReleaseContext(ctx->hContext);
            ctx->hContext = 0;
        }

        free(ctx);
    }

    // Static context for EMU and manual modes
    static struct {
        SCardMode mode;
        SCardEmuContext emu;
        SCardManualContext manual;
    } g_scard_ctx;

    int scard_set_mode(SCardMode mode) {
        g_scard_ctx.mode = mode;
        return SCARD_S_SUCCESS;
    }

    int scard_set_emu_callback(uint8_t(*cb)(const uint8_t*, size_t, uint8_t*, size_t*)) {
        if (!cb) return SCARD_E_INVALID_PARAMETER;
        g_scard_ctx.emu.emulate_cb = cb;
        return SCARD_S_SUCCESS;
    }

#ifdef __cplusplus
}
#endif
