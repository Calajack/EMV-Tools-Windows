#include "scard_common.h"
#include <winscard.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <stdio.h>

#define SCARD_CHECK(fn, ...) \
    do { \
        LONG __rc = (fn)(__VA_ARGS__); \
        if (__rc != SCARD_S_SUCCESS) { \
            return __rc; \
        } \
    } while(0)

SCardContext* scard_establish(DWORD scope) {
    SCardContext *ctx = calloc(1, sizeof(SCardContext));
    if (!ctx) return NULL;

    LONG rc = SCardEstablishContext(scope, NULL, NULL, &ctx->hContext);
    if (rc != SCARD_S_SUCCESS) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

int scard_connect(SCardContext *ctx, LPCSTR reader, DWORD share_mode, DWORD preferred_protocols) {
    if (!ctx || !reader) return SCARD_E_INVALID_PARAMETER;

    SCardDisconnect(ctx->hCard, SCARD_LEAVE_CARD);
    ctx->hCard = 0;

    LONG rc = SCardConnect(ctx->hContext, reader, share_mode, 
                          preferred_protocols, &ctx->hCard, &ctx->dwProtocol);
    if (rc != SCARD_S_SUCCESS) return rc;

    // Get ATR
    DWORD atr_len = sizeof(ctx->atr);
    rc = SCardStatus(ctx->hCard, NULL, NULL, NULL, NULL, ctx->atr, &atr_len);
    ctx->atr_len = (rc == SCARD_S_SUCCESS) ? atr_len : 0;

    return rc;
}

int scard_disconnect(SCardContext *ctx) {
    if (!ctx) return SCARD_E_INVALID_PARAMETER;
    if (ctx->hCard == 0) return SCARD_S_SUCCESS;
    
    LONG rc = SCardDisconnect(ctx->hCard, SCARD_LEAVE_CARD);
    ctx->hCard = 0;
    return rc;
}

int scard_reconnect(SCardContext *ctx, DWORD share_mode, DWORD preferred_protocols, DWORD initialization) {
    if (!ctx) return SCARD_E_INVALID_PARAMETER;
    return SCardReconnect(ctx->hCard, share_mode, preferred_protocols, initialization, &ctx->dwProtocol);
}

int scard_list_readers(SCardContext *ctx, SCardReaderState *readers, size_t *count) {
    if (!ctx || !readers || !count || *count == 0) 
        return SCARD_E_INVALID_PARAMETER;

    LPSTR mszReaders = NULL;
    DWORD cchReaders = SCARD_AUTOALLOCATE;
    LONG rc = SCardListReaders(ctx->hContext, NULL, (LPSTR)&mszReaders, &cchReaders);
    if (rc != SCARD_S_SUCCESS) return rc;

    size_t i = 0;
    char *p = mszReaders;
    while (*p && i < *count) {
        strncpy(readers[i].reader_name, p, sizeof(readers[0].reader_name)-1);
        readers[i].reader_name[sizeof(readers[0].reader_name)-1] = '\0';
        
        // Get reader state
        SCARD_READERSTATE state = {0};
        state.szReader = p;
        state.dwCurrentState = SCARD_STATE_UNAWARE;
        SCardGetStatusChange(ctx->hContext, 0, &state, 1);
        
        readers[i].state = state.dwEventState;
        readers[i].protocol = (state.dwEventState & SCARD_STATE_PRESENT) ? 
                             ctx->dwProtocol : 0;
        
        p += strlen(p) + 1;
        i++;
    }
    
    SCardFreeMemory(ctx->hContext, mszReaders);
    *count = i;
    return SCARD_S_SUCCESS;
}

int scard_transmit(SCardContext *ctx, const uint8_t *apdu, size_t apdu_len, 
                  uint8_t *resp, size_t *resp_len) {
    if (!ctx || !apdu || !resp || !resp_len) 
        return SCARD_E_INVALID_PARAMETER;

    SCARD_IO_REQUEST ioReq = { ctx->dwProtocol, sizeof(SCARD_IO_REQUEST) };
    return SCardTransmit(ctx->hCard, &ioReq, apdu, apdu_len, NULL, resp, (LPDWORD)resp_len);
}

int scard_begin_transaction(SCardContext *ctx) {
    if (!ctx) return SCARD_E_INVALID_PARAMETER;
    return SCardBeginTransaction(ctx->hCard);
}

int scard_end_transaction(SCardContext *ctx, DWORD disposition) {
    if (!ctx) return SCARD_E_INVALID_PARAMETER;
    return SCardEndTransaction(ctx->hCard, disposition);
}

void scard_free(SCardContext *ctx) {
    if (!ctx) return;
    
    if (ctx->hContext) {
        SCardReleaseContext(ctx->hContext);
        ctx->hContext = 0;
    }
    free(ctx);
}

static struct {
    SCardMode mode;
    SCardEmuContext emu;
    SCardManualContext manual;
} g_scard_ctx;

int scard_set_mode(SCardMode mode) {
    g_scard_ctx.mode = mode;
    return SCARD_S_SUCCESS;
}

int scard_set_emu_callback(uint8_t (*cb)(const uint8_t*, size_t, uint8_t*, size_t*)) {
    if (!cb) return SCARD_E_INVALID_PARAMETER;
    g_scard_ctx.emu.emulate_cb = cb;
    return SCARD_S_SUCCESS;
}
