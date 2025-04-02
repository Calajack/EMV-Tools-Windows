/ emv_defs.h - Common EMV definitions
#ifndef EMV_DEFS_H
#define EMV_DEFS_H

#include <stdint.h>
#include <stdbool.h>
#include "tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define EMV_ERR_OK                0
#define EMV_ERR_INVALID_PARAM    -1
#define EMV_ERR_DATA_MISSING     -2
#define EMV_ERR_INVALID_DATA     -3
#define EMV_ERR_NOT_SUPPORTED    -4
#define EMV_OK 0
#define EMV_ERR_INVALID_FORMAT -5

// Tag type definitions
typedef enum {
    EMV_TAG_STRING,
    EMV_TAG_BINARY,
    EMV_TAG_NUMERIC,
    EMV_TAG_BCD,
    EMV_TAG_DATE,
    EMV_TAG_DOL
} emv_tag_type_t;

// CVM (Cardholder Verification Method) definitions
#define EMV_CVM_HEADER 0x3F

// Structure for AIP (Application Interchange Profile) bits
typedef struct {
    const char *name;
    const char *description;
} aip_bit_t;

extern const aip_bit_t aip_bits[];

// Structure for AUC (Application Usage Control) bits
typedef struct {
    const char *name;
    const char *description;
} auc_bit_t;

extern const auc_bit_t auc_bits[];

// Structure for TVR (Terminal Verification Results) bits
typedef struct {
    const char *name;
    const char *description;
} tvr_bit_t;

extern const tvr_bit_t tvr_bits[];

// CVM callback type
typedef void (*emv_cvm_callback)(const struct tlv *cvm_data, void *data);

// Define tlv_t as an alias for struct tlv if needed
typedef struct tlv tlv_t;

int emv_decode_cvm(const unsigned char* ptr, size_t len, emv_cvm_callback cb, void* data);
void emv_tag_decode_bitmask(const unsigned char* buf, size_t len, const void* bits, emv_bitmask_callback callback, void* data);

#ifdef __cplusplus
}
#endif

#endif // EMV_DEFS_H
