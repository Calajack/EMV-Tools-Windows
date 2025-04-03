// emv_defs.h - Common EMV definitions
#ifndef EMV_DEFS_H
#define EMV_DEFS_H

#include <stdint.h>
#include <stdbool.h>
#include "tlv.h"
#include <openssl/types.h>

#define EMV_TAG_YYMMDD EMV_TAG_DATE
#define EMV_TAG_BITMASK 8
#define EMV_TAG_CVM_LIST 9

#ifdef __cplusplus
extern "C" {
#endif

    typedef void (*emv_cvm_callback)(const struct tlv* cvm_data, void* data);
    typedef void (*emv_bitmask_callback)(const char* bit, unsigned bit_nr, int val, void* data);
    typedef void (*emv_dol_callback)(const struct tlv* tlv, void* data);

// Error codes
#define EMV_ERR_OK                0
#define EMV_ERR_INVALID_PARAM    -1
#define EMV_ERR_DATA_MISSING     -2
#define EMV_ERR_INVALID_DATA     -3
#define EMV_ERR_NOT_SUPPORTED    -4
#define EMV_OK 0
#define EMV_ERR_INVALID_FORMAT -5

typedef enum {
    EMV_TAG_GENERIC,
    EMV_TAG_STRING,
    EMV_TAG_NUMERIC,
    EMV_TAG_BINARY,
    EMV_TAG_BCD,
    EMV_TAG_DATE,  // YYMMDD 
    EMV_TAG_DOL,
    EMV_AIP,
    AIP_BITS,
} emv_tag_format_t;

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

#ifdef __cplusplus
}
#endif

#endif // EMV_DEFS_H
