// emv_defs.h - Common EMV definitions
#ifndef EMV_DEFS_H
#define EMV_DEFS_H

#include <stdint.h>
#include <stdbool.h>
#include "tlv.h"
#include <openssl/types.h>

#define EMV_TAG_CVM_LIST 9

#ifdef __cplusplus
extern "C" {
#endif

    // Forward declarations
    struct tlv;

    // Structure for bitmasks used in EMV
    typedef struct emv_bitmask_t {
        uint16_t bit;
        const char* name;
    } emv_bitmask_t;

    // Callback types
    typedef void (*emv_cvm_callback)(void* userdata, uint8_t method, uint8_t condition, bool continue_if_fail);
    typedef bool (*emv_bitmask_callback)(void* userdata, uint16_t bit, const char* name);
    typedef bool (*emv_dol_callback)(void* userdata, const struct tlv* tlv);

    // Error codes
#define EMV_ERR_OK                0
#define EMV_ERR_INVALID_PARAM    -1
#define EMV_ERR_DATA_MISSING     -2
#define EMV_ERR_INVALID_DATA     -3
#define EMV_ERR_NOT_SUPPORTED    -4
#define EMV_OK 0
#define EMV_ERR_INVALID_FORMAT -5

// Tag format enumeration
    typedef enum {
        EMV_TAG_GENERIC,
        EMV_TAG_STRING,
        EMV_TAG_NUMERIC,
        EMV_TAG_BINARY,
        EMV_TAG_BCD,
        EMV_TAG_DATE,  // YYMMDD 
        EMV_TAG_DOL,
        EMV_TAG_BITMASK
    } emv_tag_format_t;

    // TLV type
    typedef enum {
        TLV_PRIMITIVE = 0,
        TLV_CONSTRUCTED = 1
    } tlv_type_t;

    // CVM (Cardholder Verification Method) definitions
#define EMV_CVM_HEADER 0x3F

// External declarations - these will be defined in emv_tags.c
    // Structure for AIP (Application Interchange Profile) bits
    typedef struct {
        const char* name;
        const char* description;
    } aip_bit_t;

    // Structure for AUC (Application Usage Control) bits
    typedef struct {
        const char* name;
        const char* description;
    } auc_bit_t;

    // Structure for TVR (Terminal Verification Results) bits
    typedef struct {
        const char* name;
        const char* description;
    } tvr_bit_t;

    // External declarations
    extern const aip_bit_t aip_bits[];
    extern const auc_bit_t auc_bits[];
    extern const tvr_bit_t tvr_bits[];

    // Define tlv_t as an alias for struct tlv if needed
    typedef struct tlv tlv_t;

#ifdef __cplusplus
}
#endif

#endif // EMV_DEFS_H
