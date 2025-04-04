#ifndef EMV_TAGS_H
#define EMV_TAGS_H

#include <stdint.h>
#include "emv_defs.h"

typedef struct emv_tag_info_t {
    uint16_t tag;
    const char* name;
    const char* type;
    const char* description;
} emv_tag_info_t;

#ifdef __cplusplus
extern "C" {
#endif

    // Publicly exposed tags (used in APIs)
#define EMV_TAG_PAN            0x5A     // Primary Account Number
#define EMV_TAG_EXPIRY         0x5F24   // Expiration Date
#define EMV_TAG_AID            0x4F     // Application Identifier
#define EMV_TAG_PDOL           0x9F38   // Processing Options Data Object List
#define EMV_TAG_CDOL1          0x8C     // Card Risk Management Data Object List 1
#define EMV_TAG_DDOL           0x9F49   // Dynamic Data Authentication Data Object List 

// Tag information structure - this appears to be an incomplete struct
// If not needed, you can remove it
    typedef struct {
        uint16_t tag;
        const char* name;
        const char* description;
        size_t min_len;
        size_t max_len;
    } emv_tag_length_info_t;  // Added a name to make it complete

    typedef struct {
        uint16_t tag;
        const char* name;
        const char* type;
        const char* description;
        emv_tag_format_t format;  // Changed from pointer to direct type
        const uint8_t* bitmask;
    } emv_tag_def_t;

    // Function declarations
    const emv_tag_info_t* emv_tag_get_info(uint16_t tag);
    int emv_tag_is_constructed(uint16_t tag);

    // External declarations
    extern const char* tvr_bits[5][8];
    extern const struct emv_tag_def tag_database[];
    extern const struct emv_tag_def emv_tags[];
    extern const char* const tvr_bits[8][5];

#ifdef __cplusplus
}
#endif

#endif // EMV_TAGS_H
