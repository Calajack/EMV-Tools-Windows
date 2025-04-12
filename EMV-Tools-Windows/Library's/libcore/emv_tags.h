#ifndef EMV_TAGS_H
#define EMV_TAGS_H
#include <stdint.h>
#include "emv_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

    // Tag information structure for public API
    typedef struct emv_tag_info_t {
        uint16_t tag;
        const char* name;
        const char* type;
        const char* description;
    } emv_tag_info_t;

    // Full tag definition structure for internal use
    typedef struct emv_tag_def_t {
        uint16_t tag;
        const char* name;
        emv_tag_format_t format;  // This is defined in emv_defs.h
        const emv_bitmask_t* bitmask;
        const char* description;  // Added this field
    } emv_tag_def_t;

    // Publicly exposed tags (used in APIs)
#define EMV_TAG_PAN            0x5A     // Primary Account Number
#define EMV_TAG_EXPIRY         0x5F24   // Expiration Date
#define EMV_TAG_AID            0x4F     // Application Identifier
#define EMV_TAG_PDOL           0x9F38   // Processing Options Data Object List
#define EMV_TAG_CDOL1          0x8C     // Card Risk Management Data Object List 1
#define EMV_TAG_DDOL           0x9F49   // Dynamic Data Authentication Data Object List 

// Function declarations
    const emv_tag_info_t* emv_tag_get_info(uint16_t tag);
    int emv_tag_is_constructed(uint16_t tag);
    void emv_tags_init(void);

    // External declarations
    extern const emv_tag_def_t tag_database[];

#ifdef __cplusplus
}
#endif

#endif // EMV_TAGS_H
