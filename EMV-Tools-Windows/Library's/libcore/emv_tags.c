#include "emv_tags.h"
#include "emv_defs.h"
#include "tlv.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h> // For SecureZeroMemory
#include <wincrypt.h>  // For DPAPI
#include <time.h>      // For struct tm
#include <assert.h>

#define EMV_AUC 0x9F07
#define EMV_TVR 0x95
#define CACHE_SIZE 256

// Import intrinsic for CRC32
#ifdef _MSC_VER
#include <intrin.h>
#pragma intrinsic(_mm_crc32_u16)
#else
// Fallback implementation for non-MSVC compilers
static uint32_t _mm_crc32_u16(uint32_t crc, uint16_t data) {
    crc = crc ^ data;
    for (int i = 0; i < 16; i++) {
        crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return crc;
}
#endif

// Bitmask definitions
#define EMV_BIT(byte, bit) ((byte - 1) * 8 + (8 - bit))
#define BITMASK_TERMINATOR {0xFFFF, NULL}

// Define the emv_bitmask_t structures that are actually used by tag_database
// These are separate from the ones declared in emv_defs.h

// Terminal Verification Results (TVR) bits for internal use
const emv_bitmask_t tvr_bitmask[] = {
    {EMV_BIT(1, 8), "Offline data authentication not performed"},
    {EMV_BIT(1, 7), "SDA failed"},
    {EMV_BIT(1, 6), "ICC data missing"},
    {EMV_BIT(1, 5), "Card appears on terminal exception file"},
    {EMV_BIT(1, 4), "DDA failed"},
    {EMV_BIT(1, 3), "CDA failed"},
    {EMV_BIT(1, 2), "SDA selected"},
    {EMV_BIT(2, 8), "ICC and terminal have different application versions"},
    {EMV_BIT(2, 7), "Expired application"},
    {EMV_BIT(2, 6), "Application not yet effective"},
    {EMV_BIT(2, 5), "Requested service not allowed for card product"},
    {EMV_BIT(2, 4), "New card"},
    {EMV_BIT(3, 8), "Cardholder verification was not successful"},
    {EMV_BIT(3, 7), "Unrecognised CVM"},
    {EMV_BIT(3, 6), "PIN Try Limit exceeded"},
    {EMV_BIT(3, 5), "PIN entry required and PIN pad not present or not working"},
    {EMV_BIT(3, 4), "PIN entry required, PIN pad present, but PIN was not entered"},
    {EMV_BIT(3, 3), "Online PIN entered"},
    {EMV_BIT(4, 8), "Transaction exceeds floor limit"},
    {EMV_BIT(4, 7), "Lower consecutive offline limit exceeded"},
    {EMV_BIT(4, 6), "Upper consecutive offline limit exceeded"},
    {EMV_BIT(4, 5), "Transaction selected randomly for online processing"},
    {EMV_BIT(4, 4), "Merchant forced transaction online"},
    {EMV_BIT(5, 8), "Default TDOL used"},
    {EMV_BIT(5, 7), "Issuer authentication failed"},
    {EMV_BIT(5, 6), "Script processing failed before final GENERATE AC"},
    {EMV_BIT(5, 5), "Script processing failed after final GENERATE AC"},
    {EMV_BIT(5, 4), "Reserved for use by the EMV Contactless Specifications"},
    {EMV_BIT(5, 3), "Reserved for use by the EMV Contactless Specifications"},
    {EMV_BIT(5, 2), "Reserved for use by the EMV Contactless Specifications"},
    {EMV_BIT(5, 1), "Reserved for use by the EMV Contactless Specifications"},
    BITMASK_TERMINATOR
};

// AIP (Application Interchange Profile) bits for internal use
const emv_bitmask_t aip_bitmask[] = {
    {1, "CDA Supported"},
    {2, "Issuer Authentication is supported"},
    {3, "Terminal risk management is to be performed"},
    {4, "Cardholder verification is supported"},
    {5, "DDA supported"},
    {6, "SDA supported"},
    BITMASK_TERMINATOR
};

// AUC (Application Usage Control) bits for internal use
const emv_bitmask_t auc_bitmask[] = {
    {1, "Valid for domestic cash transactions"},
    {2, "Valid for international cash transactions"},
    {3, "Valid for domestic goods"},
    {4, "Valid for international goods"},
    {5, "Valid for domestic services"},
    {6, "Valid for international services"},
    {7, "Valid at ATMs"},
    {8, "Valid at terminals other than ATMs"},
    {9, "Domestic cashback allowed"},
    {10, "International cashback allowed"},
    BITMASK_TERMINATOR
};

// Tag database
const emv_tag_def_t tag_database[] = {
    // Core EMV tags (partial list - would include all 200+ tags)
    // Format: {tag, name, format, bitmask, description}
    {0x4F, "Application Identifier", EMV_TAG_BINARY, NULL, "The application identifier for the card application"},
    {0x50, "Application Label", EMV_TAG_STRING, NULL, "The label for the card application"},
    {0x56, "Track 1 Data", EMV_TAG_BINARY, NULL, "Track 1 Data"},
    {0x57, "Track 2 Equivalent Data", EMV_TAG_BINARY, NULL, "Track 2 Equivalent Data"},
    {0x5A, "PAN", EMV_TAG_BINARY, NULL, "Primary Account Number"},
    {0x5F20, "Cardholder Name", EMV_TAG_STRING, NULL, "Cardholder Name"},
    {0x5F24, "Expiration Date", EMV_TAG_DATE, NULL, "Card Expiration Date"},
    {0x5f25, "Application Effective Date", EMV_TAG_DATE, NULL, "Application Effective Date"},
    {0x5f28, "Issuer Country Code", EMV_TAG_NUMERIC, NULL, "Issuer Country Code"},
    {0x5f2a, "Transaction Currency Code", EMV_TAG_NUMERIC, NULL, "Transaction Currency Code"},
    {0x5f2d, "Language Preference", EMV_TAG_STRING, NULL, "Language Preference"},
    {0x5f30, "Service Code", EMV_TAG_NUMERIC, NULL, "Service Code"},
    {0x5f34, "Application Primary Account Number (PAN) Sequence Number", EMV_TAG_NUMERIC, NULL, "PAN Sequence Number"},
    {0x61, "Application Template", EMV_TAG_GENERIC, NULL, "Application Template"},
    {0x6f, "File Control Information (FCI) Template", EMV_TAG_GENERIC, NULL, "FCI Template"},
    {0x70, "READ RECORD Response Message Template", EMV_TAG_GENERIC, NULL, "READ RECORD Response Template"},
    {0x77, "Response Message Template Format 2", EMV_TAG_GENERIC, NULL, "Response Message Template Format 2"},
    {0x80, "Response Message Template Format 1", EMV_TAG_GENERIC, NULL, "Response Message Template Format 1"},
    {0x82, "Application Interchange Profile", EMV_TAG_BITMASK, aip_bitmask, "Application Interchange Profile"},
    {0x83, "Command Template", EMV_TAG_GENERIC, NULL, "Command Template"},
    {0x84, "Dedicated File (DF) Name", EMV_TAG_GENERIC, NULL, "DF Name"},
    {0x87, "Application Priority Indicator", EMV_TAG_GENERIC, NULL, "Application Priority Indicator"},
    {0x88, "Short File Identifier (SFI)", EMV_TAG_GENERIC, NULL, "SFI"},
    {0x8a, "Authorisation Response Code", EMV_TAG_GENERIC, NULL, "Authorisation Response Code"},
    {0x8c, "Card Risk Management Data Object List 1 (CDOL1)", EMV_TAG_DOL, NULL, "CDOL1"},
    {0x8d, "Card Risk Management Data Object List 2 (CDOL2)", EMV_TAG_DOL, NULL, "CDOL2"},
    {0x8e, "Cardholder Verification Method (CVM) List", EMV_TAG_GENERIC, NULL, "CVM List"},
    {0x8f, "Certification Authority Public Key Index", EMV_TAG_GENERIC, NULL, "CA Public Key Index"},
    {0x90, "Issuer Public Key Certificate", EMV_TAG_GENERIC, NULL, "Issuer Public Key Certificate"},
    {0x91, "Issuer Authentication Data", EMV_TAG_GENERIC, NULL, "Issuer Authentication Data"},
    {0x92, "Issuer Public Key Remainder", EMV_TAG_GENERIC, NULL, "Issuer Public Key Remainder"},
    {0x93, "Signed Static Application Data", EMV_TAG_GENERIC, NULL, "Signed Static Application Data"},
    {0x94, "Application File Locator (AFL)", EMV_TAG_GENERIC, NULL, "AFL"},
    {0x95, "Terminal Verification Results", EMV_TAG_BITMASK, tvr_bitmask, "TVR"},
    {0x9a, "Transaction Date", EMV_TAG_DATE, NULL, "Transaction Date"},
    {0x9c, "Transaction Type", EMV_TAG_GENERIC, NULL, "Transaction Type"},
    {0x9f02, "Amount, Authorised (Numeric)", EMV_TAG_NUMERIC, NULL, "Amount, Authorised"},
    {0x9f03, "Amount, Other (Numeric)", EMV_TAG_NUMERIC, NULL, "Amount, Other"},
    {0x9f07, "Application Usage Control", EMV_TAG_BITMASK, auc_bitmask, "Application Usage Control"},
    {0x9f08, "Application Version Number", EMV_TAG_GENERIC, NULL, "Application Version Number"},
    {0x9f0d, "Issuer Action Code - Default", EMV_TAG_BITMASK, tvr_bitmask, "IAC Default"},
    {0x9f0e, "Issuer Action Code - Denial", EMV_TAG_BITMASK, tvr_bitmask, "IAC Denial"},
    {0x9f0f, "Issuer Action Code - Online", EMV_TAG_BITMASK, tvr_bitmask, "IAC Online"},
    {0x9f10, "Issuer Application Data", EMV_TAG_GENERIC, NULL, "Issuer Application Data"},
    {0x9f11, "Issuer Code Table Index", EMV_TAG_NUMERIC, NULL, "Issuer Code Table Index"},
    {0x9f12, "Application Preferred Name", EMV_TAG_STRING, NULL, "Application Preferred Name"},
    {0x9f13, "Last Online Application Transaction Counter (ATC) Register", EMV_TAG_GENERIC, NULL, "Last Online ATC Register"},
    {0x9f17, "Personal Identification Number (PIN) Try Counter", EMV_TAG_GENERIC, NULL, "PIN Try Counter"},
    {0x9f1a, "Terminal Country Code", EMV_TAG_GENERIC, NULL, "Terminal Country Code"},
    {0x9f1f, "Track 1 Discretionary Data", EMV_TAG_STRING, NULL, "Track 1 Discretionary Data"},
    {0x9f21, "Transaction Time", EMV_TAG_GENERIC, NULL, "Transaction Time"},
    {0x9f26, "Application Cryptogram", EMV_TAG_GENERIC, NULL, "Application Cryptogram"},
    {0x9f27, "Cryptogram Information Data", EMV_TAG_GENERIC, NULL, "Cryptogram Information Data"},
    {0x9f2d, "ICC PIN Encipherment Public Key Certificate", EMV_TAG_GENERIC, NULL, "ICC PIN Encipherment Public Key Certificate"},
    {0x9f2e, "ICC PIN Encipherment Public Key Exponent", EMV_TAG_GENERIC, NULL, "ICC PIN Encipherment Public Key Exponent"},
    {0x9f2f, "ICC PIN Encipherment Public Key Remainder", EMV_TAG_GENERIC, NULL, "ICC PIN Encipherment Public Key Remainder"},
    {0x9f32, "Issuer Public Key Exponent", EMV_TAG_GENERIC, NULL, "Issuer Public Key Exponent"},
    {0x9f34, "Cardholder Verification Method (CVM) Results", EMV_TAG_GENERIC, NULL, "CVM Results"},
    {0x9f35, "Terminal Type", EMV_TAG_GENERIC, NULL, "Terminal Type"},
    {0x9f36, "Application Transaction Counter (ATC)", EMV_TAG_GENERIC, NULL, "ATC"},
    {0x9f37, "Unpredictable Number", EMV_TAG_GENERIC, NULL, "Unpredictable Number"},
    {0x9f38, "Processing Options Data Object List (PDOL)", EMV_TAG_DOL, NULL, "PDOL"},
    {0x9f42, "Application Currency Code", EMV_TAG_NUMERIC, NULL, "Application Currency Code"},
    {0x9f44, "Application Currency Exponent", EMV_TAG_NUMERIC, NULL, "Application Currency Exponent"},
    {0x9f45, "Data Authentication Code", EMV_TAG_GENERIC, NULL, "Data Authentication Code"},
    {0x9F46, "ICC Public Key Certificate", EMV_TAG_BINARY, NULL, "ICC Public Key Certificate"},
    {0x9f47, "ICC Public Key Exponent", EMV_TAG_GENERIC, NULL, "ICC Public Key Exponent"},
    {0x9f48, "ICC Public Key Remainder", EMV_TAG_GENERIC, NULL, "ICC Public Key Remainder"},
    {0x9f49, "Dynamic Data Authentication Data Object List (DDOL)", EMV_TAG_DOL, NULL, "DDOL"},
    {0x9f4a, "Static Data Authentication Tag List", EMV_TAG_GENERIC, NULL, "Static Data Authentication Tag List"},
    {0x9f4b, "Signed Dynamic Application Data", EMV_TAG_GENERIC, NULL, "Signed Dynamic Application Data"},
    {0x9f4c, "ICC Dynamic Number", EMV_TAG_GENERIC, NULL, "ICC Dynamic Number"},
    {0x9f4d, "Log Entry", EMV_TAG_GENERIC, NULL, "Log Entry"},
    {0x9f4f, "Log Format", EMV_TAG_DOL, NULL, "Log Format"},
    {0xFFFF, NULL, EMV_TAG_GENERIC, NULL, NULL}
};

// Tag cache
static struct {
    tlv_tag_t tag;
    const emv_tag_info_t* info;
} tag_cache[CACHE_SIZE];

// Missing implementation from header
int emv_tag_is_constructed(uint16_t tag) {
    // EMV tags with bit 6 set in the first byte are constructed
    return (tag & 0x20) == 0x20;
}

// Binary search helper
static int compare_tags(const void* a, const void* b) {
    uint16_t tag1 = *(const uint16_t*)a;
    uint16_t tag2 = ((const emv_tag_def_t*)b)->tag;
    return (tag1 > tag2) - (tag1 < tag2);
}

// Get tag information from database
const emv_tag_info_t* emv_tag_get_info(uint16_t tag) {
    const emv_tag_def_t* found = bsearch(&tag, tag_database,
        sizeof(tag_database) / sizeof(tag_database[0]) - 1,
        sizeof(tag_database[0]), compare_tags);

    static emv_tag_info_t info;
    if (found) {
        info.tag = found->tag;
        info.name = found->name;
        info.type = found->format == EMV_TAG_GENERIC ? "Generic" :
            found->format == EMV_TAG_STRING ? "String" :
            found->format == EMV_TAG_NUMERIC ? "Numeric" :
            found->format == EMV_TAG_BINARY ? "Binary" :
            found->format == EMV_TAG_DATE ? "Date" :
            found->format == EMV_TAG_DOL ? "DOL" :
            found->format == EMV_TAG_BITMASK ? "Bitmask" : "Unknown";
        info.description = found->description;
        return &info;
    }
    return NULL;
}

// Helper functions for TLV module
const char* emv_tag_get_name(uint32_t tag) {
    const emv_tag_info_t* info = emv_tag_get_info(tag);
    return info ? info->name : "Unknown";
}

const char* emv_tag_get_description(uint32_t tag) {
    const emv_tag_info_t* info = emv_tag_get_info(tag); 
    return info ? info->description : NULL;
}

// Debug validation
#ifdef _DEBUG
static void validate_tags() {
    assert(tag_database[0].tag == 0x4F);
    assert(tag_database[sizeof(tag_database) / sizeof(tag_database[0]) - 1].tag == 0xFFFF);
    // Verify no duplicates
    for (size_t i = 0; i < sizeof(tag_database) / sizeof(tag_database[0]) - 1; i++) {
        assert(tag_database[i].tag < tag_database[i + 1].tag);
    }
}
#endif

// Format binary data to hexadecimal string
static char* format_binary(const uint8_t* data, size_t len) {
    if (!data || len == 0)
        return NULL;

    char* result = (char*)malloc(len * 3 + 1);
    if (!result)
        return NULL;

    for (size_t i = 0; i < len; i++) {
        sprintf(result + (i * 3), "%02X ", data[i]);
    }
    result[len * 3 - 1] = '\0'; // Remove trailing space

    return result;
}

// CVM (Cardholder Verification Method) handling
typedef struct {
    uint8_t method;
    uint8_t condition;
    bool continue_if_fail;
} emv_cvm_rule_t;

typedef struct {
    uint32_t x;
    uint32_t y;
    size_t num_rules;
    emv_cvm_rule_t rules[];
} emv_cvm_list_t;

static emv_cvm_list_t* emv_parse_cvm_list(const tlv_t* cvm_tlv) {
    if (!cvm_tlv || cvm_tlv->len < 8 || (cvm_tlv->len - 8) % 2 != 0)
        return NULL;

    size_t num_rules = (cvm_tlv->len - 8) / 2;
    emv_cvm_list_t* list = (emv_cvm_list_t*)malloc(sizeof(emv_cvm_list_t) +
        num_rules * sizeof(emv_cvm_rule_t));
    if (!list)
        return NULL;

    // Extract X and Y values
    list->x = (cvm_tlv->value[0] << 24) | (cvm_tlv->value[1] << 16) |
        (cvm_tlv->value[2] << 8) | cvm_tlv->value[3];
    list->y = (cvm_tlv->value[4] << 24) | (cvm_tlv->value[5] << 16) |
        (cvm_tlv->value[6] << 8) | cvm_tlv->value[7];
    list->num_rules = num_rules;

    // Extract rules
    for (size_t i = 0; i < num_rules; i++) {
        list->rules[i].method = cvm_tlv->value[8 + i * 2] & 0x3F;
        list->rules[i].continue_if_fail = (cvm_tlv->value[8 + i * 2] & 0x40) != 0;
        list->rules[i].condition = cvm_tlv->value[9 + i * 2];
    }

    return list;
}

// Secure memory handling for sensitive data
static void secure_zero_memory(void* ptr, size_t len) {
    SecureZeroMemory(ptr, len);
}

// Init function for module
void emv_tags_init(void) {
#ifdef _DEBUG
    validate_tags();
#endif

    // Initialize tag cache
    memset(tag_cache, 0, sizeof(tag_cache));

    // Pre-populate cache with common tags
    for (size_t i = 0; tag_database[i].tag != 0xFFFF; i++) {
        uint32_t hash = _mm_crc32_u16(0, tag_database[i].tag);
        uint32_t idx = hash % CACHE_SIZE;

        static emv_tag_info_t info;
        info.tag = tag_database[i].tag;
        info.name = tag_database[i].name;
        info.type = tag_database[i].format == EMV_TAG_GENERIC ? "Generic" :
            tag_database[i].format == EMV_TAG_STRING ? "String" :
            tag_database[i].format == EMV_TAG_NUMERIC ? "Numeric" :
            tag_database[i].format == EMV_TAG_BINARY ? "Binary" :
            tag_database[i].format == EMV_TAG_DATE ? "Date" :
            tag_database[i].format == EMV_TAG_DOL ? "DOL" :
            tag_database[i].format == EMV_TAG_BITMASK ? "Bitmask" : "Unknown";
        info.description = tag_database[i].description;

        tag_cache[idx].tag = tag_database[i].tag;
        tag_cache[idx].info = &info;
    }
}
