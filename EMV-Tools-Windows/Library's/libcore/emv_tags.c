#define _CRT_SECURE_NO_WARNINGS

#include "emv_tags.h"
#include "emv_defs.h"
#include "apdu.h"  // Make sure this can be found
#include "tlv.h"
#include "emv_commands.h"
#include <stdlib.h>
#include <string.h>
#include <windows.h> // For SecureZeroMemory
#include <wincrypt.h>  // For DPAPI
#include <time.h>      // For struct tm
#include <dpapi.h>
#include <assert.h>

static int emv_tag_cmp(const void* a, const void* b)
{
    const struct emv_tag_info_t* ta = (const struct emv_tag_info_t*)a;
    const struct emv_tag_info_t* tb = (const struct emv_tag_info_t*)b;

    if (ta->tag < tb->tag)
        return -1;
    else if (ta->tag > tb->tag)
        return 1;
    else
        return 0;
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define CACHE_SIZE 8

#ifdef _DEBUG
static void validate_tags() {
    assert(tag_database[0].tag == 0x4F);
    assert(tag_database[ARRAY_SIZE(tag_database)-1].tag == 0xFFFF);
    // Verify no duplicates
    for(size_t i=0; i<ARRAY_SIZE(tag_database)-1; i++) {
        assert(tag_database[i].tag < tag_database[i+1].tag);
    }
}
#endif

const char* tlv_tag_get_name(tlv_tag_t tag) {
    return emv_tag_get_name(tag);
}

const char* tlv_tag_get_description(tlv_tag_t tag) {
    return emv_tag_get_description(tag);
}

static void build_tag_cache() {
    for(size_t i=0; tag_database[i].tag != 0xFFFF; i++) {
        uint32_t hash = _mm_crc32_u16(0, tag_database[i].tag);
        tag_cache[hash % CACHE_SIZE] = &tag_database[i];
    }
}

int emv_tag_protect(tlv_t* tlv) {
    DATA_BLOB in = {tlv->len, tlv->value};
    DATA_BLOB out;
    
    if (!CryptProtectData(&in, L"EMV_TAG", NULL, NULL, NULL, 0, &out))
        return GetLastError();
    
    free(tlv->value);
    tlv->value = out.pbData;
    tlv->len = out.cbData;
    return EMV_OK;
}

#define PAYMENT_SYSTEM_TAGS \
    /* Visa */ \
    {0x9F5B, "Visa Transaction Identifier", EMV_TAG_BINARY}, \
    {0x9F5C, "Visa Token Requestor ID", EMV_TAG_NUMERIC}, \
    /* Mastercard */ \
    {0x9F5D, "MC UCAF", EMV_TAG_BINARY}, \
    {0x9F5E, "MC Device Type", EMV_TAG_NUMERIC}, \
    /* Amex */ \
    {0x9F5F, "Amex Card Identifier", EMV_TAG_BINARY}, \
    {0x9F60, "Amex Token Data", EMV_TAG_BINARY}, \
    /* JCB */ \
    {0x9F61, "JCB Secure Code", EMV_TAG_BINARY}, \
    {0x9F62, "JCB Token Indicator", EMV_TAG_NUMERIC}

typedef enum {
    EMV_TAG_GENERIC,
    EMV_TAG_BITMASK,
    EMV_TAG_DOL,
    EMV_TAG_CVM_LIST,
    EMV_TAG_STRING,
    EMV_TAG_NUMERIC,
    EMV_TAG_YYMMDD,
} emv_tag_type_t;

// Bitmask handling structures
typedef struct {
    uint16_t bit;
    const char* name;
} emv_bitmask_t;

#define EMV_BIT(byte, bit) ((byte - 1) * 8 + (8 - bit))
#define BITMASK_TERMINATOR {0xFFFF, NULL}

// Application Interchange Profile (AIP) bits
static const emv_bitmask_t aip_bits[] = {
    {EMV_BIT(1, 7), "SDA supported"},
    {EMV_BIT(1, 6), "DDA supported"},
    {EMV_BIT(1, 5), "Cardholder verification supported"},
    {EMV_BIT(1, 4), "Terminal risk management required"},
    {EMV_BIT(1, 3), "Issuer authentication supported"},
    {EMV_BIT(1, 1), "CDA supported"},
    BITMASK_TERMINATOR
};

static const emv_bitmask_t visa_qual_bits[] = {
    {EMV_BIT(1, 8), "Cashback allowed"},
    {EMV_BIT(1, 7), "Refund allowed"},
    BITMASK_TERMINATOR
};

{0x9F72, "Visa Transaction Qualifiers", EMV_TAG_BITMASK, visa_qual_bits, false}

// Terminal Verification Results (TVR) bits
static const emv_bitmask_t tvr_bits[] = {
    {EMV_BIT(1, 8), "Offline data authentication not performed"},
    {EMV_BIT(1, 7), "SDA failed"},
    { EMV_BIT(1, 6), "ICC data missing" },
	{ EMV_BIT(1, 5), "Card appears on terminal exception file" },
	{ EMV_BIT(1, 4), "DDA failed" },
	{ EMV_BIT(1, 3), "CDA failed" },
	{ EMV_BIT(1, 2), "SDA selected" },
	{ EMV_BIT(2, 8), "ICC and terminal have different application versions" },
	{ EMV_BIT(2, 7), "Expired application" },
	{ EMV_BIT(2, 6), "Application not yet effective" },
	{ EMV_BIT(2, 5), "Requested service not allowed for card product" },
	{ EMV_BIT(2, 4), "New card" },
	{ EMV_BIT(3, 8), "Cardholder verification was not successful" },
	{ EMV_BIT(3, 7), "Unrecognised CVM" },
	{ EMV_BIT(3, 6), "PIN Try Limit exceeded" },
	{ EMV_BIT(3, 5), "PIN entry required and PIN pad not present or not working" },
	{ EMV_BIT(3, 4), "PIN entry required, PIN pad present, but PIN was not entered" },
	{ EMV_BIT(3, 3), "Online PIN entered" },
	{ EMV_BIT(4, 8), "Transaction exceeds floor limit" },
	{ EMV_BIT(4, 7), "Lower consecutive offline limit exceeded" },
	{ EMV_BIT(4, 6), "Upper consecutive offline limit exceeded" },
	{ EMV_BIT(4, 5), "Transaction selected randomly for online processing" },
	{ EMV_BIT(4, 4), "Merchant forced transaction online" },
	{ EMV_BIT(5, 8), "Default TDOL used" },
	{ EMV_BIT(5, 7), "Issuer authentication failed" },
	{ EMV_BIT(5, 6), "Script processing failed before final GENERATE AC" },
	{ EMV_BIT(5, 5), "Script processing failed after final GENERATE AC" },
	{ EMV_BIT(5, 4), "Reserved for use by the EMV Contactless Specifications" },
	{ EMV_BIT(5, 3), "Reserved for use by the EMV Contactless Specifications" },
	{ EMV_BIT(5, 2), "Reserved for use by the EMV Contactless Specifications" },
	{ EMV_BIT(5, 1), "Reserved for use by the EMV Contactless Specifications" },
    BITMASK_TERMINATOR
};

static const emv_tag_def_t tag_database[] = {
    // Core EMV tags (partial list - would include all 200+ tags)
    {0x4F, "Application Identifier", EMV_TAG_BINARY, NULL},
    {0x50, "Application Label", EMV_TAG_STRING, NULL},
    {0x56, "Track 1 Data", EMV_TAG_BINARY, NULL},
    {0x57, "Track 2 Equivalent Data", EMV_TAG_BINARY, NULL},
    {0x5A, "PAN", EMV_TAG_BINARY, NULL},
    {0x5F20, "Cardholder Name", EMV_TAG_STRING, NULL},
    {0x5F24, "Expiration Date", EMV_TAG_YYMMDD, NULL},
    {0x5f25, "Application Effective Date", EMV_TAG_YYMMDD },
	{0x5f28, "Issuer Country Code", EMV_TAG_NUMERIC },
	{0x5f2a, "Transaction Currency Code", EMV_TAG_NUMERIC },
	{0x5f2d, "Language Preference", EMV_TAG_STRING },
	{0x5f30, "Service Code", EMV_TAG_NUMERIC },
	{0x5f34, "Application Primary Account Number (PAN) Sequence Number", EMV_TAG_NUMERIC },
	{0x61  , "Application Template" },
	{0x6f  , "File Control Information (FCI) Template" },
	{0x70  , "READ RECORD Response Message Template" },
	{0x77  , "Response Message Template Format 2" },
	{0x80  , "Response Message Template Format 1" },
	{0x82  , "Application Interchange Profile", EMV_TAG_BITMASK, &EMV_AIP, aip_bits },
	{0x83  , "Command Template" },
	{0x84  , "Dedicated File (DF) Name" },
	{0x87  , "Application Priority Indicator" },
	{0x88  , "Short File Identifier (SFI)" },
	{0x8a  , "Authorisation Response Code" },
	{0x8c  , "Card Risk Management Data Object List 1 (CDOL1)", EMV_TAG_DOL },
	{0x8d  , "Card Risk Management Data Object List 2 (CDOL2)", EMV_TAG_DOL },
	{0x8e  , "Cardholder Verification Method (CVM) List", EMV_TAG_CVM_LIST },
	{0x8f  , "Certification Authority Public Key Index" },
	{0x90  , "Issuer Public Key Certificate" },
	{0x91  , "Issuer Authentication Data" },
	{0x92  , "Issuer Public Key Remainder" },
	{0x93  , "Signed Static Application Data" },
	{0x94  , "Application File Locator (AFL)" },
	{0x95  , "Terminal Verification Results", EMV_TAG_BITMASK, tvr_bits},
	{0x9a  , "Transaction Date", EMV_TAG_YYMMDD },
	{0x9c  , "Transaction Type" },
	{0x9f02, "Amount, Authorised (Numeric)", EMV_TAG_NUMERIC },
	{0x9f03, "Amount, Other (Numeric)", EMV_TAG_NUMERIC, },
	{0x9f07, "Application Usage Control", EMV_TAG_BITMASK, &EMV_AUC },
	{0x9f08, "Application Version Number" },
	{0x9f0d, "Issuer Action Code - Default", EMV_TAG_BITMASK, &EMV_TVR },
	{0x9f0e, "Issuer Action Code - Denial", EMV_TAG_BITMASK, &EMV_TVR },
	{0x9f0f, "Issuer Action Code - Online", EMV_TAG_BITMASK, &EMV_TVR },
	{0x9f10, "Issuer Application Data" },
	{0x9f11, "Issuer Code Table Index", EMV_TAG_NUMERIC },
	{0x9f12, "Application Preferred Name", EMV_TAG_STRING },
	{0x9f13, "Last Online Application Transaction Counter (ATC) Register" },
	{0x9f17, "Personal Identification Number (PIN) Try Counter" },
	{0x9f1a, "Terminal Country Code" },
	{0x9f1f, "Track 1 Discretionary Data", EMV_TAG_STRING },
	{0x9f21, "Transaction Time" },
	{0x9f26, "Application Cryptogram" },
	{0x9f27, "Cryptogram Information Data" },
	{0x9f2d, "ICC PIN Encipherment Public Key Certificate" },
	{0x9f2e, "ICC PIN Encipherment Public Key Exponent" },
	{0x9f2f, "ICC PIN Encipherment Public Key Remainder" },
	{0x9f32, "Issuer Public Key Exponent" },
	{0x9f34, "Cardholder Verification Method (CVM) Results" },
	{0x9f35, "Terminal Type" },
	{0x9f36, "Application Transaction Counter (ATC)" },
	{0x9f37, "Unpredictable Number" },
	{0x9f38, "Processing Options Data Object List (PDOL)", EMV_TAG_DOL },
	{0x9f42, "Application Currency Code", EMV_TAG_NUMERIC },
	{0x9f44, "Application Currency Exponent", EMV_TAG_NUMERIC },
	{0x9f45, "Data Authentication Code" },
	{0x9F46, "ICC Public Key Certificate", EMV_TAG_BINARY },
	{0x9f47, "ICC Public Key Exponent" },
	{0x9f48, "ICC Public Key Remainder" },
	{0x9f49, "Dynamic Data Authentication Data Object List (DDOL)", EMV_TAG_DOL },
	{0x9f4a, "Static Data Authentication Tag List" },
	{0x9f4b, "Signed Dynamic Application Data" },
	{0x9f4c, "ICC Dynamic Number" },
	{0x9f4d, "Log Entry" },
	{0x9f4f, "Log Format", EMV_TAG_DOL },
	{0x9f62, "PCVC3(Track1)" },
	{0x9f63, "PUNATC(Track1)" },
	{0x9f64, "NATC(Track1)" },
	{0x9f65, "PCVC3(Track2)" },
	{0x9f66, "PUNATC(Track2)" },
	{0x9f67, "NATC(Track2)" },
	{0x9f6b, "Track 2 Data" },
	{0xa5  , "File Control Information (FCI) Proprietary Template" },
	{0xbf0c, "File Control Information (FCI) Issuer Discretionary Data" },
    {0xFFFF, NULL, EMV_TAG_GENERIC, NULL}
};

static struct {
    tlv_tag_t tag;
    const struct emv_tag_info_t* info;
} tag_cache[CACHE_SIZE];

// Complete EMV tag database
typedef struct {
    uint16_t tag;
    const char* name;
    emv_tag_type_t type;
    const emv_bitmask_t* bitmask;
} emv_tag_def_t;

// Binary search helper
static int compare_tags(const void* a, const void* b) {
    uint16_t tag1 = *(const uint16_t*)a;
    uint16_t tag2 = ((const emv_tag_def_t*)b)->tag;
    return (tag1 > tag2) - (tag1 < tag2);
}

const emv_tag_info_t* emv_tag_get_info(uint16_t tag) {
    const emv_tag_def_t* found = bsearch(&tag, tag_database, 
        sizeof(tag_database)/sizeof(tag_database[0]) - 1,
        sizeof(tag_database[0]), compare_tags);
    
    static emv_tag_info_t info;
    if (found) {
        info.tag = found->tag;
        info.name = found->name;
        info.type = found->type;
        return &info;
    }
    return NULL;
}

// Secure memory clearing for sensitive data
void emv_tag_secure_free(tlv_t* tlv) {
    if (tlv && tlv->value) {
        SecureZeroMemory(tlv->value, tlv->len);
        free(tlv->value);
    }
}

static const emv_bitmask_t auc_bits[] = {
    {EMV_BIT(1, 8), "Valid for domestic cash transactions"},
    {EMV_BIT(1, 7), "Valid for international cash transactions"},
    {EMV_BIT(1, 6), "Valid for domestic goods"},
    {EMV_BIT(1, 5), "Valid for international goods"},
    {EMV_BIT(1, 4), "Valid for domestic services"},
    {EMV_BIT(1, 3), "Valid for international services"},
    {EMV_BIT(1, 2), "Valid at ATMs"},
    {EMV_BIT(1, 1), "Valid at terminals other than ATMs"},
    {EMV_BIT(2, 8), "Domestic cashback allowed"},
    {EMV_BIT(2, 7), "International cashback allowed"},
    BITMASK_TERMINATOR
};

int emv_process_cvm_secure(const tlv_t* cvm_tlv, 
                          emv_cvm_callback callback,
                          void* userdata,
                          CRITICAL_SECTION* lock) {
    if (!lock) return EMV_ERR_INVALID_PARAM;
    
    EnterCriticalSection(lock);
    int ret = emv_decode_cvm(cvm_tlv, callback, userdata);
    LeaveCriticalSection(lock);
    
    return ret;
}

// Aligned memory allocation for tags
tlv_t* emv_tag_create_aligned(size_t len) {
    void* ptr = _aligned_malloc(len, 8); // 8-byte alignment
    if (!ptr) return NULL;
    
    tlv_t* tlv = (tlv_t*)ptr;
    tlv->value = ((uint8_t*)ptr) + sizeof(tlv_t);
    return tlv;
}

int emv_decode_cvm(const tlv_t* cvm_tlv, emv_cvm_callback callback, void* userdata) {
    if (!cvm_tlv || cvm_tlv->len < 8 || (cvm_tlv->len % 2) != 0) 
        return EMV_ERR_INVALID_FORMAT;

    // Extract X and Y values (4 bytes each)
    uint32_t X = (cvm_tlv->value[0] << 24) | (cvm_tlv->value[1] << 16) 
               | (cvm_tlv->value[2] << 8) | cvm_tlv->value[3];
    uint32_t Y = (cvm_tlv->value[4] << 24) | (cvm_tlv->value[5] << 16) 
               | (cvm_tlv->value[6] << 8) | cvm_tlv->value[7];

    if (callback) {
        callback(userdata, X, Y, EMV_CVM_HEADER);
    }

    // Process each CVM rule
    for (size_t i = 8; i < cvm_tlv->len; i += 2) {
        uint8_t method = cvm_tlv->value[i] & 0x3F;
        uint8_t condition = cvm_tlv->value[i+1];
        bool continue_if_fail = (cvm_tlv->value[i] & 0x40) != 0;

        if (callback) {
            callback(userdata, method, condition, continue_if_fail);
        }
    }

    return EMV_OK;
}
const char* emv_tag_to_string(uint16_t tag) {
    const emv_tag_info_t* info = emv_tag_get_info(tag);
    return info ? info->name : "UNKNOWN";
}
int emv_process_dol_with_context(const tlv_t* dol, 
    const tlvdb_t* context,
    emv_dol_callback cb, 
    void* userdata);
    
// Bitmask decoding (Windows-optimized)
void emv_tag_decode_bitmask(const tlv_t* tlv, emv_bitmask_callback callback, void* userdata) {
    if (!tlv || tlv->type != EMV_TAG_BITMASK) return;
    
    const emv_tag_def_t* def = bsearch(&tlv->tag, tag_database, 
        sizeof(tag_database)/sizeof(tag_database[0]) - 1,
        sizeof(tag_database[0]), compare_tags);
    
    if (!def || !def->bitmask) return;
    
    for (size_t byte = 0; byte < tlv->len; byte++) {
        uint8_t val = tlv->value[byte];
        for (int bit = 7; bit >= 0; bit--) {
            uint16_t combined_bit = EMV_BIT(byte + 1, bit + 1);
            const emv_bitmask_t* mask = def->bitmask;
            
            while (mask->bit != 0xFFFF) {
                if (mask->bit == combined_bit && (val & (1 << bit))) {
                    if (callback) {
                        callback(userdata, combined_bit, mask->name);
                    }
                    break;
                }
                mask++;
            }
        }
    }
}

static const char* bitstrings[] = {
    ".......1", "......1.", ".....1..", "....1...",
    "...1....", "..1.....", ".1......", "1......."
};

void emv_tag_format_bitmask(const tlv_t* tlv, FILE* out) {
    emv_tag_decode_bitmask(tlv, [](void* f, uint16_t bit, const char* name) {
        fprintf((FILE*)f, "\t%s - %s\n", bitstrings[bit % 8], name);
        return true;
    }, out);
}
// Date parsing (YYMMDD format)
int emv_tag_parse_date(const tlv_t* tlv, struct tm* date) {
    if (!tlv || tlv->type != EMV_TAG_DATE || tlv->len != 3) 
        return EMV_ERR_INVALID_FORMAT;
    
    date->tm_year = (tlv->value[0] >> 4) * 10 + (tlv->value[0] & 0xF) + 100; // Years since 1900
    date->tm_mon = (tlv->value[1] >> 4) * 10 + (tlv->value[1] & 0xF) - 1; // 0-11
    date->tm_mday = (tlv->value[2] >> 4) * 10 + (tlv->value[2] & 0xF);
    
    return EMV_OK;
}

// DOL parsing (Data Object List)
int emv_tag_parse_dol(const tlv_t* dol, emv_dol_callback callback, void* userdata) {
    if (!dol || dol->type != EMV_TAG_DOL) 
        return EMV_ERR_INVALID_PARAM;
    
    const uint8_t* ptr = dol->value;
    size_t remaining = dol->len;
    
    while (remaining > 0) {
        tlv_t entry;
        if (!tlv_parse_tl(&ptr, &remaining, &entry)) 
            break;
            
        if (callback) {
            callback(userdata, &entry);
        }
    }
    
    return EMV_OK;
}
