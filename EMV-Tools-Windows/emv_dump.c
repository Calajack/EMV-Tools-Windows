#ifdef _MSC_VER
#pragma comment(lib, "libcrypto-emv.lib")
#pragma comment(lib, "libcore.lib")
#pragma comment(lib, "libscard.lib")
#pragma comment(lib, "Winscard.lib")
#endif

// emv_dump.c - EMV Card Data Dump Tool
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <time.h>

// Core library includes
#include "config.h"
#include "tlv.h"
#include "dol.h"
#include "emv_tags.h"
#include "config_windows.h"
#include "emv_defs.h"
#include "utils_windows.h"
#include "emv_operations.h"
#include "emv_file_utils.h"
#include "crypto_hash.h"

// Smart card library includes
#include "scard_common.h"
#include "apdu.h"
#include "emv_commands.h"

static void print_hex(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

// Function to format PAN with spaces
static void print_pan(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char digit = data[i];
        
        // Check if we're at a position where we should add a space (every 4 digits)
        if (i > 0 && i % 2 == 0)
            printf(" ");
        
        printf("%02x", digit);
    }
}

// Function to get expiration date as a string
static void format_date(const unsigned char *data, size_t len, char *out, size_t out_len)
{
    if (len >= 2 && out_len >= 8) {
        snprintf(out, out_len, "20%02x/%02x", data[0], data[1]);
    } else {
        strncpy(out, "Unknown", out_len);
    }
}

// Function to get card holder name from tag 5F20
static void format_name(const unsigned char *data, size_t len, char *out, size_t out_len)
{
    if (len == 0 || out_len == 0)
        return;
    
    size_t i, j;
    for (i = 0, j = 0; i < len && j < out_len - 1; i++) {
        // Filter printable ASCII
        if (data[i] >= 0x20 && data[i] <= 0x7E) {
            out[j++] = data[i];
        }
    }
    out[j] = '\0';
    
    // Trim trailing spaces
    while (j > 0 && out[j-1] == ' ')
        out[--j] = '\0';
}

static void dump_tag_info(const struct tlv *tlv)
{
    const char *name = emv_tag_get_name(tlv->tag);
    const char *desc = emv_tag_get_description(tlv->tag);
    
    printf("Tag: %04X", tlv->tag);
    if (name)
        printf(" (%s)", name);
    
    printf("\nLength: %zu bytes\n", tlv->len);
    
    printf("Value: ");
    
    // Special handling for specific tags
    switch (tlv->tag) {
        case 0x5A: // PAN
            print_pan(tlv->value, tlv->len);
            break;
        
        case 0x5F24: // Expiration Date
            {
                char date_str[16];
                format_date(tlv->value, tlv->len, date_str, sizeof(date_str));
                printf("%s", date_str);
            }
            break;
        
        case 0x5F20: // Cardholder Name
            {
                char name_str[64];
                format_name(tlv->value, tlv->len, name_str, sizeof(name_str));
                printf("%s", name_str);
            }
            break;
        
        case 0x9F07: // Application Usage Control
        case 0x82: // Application Interchange Profile
        case 0x95: // Terminal Verification Results
        case 0x9B: // Transaction Status Information
            // These are commonly viewed as bit fields
            print_hex(tlv->value, tlv->len);
            printf(" (bit field)");
            break;
        
        case 0x9F27: // Cryptogram Information Data
            print_hex(tlv->value, tlv->len);
            if (tlv->len > 0) {
                printf(" (");
                switch (tlv->value[0] & 0xC0) {
                    case 0x00: printf("AAC - Declined"); break;
                    case 0x40: printf("TC - Approved"); break;
                    case 0x80: printf("ARQC - Online"); break;
                    default: printf("RFU"); break;
                }
                printf(")");
            }
            break;
        
        default:
            print_hex(tlv->value, tlv->len);
            break;
    }
    
    printf("\n");
    
    if (desc)
        printf("Description: %s\n", desc);
    
    printf("\n");
}

// Function to dump a TLV database in a more readable format
static void dump_tlvdb_info(const struct tlvdb *tlvdb)
{
    if (!tlvdb)
        return;
    
    // First dump this tag
    if (tlvdb->tag.tag != 0 && tlvdb->tag.len > 0)
        dump_tag_info(&tlvdb->tag);
    
    // Then dump children
    dump_tlvdb_info(tlvdb->children);
    
    // Then dump siblings
    dump_tlvdb_info(tlvdb->next);
}

static void dump_card_data(struct sc *scard, const char *aid_str, 
                        bool dump_records, bool perform_gpo)
{
    // Parse AID if provided
    unsigned char aid[16] = {0};
    size_t aid_len = 0;
    
    if (aid_str) {
        aid_len = strlen(aid_str) / 2;
        if (aid_len > sizeof(aid))
            aid_len = sizeof(aid);
        
        for (size_t i = 0; i < aid_len; i++) {
            char byte[3] = {aid_str[i*2], aid_str[i*2+1], 0};
            aid[i] = strtol(byte, NULL, 16);
        }
    }
    
    // If no AID provided, try to list applications
    if (aid_len == 0) {
        printf("No AID provided. Attempting to select PSE...\n");
        
        // Try to select PSE (Payment System Environment)
        unsigned char pse[] = {'1', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1'};
        struct tlvdb *pse_db = emv_select(scard, pse, sizeof(pse));
        
        if (pse_db) {
            printf("\n=== PSE DIRECTORY ===\n\n");
            dump_tlvdb_info(pse_db);
            
            // Extract and try to read SFI records
            const struct tlv *sfi_tlv = tlvdb_get(pse_db, 0x88, NULL);
            if (sfi_tlv && sfi_tlv->len > 0) {
                unsigned char sfi = sfi_tlv->value[0];
                printf("\nReading PSE records (SFI: %02X)...\n", sfi);
                
                // Try to read a few records
                for (int i = 1; i <= 10; i++) {
                    struct tlvdb *record_db = emv_read_record(scard, sfi >> 3, i);
                    if (record_db) {
                        printf("\n=== PSE RECORD %d ===\n\n", i);
                        dump_tlvdb_info(record_db);
                        
                        // Extract AIDs from record
                        const struct tlv *aid_tlv = tlvdb_get(record_db, 0x4F, NULL);
                        if (aid_tlv) {
                            printf("Found AID: ");
                            print_hex(aid_tlv->value, aid_tlv->len);
                            printf("\n");
                            
                            // Use this AID
                            if (aid_len == 0 && aid_tlv->len <= sizeof(aid)) {
                                memcpy(aid, aid_tlv->value, aid_tlv->len);
                                aid_len = aid_tlv->len;
                                printf("Using this AID for further operations\n");
                            }
                        }
                        
                        tlvdb_free(record_db);
                    }
                }
            }
            
            tlvdb_free(pse_db);
        } else {
            printf("PSE selection failed. Trying PPSE...\n");
            
            // Try to select PPSE (Proximity Payment System Environment) for contactless
            unsigned char ppse[] = {'2', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1'};
            struct tlvdb *ppse_db = emv_select(scard, ppse, sizeof(ppse));
            
            if (ppse_db) {
                printf("\n=== PPSE DIRECTORY ===\n\n");
                dump_tlvdb_info(ppse_db);
                
                // Extract applications from FCI Template
                const struct tlv *fci_tlv = tlvdb_get(ppse_db, 0xA5, NULL);
                if (fci_tlv) {
                    struct tlvdb *fci_db = tlvdb_parse(fci_tlv->value, fci_tlv->len);
                    if (fci_db) {
                        // Look for Directory Entry template
                        const struct tlv *entry_tlv = tlvdb_get(fci_db, 0x61, NULL);
                        while (entry_tlv) {
                            struct tlvdb *entry_db = tlvdb_parse(entry_tlv->value, entry_tlv->len);
                            if (entry_db) {
                                const struct tlv *aid_tlv = tlvdb_get(entry_db, 0x4F, NULL);
                                if (aid_tlv) {
                                    printf("Found AID: ");
                                    print_hex(aid_tlv->value, aid_tlv->len);
                                    printf("\n");
                                    
                                    // Use this AID
                                    if (aid_len == 0 && aid_tlv->len <= sizeof(aid)) {
                                        memcpy(aid, aid_tlv->value, aid_tlv->len);
                                        aid_len = aid_tlv->len;
                                        printf("Using this AID for further operations\n");
                                    }
                                }
                                tlvdb_free(entry_db);
                            }
                            
                            // Get next entry
                            entry_tlv = tlvdb_get(fci_db, 0x61, entry_tlv);
                        }
                        
                        tlvdb_free(fci_db);
                    }
                }
                
                tlvdb_free(ppse_db);
            } else {
                printf("PPSE selection failed\n");
            }
        }
    }
    
    // If we have an AID now, use it
    if (aid_len > 0) {
        printf("\nSelecting application: ");
        print_hex(aid, aid_len);
        printf("\n");
        
        struct tlvdb *select_db = emv_select(scard, aid, aid_len);
        if (!select_db) {
            printf("Application selection failed\n");
            return;
        }
        
        printf("\n=== APPLICATION FCI ===\n\n");
        dump_tlvdb_info(select_db);
        
        // Get processing options if requested
        if (perform_gpo) {
            printf("\nGetting processing options...\n");
            struct tlvdb *gpo_db = emv_get_processing_options(scard, NULL);
            
            if (gpo_db) {
                printf("\n=== PROCESSING OPTIONS ===\n\n");
                dump_tlvdb_info(gpo_db);
                
                // Read records if requested
                if (dump_records) {
                    // Extract PAN for later
                    unsigned char pan[10] = {0};
                    size_t pan_len = 0;
                    
                    const struct tlv *pan_tlv = tlvdb_get(select_db, 0x5A, NULL);
                    if (pan_tlv) {
                        pan_len = pan_tlv->len > 10 ? 10 : pan_tlv->len;
                        memcpy(pan, pan_tlv->value, pan_len);
                    }
                    
                    // Get AFL (Application File Locator)
                    const struct tlv *afl_tlv = tlvdb_get(gpo_db, 0x94, NULL);
                    if (afl_tlv) {
                        printf("\nReading application records...\n");
                        
                        struct tlvdb *afl_db = tlvdb_fixed(0x94, afl_tlv->len, afl_tlv->value);
                        struct tlvdb *records_db = emv_read_records(scard, pan, afl_db);
                        tlvdb_free(afl_db);
                        
                        if (records_db) {
                            printf("\n=== APPLICATION RECORDS ===\n\n");
                            dump_tlvdb_info(records_db);
                            tlvdb_free(records_db);
                        } else {
                            printf("Failed to read application records\n");
                        }
                    }
                }
                
                tlvdb_free(gpo_db);
            } else {
                printf("GET PROCESSING OPTIONS failed\n");
            }
        }
        
        tlvdb_free(select_db);
    } else {
        printf("No valid AID found or provided\n");
    }
}

static void print_usage(void)
{
    printf("EMV Card Data Dump Tool\n");
    printf("Usage: emv_dump [options]\n");
    printf("Options:\n");
    printf("  -h, --help            Display this help message\n");
    printf("  -a, --aid AID         Application ID to select (hex)\n");
    printf("  -r, --reader INDEX    Use specific reader by index\n");
    printf("  -n, --no-records      Don't read application records\n");
    printf("  -g, --no-gpo          Don't perform GET PROCESSING OPTIONS\n");
}

int main(int argc, char **argv)
{
    const char *aid_str = NULL;
    int reader_index = -1;
    bool dump_records = true;
    bool perform_gpo = true;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--aid") == 0) {
            if (i + 1 < argc)
                aid_str = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--reader") == 0) {
            if (i + 1 < argc)
                reader_index = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--no-records") == 0) {
            dump_records = false;
        } else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--no-gpo") == 0) {
            perform_gpo = false;
        }
    }
    
    // Initialize EMV configuration
    emv_config_init(NULL);
    
    // Initialize card readers
    SCARDCONTEXT hContext;
    LONG result = scard_establish_context(&hContext);
    if (result != SCARD_S_SUCCESS) {
        printf("Failed to establish smart card context: %s\n", pcsc_stringify_error(result));
        return 1;
    }
    
    // List available readers
    char reader_names[MAX_READERS][MAX_READERNAME];
    DWORD readers_count = 0;
    if (!scard_list_readers(hContext, reader_names, &readers_count, MAX_READERS, MAX_READERNAME)) {
        printf("Failed to list readers\n");
        scard_release_context(hContext);
        return 1;
    }
    
    if (readers_count == 0) {
        printf("No readers found\n");
        scard_release_context(hContext);
        return 1;
    }
    
    // Display available readers
    printf("Available readers:\n");
    for (DWORD i = 0; i < readers_count; i++) {
        printf("%lu: %s\n", i, reader_names[i]);
    }
    
    // Select reader
    DWORD selected_reader = 0;
    if (reader_index >= 0 && reader_index < readers_count) {
        selected_reader = reader_index;
    } else if (readers_count > 1) {
        printf("Select reader (0-%lu): ", readers_count - 1);
        char input[10] = {0};
        if (fgets(input, sizeof(input), stdin)) {
            selected_reader = atoi(input);
            if (selected_reader >= readers_count)
                selected_reader = 0;
        }
    }
    
    printf("Using reader: %s\n", reader_names[selected_reader]);
    
    // Connect to card
    SCARDHANDLE hCard;
    DWORD dwActiveProtocol;
    result = scard_connect(hContext, reader_names[selected_reader], &hCard, &dwActiveProtocol);
    if (result != SCARD_S_SUCCESS) {
        printf("Failed to connect to card: %s\n", pcsc_stringify_error(result));
        scard_release_context(hContext);
        return 1;
    }
    
    // Create sc structure that's compatible with emv_commands functions
    struct sc scard = {
        .hContext = hContext,
        .hCard = hCard,
        .dwActiveProtocol = dwActiveProtocol
    };
    
    // Dump card data
    dump_card_data(&scard, aid_str, dump_records, perform_gpo);
    
    // Cleanup
    scard_disconnect(hCard, SCARD_LEAVE_CARD);
    scard_release_context(hContext);
    
    return 0;
}
