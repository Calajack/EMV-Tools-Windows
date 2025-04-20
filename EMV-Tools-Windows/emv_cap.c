// emv_cap.c - EMV CAP implementation for Windows
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
#include "emv_commands.h"
#include "emv_defs.h"
#include "emv_pki.h"

// Crypto library includes
#include "crypto_windows.h"
#include "emv_pk.h"
#include "emv_pki_priv.h"

// Smart card library includes
#include "scard_common.h"
#include "apdu_processing.c"
#include "apdu.h"


// Helper for console output
static void print_hex(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

static void print_tlv(const struct tlv *tlv)
{
    const char *name = emv_tag_get_name(tlv->tag);
    
    printf("Tag: %04x", tlv->tag);
    if (name)
        printf(" (%s)", name);
    
    printf(", len: %zu\nData: ", tlv->len);
    print_hex(tlv->value, tlv->len);
    printf("\n");
}

// Parse the transaction value (amount)
static unsigned long long parse_value(const char *value_str)
{
    if (!value_str || !*value_str)
        return 0;
    
    unsigned long long value = 0;
    while (*value_str) {
        if (*value_str >= '0' && *value_str <= '9') {
            value = value * 10 + (*value_str - '0');
        }
        value_str++;
    }
    
    return value;
}

// CAP calculation functions
static unsigned int cap_calculate_pin(const unsigned char *pin_block, size_t pin_block_len,
                                   const unsigned char *atc, size_t atc_len,
                                   const unsigned char *arqc, size_t arqc_len)
{
    ByteBuffer hash;
    unsigned int result = 0;
    
    // Create concatenated data for hashing
    unsigned char *data = malloc(pin_block_len + atc_len + arqc_len);
    if (!data)
        return 0;
    
    // Pin block + ATC + ARQC
    memcpy(data, pin_block, pin_block_len);
    memcpy(data + pin_block_len, atc, atc_len);
    memcpy(data + pin_block_len + atc_len, arqc, arqc_len);
    
    // Calculate SHA-1 hash
    hash = emv_sha1_hash(data, pin_block_len + atc_len + arqc_len);
    free(data);
    
    if (!hash.data || hash.length < 4)
        return 0;
    
    // Extract 8 decimal digits from hash
    result = ((hash.data[0] & 0x7f) << 24) |
             (hash.data[1] << 16) |
             (hash.data[2] << 8) |
             hash.data[3];
    
    result %= 100000000; // Limit to 8 digits
    
    emv_free_buffer(&hash);
    return result;
}

static unsigned int cap_calculate_no_pin(const unsigned char *pan, size_t pan_len,
                                      const unsigned char *atc, size_t atc_len,
                                      const unsigned char *arqc, size_t arqc_len)
{
    ByteBuffer hash;
    unsigned int result = 0;
    
    // Create concatenated data for hashing
    unsigned char *data = malloc(pan_len + atc_len + arqc_len);
    if (!data)
        return 0;
    
    // PAN + ATC + ARQC
    memcpy(data, pan, pan_len);
    memcpy(data + pan_len, atc, atc_len);
    memcpy(data + pan_len + atc_len, arqc, arqc_len);
    
    // Calculate SHA-1 hash
    hash = emv_sha1_hash(data, pan_len + atc_len + arqc_len);
    free(data);
    
    if (!hash.data || hash.length < 4)
        return 0;
    
    // Extract 8 decimal digits from hash
    result = ((hash.data[0] & 0x7f) << 24) |
             (hash.data[1] << 16) |
             (hash.data[2] << 8) |
             hash.data[3];
    
    result %= 100000000; // Limit to 8 digits
    
    emv_free_buffer(&hash);
    return result;
}

// Windows console input for PIN
static bool get_pin(unsigned char *pin, size_t max_len)
{
    if (!pin || max_len < 4)
        return false;
    
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE)
        return false;
    
    // Save current console mode
    DWORD mode;
    if (!GetConsoleMode(hStdin, &mode))
        return false;
    
    // Disable echo
    if (!SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT))
        return false;
    
    printf("Enter PIN: ");
    
    // Read PIN
    char pin_str[20] = {0};
    DWORD read;
    
    if (!ReadConsole(hStdin, pin_str, sizeof(pin_str) - 1, &read, NULL)) {
        SetConsoleMode(hStdin, mode); // Restore console mode
        return false;
    }
    
    // Restore console mode
    SetConsoleMode(hStdin, mode);
    
    // Process input (remove newline)
    for (DWORD i = 0; i < read; i++) {
        if (pin_str[i] == '\r' || pin_str[i] == '\n') {
            pin_str[i] = 0;
            break;
        }
    }
    
    printf("\n");
    
    // Validate PIN
    size_t pin_len = strlen(pin_str);
    if (pin_len < 4 || pin_len > max_len) {
        printf("Invalid PIN length\n");
        return false;
    }
    
    for (size_t i = 0; i < pin_len; i++) {
        if (pin_str[i] < '0' || pin_str[i] > '9') {
            printf("Invalid PIN character\n");
            return false;
        }
        pin[i] = pin_str[i] - '0';
    }
    
    return true;
}

// Process a CAP transaction
static bool process_cap_transaction(struct sc *scard, const char *aid_str, 
                                   const char *value_str, bool use_pin)
{
    if (!scard || !aid_str)
        return false;
    
    // Parse AID
    size_t aid_len = strlen(aid_str) / 2;
    unsigned char aid[16] = {0};
    
    for (size_t i = 0; i < aid_len && i < sizeof(aid); i++) {
        char byte[3] = {aid_str[i*2], aid_str[i*2+1], 0};
        aid[i] = strtol(byte, NULL, 16);
    }
    
    // Select application
    printf("Selecting application: ");
    print_hex(aid, aid_len);
    printf("\n");
    
    struct tlvdb *select_db = emv_select(scard, aid, aid_len);
    if (!select_db) {
        printf("Application selection failed\n");
        return false;
    }
    
    // Extract PAN for CAP calculation
    const struct tlv *pan_tlv = tlvdb_get(select_db, 0x5A, NULL);
    if (!pan_tlv) {
        printf("PAN not found\n");
        tlvdb_free(select_db);
        return false;
    }
    
    // Prepare PDOL data
    struct tlvdb *pdol_data_db = NULL;
    const struct tlv *pdol_tlv = tlvdb_get(select_db, 0x9F38, NULL);
    
    if (pdol_tlv) {
        // Parse PDOL format
        struct dol pdol = {
            .data = pdol_tlv->value,
            .len = pdol_tlv->len
        };
        
        // Fill PDOL with terminal data
        struct tlvdb *temp_db = tlvdb_fixed(0x9F66, 4, (unsigned char[]){0x86, 0x00, 0x00, 0x00}); // TTQ
        
        // Add terminal country code
        unsigned char country_code[2] = {0x08, 0x40}; // US
        tlvdb_add(temp_db, tlvdb_fixed(0x9F1A, sizeof(country_code), country_code));
        
        // Add terminal capabilities
        unsigned char term_caps[3] = {0xE0, 0xB8, 0xC8};
        tlvdb_add(temp_db, tlvdb_fixed(0x9F33, sizeof(term_caps), term_caps));
        
        // Add transaction currency code (USD)
        unsigned char currency_code[2] = {0x08, 0x40};
        tlvdb_add(temp_db, tlvdb_fixed(0x5F2A, sizeof(currency_code), currency_code));
        
        // Add transaction amount if provided
        if (value_str && *value_str) {
            unsigned long long value = parse_value(value_str);
            unsigned char amount[6] = {0};
            
            // Convert to BCD
            for (int i = 5; i >= 0; i--) {
                amount[i] = (value % 10) | ((value / 10 % 10) << 4);
                value /= 100;
            }
            
            tlvdb_add(temp_db, tlvdb_fixed(0x9F02, sizeof(amount), amount));
        }
        
        // Process PDOL
        pdol_data_db = dol_process(0x83, &pdol, temp_db);
        tlvdb_free(temp_db);
    } else {
        // Default minimal PDOL data
        unsigned char default_pdol[2] = {0x83, 0x00};
        pdol_data_db = tlvdb_fixed(0x83, sizeof(default_pdol), default_pdol);
    }
    
    if (!pdol_data_db) {
        printf("Failed to prepare PDOL data\n");
        tlvdb_free(select_db);
        return false;
    }
    
    // Get processing options
    printf("Getting processing options...\n");
    struct tlvdb *gpo_db = emv_get_processing_options(scard, pdol_data_db);
    tlvdb_free(pdol_data_db);
    
    if (!gpo_db) {
        printf("GET PROCESSING OPTIONS failed\n");
        tlvdb_free(select_db);
        return false;
    }
    
    // Read application records
    printf("Reading application data...\n");
    struct tlvdb *records_db = NULL;
    const struct tlv *aip_tlv = tlvdb_get(gpo_db, 0x82, NULL);
    const struct tlv *afl_tlv = tlvdb_get(gpo_db, 0x94, NULL);
    
    if (afl_tlv) {
        // Read records according to AFL
        struct tlvdb *afl_db = tlvdb_fixed(0x94, afl_tlv->len, afl_tlv->value);
        records_db = emv_read_records(scard, 0, afl_db);
        tlvdb_free(afl_db);
    }
    
    if (!records_db) {
        printf("Failed to read application data\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        return false;
    }
    
    // Get data needed for CAP calculation
    const struct tlv *atc_tlv = tlvdb_get(records_db, 0x9F36, NULL);
    
    if (!atc_tlv) {
        // Try to get ATC with GET DATA
        struct tlvdb *atc_db = emv_get_data(scard, 0x9F36);
        if (atc_db) {
            atc_tlv = tlvdb_get(atc_db, 0x9F36, NULL);
            tlvdb_add(records_db, atc_db);
        }
    }
    
    if (!atc_tlv) {
        printf("Failed to get ATC\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    // Prepare CDOL1 data for GENERATE AC
    struct tlvdb *cdol_data_db = NULL;
    const struct tlv *cdol1_tlv = tlvdb_get(records_db, 0x8C, NULL);
    
    if (cdol1_tlv) {
        // Parse CDOL1 format
        struct dol cdol1 = {
            .data = cdol1_tlv->value,
            .len = cdol1_tlv->len
        };
        
        // Fill CDOL1 with transaction data
        struct tlvdb *temp_db = tlvdb_fixed(0x9F66, 4, (unsigned char[]){0x86, 0x00, 0x00, 0x00}); // TTQ
        
        // Add terminal country code
        unsigned char country_code[2] = {0x08, 0x40}; // US
        tlvdb_add(temp_db, tlvdb_fixed(0x9F1A, sizeof(country_code), country_code));
        
        // Add terminal capabilities
        unsigned char term_caps[3] = {0xE0, 0xB8, 0xC8};
        tlvdb_add(temp_db, tlvdb_fixed(0x9F33, sizeof(term_caps), term_caps));
        
        // Add transaction currency code (USD)
        unsigned char currency_code[2] = {0x08, 0x40};
        tlvdb_add(temp_db, tlvdb_fixed(0x5F2A, sizeof(currency_code), currency_code));
        
        // Add transaction date (today)
        time_t t = time(NULL);
        struct tm *tm = localtime(&t);
        unsigned char date[3] = {
            ((tm->tm_year + 1900) % 100) & 0xFF,
            (tm->tm_mon + 1) & 0xFF,
            tm->tm_mday & 0xFF
        };
        tlvdb_add(temp_db, tlvdb_fixed(0x9A, sizeof(date), date));
        
        // Add transaction amount if provided
        if (value_str && *value_str) {
            unsigned long long value = parse_value(value_str);
            unsigned char amount[6] = {0};
            
            // Convert to BCD
            for (int i = 5; i >= 0; i--) {
                amount[i] = (value % 10) | ((value / 10 % 10) << 4);
                value /= 100;
            }
            
            tlvdb_add(temp_db, tlvdb_fixed(0x9F02, sizeof(amount), amount));
        } else {
            // Zero amount for sign mode
            unsigned char amount[6] = {0};
            tlvdb_add(temp_db, tlvdb_fixed(0x9F02, sizeof(amount), amount));
        }
        
        // Process CDOL1
        cdol_data_db = dol_process(0x8C, &cdol1, temp_db);
        tlvdb_free(temp_db);
    }
    
    if (!cdol_data_db) {
        printf("Failed to prepare CDOL1 data\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    // Handle PIN verification if required
    if (use_pin) {
        unsigned char pin[12] = {0};
        
        // Get PIN from user
        if (!get_pin(pin, sizeof(pin))) {
            printf("PIN entry failed\n");
            tlvdb_free(select_db);
            tlvdb_free(gpo_db);
            tlvdb_free(records_db);
            tlvdb_free(cdol_data_db);
            return false;
        }
        
        // Prepare PIN block
        unsigned char pin_block[8] = {0x24}; // Format
        pin_block[1] = 0x00 | (8 & 0x0F); // PIN length
        
        // PIN digits (2 per byte)
        for (int i = 0; i < 8/2; i++) {
            pin_block[i+2] = (pin[i*2] << 4) | (pin[i*2+1] & 0x0F);
        }
        
        // Verify PIN
        printf("Verifying PIN...\n");
        struct tlvdb *verify_db = emv_verify_pin(scard, pin_block, sizeof(pin_block));
        
        if (!verify_db) {
            printf("PIN verification failed\n");
            tlvdb_free(select_db);
            tlvdb_free(gpo_db);
            tlvdb_free(records_db);
            tlvdb_free(cdol_data_db);
            return false;
        }
        
        tlvdb_free(verify_db);
    }
    
    // Generate AC
    printf("Generating cryptogram...\n");
    struct tlvdb *gen_ac_db = emv_generate_ac(scard, 0x80, cdol_data_db); // ARQC
    tlvdb_free(cdol_data_db);
    
    if (!gen_ac_db) {
        printf("GENERATE AC failed\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    // Get ARQC
    const struct tlv *arqc_tlv = tlvdb_get(gen_ac_db, 0x9F26, NULL);
    if (!arqc_tlv) {
        printf("ARQC not found\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        tlvdb_free(gen_ac_db);
        return false;
    }
    
    // Calculate CAP value
    unsigned int cap_value;
    
    if (use_pin) {
        // Create PIN block for CAP
        unsigned char pin_block[8] = {0x24}; // Format
        unsigned char pin[12] = {0};
        
        // Get PIN again for CAP calculation (could be stored from earlier)
        if (!get_pin(pin, sizeof(pin))) {
            printf("PIN entry failed\n");
            tlvdb_free(select_db);
            tlvdb_free(gpo_db);
            tlvdb_free(records_db);
            tlvdb_free(gen_ac_db);
            return false;
        }
        
        pin_block[1] = 0x00 | (8 & 0x0F); // PIN length
        
        // PIN digits (2 per byte)
        for (int i = 0; i < 8/2; i++) {
            pin_block[i+2] = (pin[i*2] << 4) | (pin[i*2+1] & 0x0F);
        }
        
        cap_value = cap_calculate_pin(pin_block, sizeof(pin_block),
                                     atc_tlv->value, atc_tlv->len,
                                     arqc_tlv->value, arqc_tlv->len);
    } else {
        cap_value = cap_calculate_no_pin(pan_tlv->value, pan_tlv->len,
                                        atc_tlv->value, atc_tlv->len,
                                        arqc_tlv->value, arqc_tlv->len);
    }
    
    // Display result
    printf("\nCAP Result: %08u\n", cap_value);
    
    // Cleanup
    tlvdb_free(select_db);
    tlvdb_free(gpo_db);
    tlvdb_free(records_db);
    tlvdb_free(gen_ac_db);
    
    return true;
}

static void print_usage(void)
{
    printf("EMV CAP Tool\n");
    printf("Usage: emv_cap [options]\n");
    printf("Options:\n");
    printf("  -h, --help            Display this help message\n");
    printf("  -a, --aid AID         Application ID to select (hex)\n");
    printf("  -v, --value AMOUNT    Transaction amount (in smallest currency unit)\n");
    printf("  -p, --pin             Use PIN for CAP calculation\n");
    printf("  -r, --reader INDEX    Use specific reader by index\n");
}

int main(int argc, char** argv)
{
    const char* aid_str = NULL;
    const char* value_str = NULL;
    int reader_index = -1;
    bool use_pin = false;

    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--aid") == 0) {
            if (i + 1 < argc)
                aid_str = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--value") == 0) {
            if (i + 1 < argc)
                value_str = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pin") == 0) {
            use_pin = true;
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--reader") == 0) {
            if (i + 1 < argc)
                reader_index = atoi(argv[++i]);
        }
    }
    
    // Default AID if not specified
    if (!aid_str) {
        aid_str = "a0000000031010"; // Visa
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
    char reader_names[MAX_READERS][MAX_READERNAME]; {};
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
   SCARDHANDLE hCard= 0;
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

// Process CAP transaction
bool success = process_cap_transaction(&scard, aid_str, value_str, use_pin);

// Cleanup
scard_disconnect(hCard, SCARD_LEAVE_CARD);
scard_release_context(hContext);

return success ? 0 : 1;
