// emv_cl_cda.c - EMV Contactless CDA verification tool
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

// Crypto library includes
#include "crypto_windows.h"
#include "emv_pk.h"
#include "emv_pki.h"

// Smart card library includes
#include "scard_common.h"
#include "apdu_processing.h"
#include "emv_commands.h"

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

static struct tlvdb *perform_contactless_transaction(struct sc *scard, const char *aid_str, 
                                                    const char *value_str, bool force_online)
{
    if (!scard || !aid_str)
        return NULL;
    
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
        return NULL;
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
        
        // Build TTQ (Terminal Transaction Qualifiers)
        // Bit definitions from EMV Contactless Book C-3
        unsigned char ttq[4] = {0};
        
        // Byte 1
        ttq[0] |= 0x80; // MSD supported
        ttq[0] |= 0x40; // EMV mode supported
        ttq[0] |= 0x20; // EMV contact chip supported
        
        // Byte 2
        ttq[1] |= 0x80; // Online cryptogram required
        if (force_online)
            ttq[1] |= 0x40; // Online cryptogram if possible
        ttq[1] |= 0x20; // Offline PIN supported
        
        // Byte 3
        ttq[2] |= 0x80; // Signature supported
        ttq[2] |= 0x40; // Online PIN supported
        
        // Byte 4
        ttq[3] |= 0x80; // Issuer Update Processing supported
        ttq[3] |= 0x20; // Consumer Device CVM supported
        
        // Fill PDOL with terminal data
        struct tlvdb *temp_db = tlvdb_fixed(0x9F66, 4, ttq); // TTQ
        
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
            // Zero amount for no amount transaction
            unsigned char amount[6] = {0};
            tlvdb_add(temp_db, tlvdb_fixed(0x9F02, sizeof(amount), amount));
        }
        
        // Add unpredictable number
        srand((unsigned int)time(NULL));
        unsigned char un[4];
        for (int i = 0; i < 4; i++) {
            un[i] = rand() & 0xFF;
        }
        tlvdb_add(temp_db, tlvdb_fixed(0x9F37, sizeof(un), un));
        
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
        return NULL;
    }
    
    // Get processing options
    printf("Getting processing options...\n");
    struct tlvdb *gpo_db = emv_get_processing_options(scard, pdol_data_db);
    tlvdb_free(pdol_data_db);
    
    if (!gpo_db) {
        printf("GET PROCESSING OPTIONS failed\n");
        tlvdb_free(select_db);
        return NULL;
    }
    
    // Check Application Interchange Profile for CDA support
    const struct tlv *aip_tlv = tlvdb_get(gpo_db, 0x82, NULL);
    if (!aip_tlv || aip_tlv->len < 2) {
        printf("Application Interchange Profile not found or invalid\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        return NULL;
    }
    
    // Check if CDA is supported (bit 3 of byte 1)
    bool cda_supported = (aip_tlv->value[0] & 0x01) != 0;
    if (!cda_supported) {
        printf("CDA not supported by this card. AIP: %02x %02x\n", 
              aip_tlv->value[0], aip_tlv->value[1]);
    } else {
        printf("CDA supported by this card. AIP: %02x %02x\n", 
              aip_tlv->value[0], aip_tlv->value[1]);
    }
    
    // Read application records
    printf("Reading application data...\n");
    struct tlvdb *records_db = NULL;
    const struct tlv *afl_tlv = tlvdb_get(gpo_db, 0x94, NULL);
    
    if (afl_tlv) {
        // Read records according to AFL
        unsigned char pan[10] = {0};
        const struct tlv *pan_tlv = tlvdb_get(select_db, 0x5A, NULL);
        if (pan_tlv) {
            size_t pan_len = pan_tlv->len > 10 ? 10 : pan_tlv->len;
            memcpy(pan, pan_tlv->value, pan_len);
        }
        
        struct tlvdb *afl_db = tlvdb_fixed(0x94, afl_tlv->len, afl_tlv->value);
        records_db = emv_read_records(scard, *pan, afl_db);
        tlvdb_free(afl_db);
    }
    
    if (!records_db) {
        printf("Failed to read application data\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        return NULL;
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
            // Zero amount for no amount transaction
            unsigned char amount[6] = {0};
            tlvdb_add(temp_db, tlvdb_fixed(0x9F02, sizeof(amount), amount));
        }
        
        // Add unpredictable number
        srand((unsigned int)time(NULL));
        unsigned char un[4];
        for (int i = 0; i < 4; i++) {
            un[i] = rand() & 0xFF;
        }
        tlvdb_add(temp_db, tlvdb_fixed(0x9F37, sizeof(un), un));
        
        // Process CDOL1
        cdol_data_db = dol_process(0x8C, &cdol1, temp_db);
        tlvdb_free(temp_db);
    }
    
    if (!cdol_data_db) {
        printf("Failed to prepare CDOL1 data\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return NULL;
    }
    
    // Generate AC
    printf("Generating cryptogram...\n");
    unsigned char ac_type = force_online ? 0x80 : 0x40; // ARQC or TC
    struct tlvdb *gen_ac_db = emv_generate_ac(scard, ac_type, cdol_data_db);
    tlvdb_free(cdol_data_db);
    
    if (!gen_ac_db) {
        printf("GENERATE AC failed\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return NULL;
    }
    
    // Create combined database with all the transaction data
    struct tlvdb *result_db = tlvdb_fixed(0xFF, 0, NULL); // Dummy tag
    
    // Add data from SELECT
    tlvdb_add(result_db, select_db);
    
    // Add data from GPO
    tlvdb_add(result_db, gpo_db);
    
    // Add data from READ RECORD
    tlvdb_add(result_db, records_db);
    
    // Add data from GENERATE AC
    tlvdb_add(result_db, gen_ac_db);
    
    return result_db;
}

static bool verify_cda(struct tlvdb *transaction_db, const char *ca_key_file)
{
    if (!transaction_db)
        return false;
    
    // Get ICC Public Key Certificate
    const struct tlv *icc_cert_tlv = tlvdb_get(transaction_db, 0x9F46, NULL);
    if (!icc_cert_tlv) {
        printf("ICC Certificate not found\n");
        return false;
    }
    
    // Get ICC Public Key Exponent
    const struct tlv *icc_exp_tlv = tlvdb_get(transaction_db, 0x9F47, NULL);
    if (!icc_exp_tlv) {
        printf("ICC Public Key Exponent not found\n");
        return false;
    }
    
    // Get ICC Public Key Remainder
    const struct tlv *icc_rem_tlv = tlvdb_get(transaction_db, 0x9F48, NULL);
    
    // Get PAN from track 2 equivalent data or PAN
    const struct tlv *track2_tlv = tlvdb_get(transaction_db, 0x57, NULL);
    const struct tlv *pan_tlv = tlvdb_get(transaction_db, 0x5A, NULL);
    
    unsigned char pan[10] = {0};
    size_t pan_len = 0;
    
    if (track2_tlv) {
        // Extract PAN from track 2
        for (size_t i = 0; i < track2_tlv->len && i < 10 && track2_tlv->value[i] != 'D'; i++) {
            pan[i] = track2_tlv->value[i];
            pan_len++;
        }
    } else if (pan_tlv) {
        // Use PAN directly
        pan_len = pan_tlv->len > 10 ? 10 : pan_tlv->len;
        memcpy(pan, pan_tlv->value, pan_len);
    } else {
        printf("PAN not found\n");
        return false;
    }
    
    // Get Issuer Public Key Certificate
    const struct tlv *issuer_cert_tlv = tlvdb_get(transaction_db, 0x90, NULL);
    if (!issuer_cert_tlv) {
        printf("Issuer Certificate not found\n");
        return false;
    }
    
    // Get Issuer PK Remainder
    const struct tlv *issuer_rem_tlv = tlvdb_get(transaction_db, 0x92, NULL);
    
    // Get Issuer PK Exponent
    const struct tlv *issuer_exp_tlv = tlvdb_get(transaction_db, 0x9F32, NULL);
    if (!issuer_exp_tlv) {
        printf("Issuer Public Key Exponent not found\n");
        return false;
    }
    
    // Get RID from AID
    const struct tlv *aid_tlv = tlvdb_get(transaction_db, 0x4F, NULL);
    if (!aid_tlv || aid_tlv->len < 5) {
        printf("AID not found or too short\n");
        return false;
    }
    
    unsigned char rid[5];
    memcpy(rid, aid_tlv->value, 5);
    
    // Get Public Key Index
    const struct tlv *pk_index_tlv = tlvdb_get(transaction_db, 0x8F, NULL);
    if (!pk_index_tlv || pk_index_tlv->len != 1) {
        printf("Public Key Index not found or invalid\n");
        return false;
    }
    
    printf("Using CA Public Key with RID: ");
    print_hex(rid, 5);
    printf(" Index: %02x\n", pk_index_tlv->value[0]);
    
    // Get CA Public Key
    struct emv_pk *ca_pk;
    if (ca_key_file) {
        // Use provided CA key file
        FILE *f = fopen(ca_key_file, "r");
        if (!f) {
            printf("Failed to open CA key file: %s\n", ca_key_file);
            return false;
        }
        
        char buf[1024];
        if (fgets(buf, sizeof(buf), f) == NULL) {
            printf("Failed to read CA key file\n");
            fclose(f);
            return false;
        }
        
        fclose(f);
        
        ca_pk = emv_pk_parse_pk(buf);
        if (!ca_pk) {
            printf("Failed to parse CA public key\n");
            return false;
        }
    } else {
        // Try to find CA key in default locations
        ca_pk = emv_pk_get_ca_pk(rid, pk_index_tlv->value[0]);
        if (!ca_pk) {
            printf("CA Public Key not found\n");
            return false;
        }
    }
    
    // Recover Issuer Public Key
    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(ca_pk, transaction_db);
    if (!issuer_pk) {
        printf("Failed to recover Issuer Public Key\n");
        emv_pk_free(ca_pk);
        return false;
    }
    
    printf("Successfully recovered Issuer Public Key:\n");
    printf("  RID: ");
    print_hex(issuer_pk->rid, 5);
    printf("\n  Index: %02x\n", issuer_pk->index);
    printf("  Modulus length: %zu bytes\n", issuer_pk->mlen);
    
    // Recover ICC Public Key
    struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, transaction_db, pan, pan_len);
    if (!icc_pk) {
        printf("Failed to recover ICC Public Key\n");
        emv_pk_free(ca_pk);
        emv_pk_free(issuer_pk);
        return false;
    }
    
    printf("Successfully recovered ICC Public Key:\n");
    printf("  RID: ");
    print_hex(icc_pk->rid, 5);
    printf("\n  Modulus length: %zu bytes\n", icc_pk->mlen);
    
    // Get Signed Dynamic Application Data (for CDA)
    const struct tlv *sdad_tlv = tlvdb_get(transaction_db, 0x9F4B, NULL);
    if (!sdad_tlv) {
        printf("Signed Dynamic Application Data not found - CDA not performed\n");
        emv_pk_free(ca_pk);
        emv_pk_free(issuer_pk);
        emv_pk_free(icc_pk);
        return false;
    }
    
    // Get cryptogram for verification
    const struct tlv *cryptogram_tlv = tlvdb_get(transaction_db, 0x9F26, NULL);
    if (!cryptogram_tlv) {
        printf("Cryptogram not found\n");
        emv_pk_free(ca_pk);
        emv_pk_free(issuer_pk);
        emv_pk_free(icc_pk);
        return false;
    }
    
    printf("Cryptogram: ");
    print_hex(cryptogram_tlv->value, cryptogram_tlv->len);
    printf("\n");
    
    // Verify CDA signature
    printf("Verifying CDA signature...\n");
    bool verified = emv_pki_verify_sig(icc_pk, transaction_db, 0x9F4B, 0, 0);
    
    printf("CDA verification %s\n", verified ? "SUCCESSFUL" : "FAILED");
    
    // Cleanup
    emv_pk_free(ca_pk);
    emv_pk_free(issuer_pk);
    emv_pk_free(icc_pk);
    
    return verified;
}

static void print_usage(void)
{
    printf("EMV Contactless CDA Verification Tool\n");
    printf("Usage: emv_cl_cda [options]\n");
    printf("Options:\n");
    printf("  -h, --help            Display this help message\n");
    printf("  -a, --aid AID         Application ID to select (hex)\n");
    printf("  -v, --value AMOUNT    Transaction amount (in smallest currency unit)\n");
    printf("  -o, --online          Force online transaction (ARQC)\n");
    printf("  -c, --cakey FILE      CA Public Key file\n");
    printf("  -r, --reader INDEX    Use specific reader by index\n");
}

int main(int argc, char **argv)
{
    const char *aid_str = NULL;
    const char *value_str = NULL;
    const char *ca_key_file = NULL;
    int reader_index = -1;
    bool force_online = false;
    
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
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--online") == 0) {
            force_online = true;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cakey") == 0) {
            if (i + 1 < argc)
                ca_key_file = argv[++i];
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
    
    // Initialize cryptographic subsystem
    emv_crypto_init();
    
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
    
    // Perform contactless EMV transaction
    struct tlvdb *transaction_db = perform_contactless_transaction(&scard, aid_str, value_str, force_online);
    if (!transaction_db) {
        printf("Transaction failed\n");
        scard_disconnect(hCard, SCARD_LEAVE_CARD);
        scard_release_context(hContext);
        return 1;
    }
    
    // Verify CDA signature
    bool success = verify_cda(transaction_db, ca_key_file);
    
    // Print all transaction data
    printf("\nTransaction Data:\n");
    tlvdb_dump(transaction_db, stdout);
    
    // Cleanup
    tlvdb_free(transaction_db);
    scard_disconnect(hCard, SCARD_LEAVE_CARD);
    scard_release_context(hContext);
    
    return success ? 0 : 1;
}