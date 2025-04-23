// emv_sda.c - EMV Static Data Authentication tool
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winscard.h>
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

// Crypto library includes
#include "crypto_windows.h"
#include "crypto_hash.h"
#include "emv_pk.h"
#include "emv_pki.h"

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

// Add these functions to emv_sda.c for manual data input

static bool parse_hex_string(const char *hex_str, unsigned char *data, size_t *len)
{
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0)
        return false;
    
    size_t binary_len = hex_len / 2;
    if (binary_len > *len)
        return false;
    
    *len = binary_len;
    
    for (size_t i = 0; i < binary_len; i++) {
        char byte[3] = {hex_str[i*2], hex_str[i*2+1], 0};
        data[i] = (unsigned char)strtol(byte, NULL, 16);
    }
    
    return true;
}

static struct tlvdb *build_manual_db(const char *ssad_hex, const char *issuer_cert_hex, 
                                   const char *issuer_exp_hex, const char *issuer_rem_hex)
{
    struct tlvdb *db = NULL;
    
    // Parse SSAD
    if (ssad_hex && *ssad_hex) {
        unsigned char ssad[256];
        size_t ssad_len = sizeof(ssad);
        
        if (parse_hex_string(ssad_hex, ssad, &ssad_len)) {
            struct tlvdb *ssad_db = tlvdb_fixed(0x93, ssad_len, ssad);
            if (ssad_db) {
                db = ssad_db;
            }
        } else {
            printf("Error parsing SSAD hex string\n");
            return NULL;
        }
    } else {
        printf("SSAD data is required\n");
        return NULL;
    }
    
    // Parse Issuer Certificate
    if (issuer_cert_hex && *issuer_cert_hex) {
        unsigned char cert[256];
        size_t cert_len = sizeof(cert);
        
        if (parse_hex_string(issuer_cert_hex, cert, &cert_len)) {
            struct tlvdb *cert_db = tlvdb_fixed(0x90, cert_len, cert);
            if (cert_db) {
                if (db)
                    tlvdb_add(db, cert_db);
                else
                    db = cert_db;
            }
        } else {
            printf("Error parsing Issuer Certificate hex string\n");
            tlvdb_free(db);
            return NULL;
        }
    } else {
        printf("Issuer Certificate data is required\n");
        tlvdb_free(db);
        return NULL;
    }
    
    // Parse Issuer Exponent
    if (issuer_exp_hex && *issuer_exp_hex) {
        unsigned char exp[8];
        size_t exp_len = sizeof(exp);
        
        if (parse_hex_string(issuer_exp_hex, exp, &exp_len)) {
            struct tlvdb *exp_db = tlvdb_fixed(0x9F32, exp_len, exp);
            if (exp_db) {
                tlvdb_add(db, exp_db);
            }
        } else {
            printf("Error parsing Issuer Exponent hex string\n");
            tlvdb_free(db);
            return NULL;
        }
    } else {
        printf("Issuer Exponent data is required\n");
        tlvdb_free(db);
        return NULL;
    }
    
    // Parse Issuer Remainder (optional)
    if (issuer_rem_hex && *issuer_rem_hex) {
        unsigned char rem[256];
        size_t rem_len = sizeof(rem);
        
        if (parse_hex_string(issuer_rem_hex, rem, &rem_len)) {
            struct tlvdb *rem_db = tlvdb_fixed(0x92, rem_len, rem);
            if (rem_db) {
                tlvdb_add(db, rem_db);
            }
        } else {
            printf("Error parsing Issuer Remainder hex string\n");
            // This is optional, so don't fail if it's wrong
        }
    }
    
    // Add Public Key Index (hardcoded for manual mode, can be made configurable)
    unsigned char pk_index = 0x01; // Default to index 1
    tlvdb_add(db, tlvdb_fixed(0x8F, 1, &pk_index));
    
    return db;
}

static bool process_manual_sda_verification(const char *ssad_hex, const char *issuer_cert_hex,
                                          const char *issuer_exp_hex, const char *issuer_rem_hex,
                                          const char *ca_key_file, const char *rid_hex)
{
    printf("Processing manual SDA verification\n");
    
    // Build TLV database from manual inputs
    struct tlvdb *records_db = build_manual_db(ssad_hex, issuer_cert_hex, issuer_exp_hex, issuer_rem_hex);
    if (!records_db) {
        printf("Failed to build TLV database from manual inputs\n");
        return false;
    }
    
    // Parse RID
    unsigned char rid[5] = {0};
    size_t rid_len = sizeof(rid);
    
    if (!rid_hex || !parse_hex_string(rid_hex, rid, &rid_len) || rid_len != 5) {
        printf("Invalid RID - using default A000000003 (Visa)\n");
        rid[0] = 0xA0; rid[1] = 0x00; rid[2] = 0x00; rid[3] = 0x00; rid[4] = 0x03;
    }
    
    // Get Public Key Index
    const struct tlv *pk_index_tlv = tlvdb_get(records_db, 0x8F, NULL);
    if (!pk_index_tlv || pk_index_tlv->len != 1) {
        printf("Public Key Index not found or invalid\n");
        tlvdb_free(records_db);
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
            tlvdb_free(records_db);
            return false;
        }
        
        char buf[1024];
        if (fgets(buf, sizeof(buf), f) == NULL) {
            printf("Failed to read CA key file\n");
            fclose(f);
            tlvdb_free(records_db);
            return false;
        }
        
        fclose(f);
        
        ca_pk = emv_pk_parse_pk(buf);
    } else {
        // Try to find CA key in default locations
        ca_pk = emv_pk_get_ca_pk(rid, pk_index_tlv->value[0]);
    }
    
    if (!ca_pk) {
        printf("CA Public Key not found\n");
        tlvdb_free(records_db);
        return false;
    }
    
    // Recover Issuer Public Key
    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(ca_pk, records_db);
    if (!issuer_pk) {
        printf("Failed to recover Issuer Public Key\n");
        emv_pk_free(ca_pk);
        tlvdb_free(records_db);
        return false;
    }
    
    printf("Successfully recovered Issuer Public Key:\n");
    printf("  RID: ");
    print_hex(issuer_pk->rid, 5);
    printf("\n  Index: %02x\n", issuer_pk->index);
    printf("  Modulus length: %zu bytes\n", issuer_pk->mlen);
    
    // SDA verification
    printf("Verifying SDA...\n");
    bool verified = emv_pki_verify_sig(issuer_pk, records_db, 0x93, 0, 0);
    
    printf("SDA verification %s\n", verified ? "SUCCESSFUL" : "FAILED");
    
    // Cleanup
    emv_pk_free(ca_pk);
    emv_pk_free(issuer_pk);
    tlvdb_free(records_db);
    
    return verified;
}

static bool process_sda_verification(struct sc *scard, const char *aid_str, 
                                    const char *ca_key_file)
{
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
        printf("APPLICATION SELECTION failed\n");
        return false;
    }
    
    // Extract PAN for later
    const struct tlv *pan_tlv = tlvdb_get(select_db, 0x5A, NULL);
    if (!pan_tlv) {
        printf("PAN not found in SELECT response\n");
        tlvdb_free(select_db);
        return false;
    }
    
    unsigned char pan[10];
    size_t pan_len = pan_tlv->len > 10 ? 10 : pan_tlv->len;
    memcpy(pan, pan_tlv->value, pan_len);
    
    // Get processing options
    printf("Getting processing options...\n");
    struct tlvdb *gpo_db = emv_get_processing_options(scard, NULL);
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
    
    if (!aip_tlv) {
        printf("Application Interchange Profile (AIP) not found\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        return false;
    }
    
    // Check if SDA is supported
    if (!(aip_tlv->value[0] & 0x40)) {
        printf("SDA not supported by this card!\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        return false;
    }
    
    if (afl_tlv) {
        // Read records according to AFL
        struct tlvdb *afl_db = tlvdb_fixed(0x94, afl_tlv->len, afl_tlv->value);
        records_db = emv_read_records(scard, pan, afl_db);
        tlvdb_free(afl_db);
    }
    
    if (!records_db) {
        printf("Failed to read application data\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        return false;
    }
    
    // Find the Signed Static Application Data (SSAD)
    const struct tlv *ssad_tlv = tlvdb_get(records_db, 0x93, NULL);
    if (!ssad_tlv) {
        printf("Signed Static Application Data (tag 0x93) not found\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    printf("Found Signed Static Application Data:\n");
    print_tlv(ssad_tlv);
    
    // Get Issuer Public Key Certificate
    const struct tlv *cert_tlv = tlvdb_get(records_db, 0x90, NULL);
    if (!cert_tlv) {
        printf("Issuer Public Key Certificate not found\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    // Get Issuer PK Remainder (if any)
    const struct tlv *pk_rem_tlv = tlvdb_get(records_db, 0x92, NULL);
    
    // Get Issuer PK Exponent
    const struct tlv *pk_exp_tlv = tlvdb_get(records_db, 0x9F32, NULL);
    if (!pk_exp_tlv) {
        printf("Issuer Public Key Exponent not found\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    // Get CA Public Key from file if provided
    unsigned char rid[5];
    memcpy(rid, aid, 5); // RID is first 5 bytes of AID
    
    // Get Public Key Index
    const struct tlv *pk_index_tlv = tlvdb_get(records_db, 0x8F, NULL);
    if (!pk_index_tlv || pk_index_tlv->len != 1) {
        printf("Public Key Index not found or invalid\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
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
            tlvdb_free(select_db);
            tlvdb_free(gpo_db);
            tlvdb_free(records_db);
            return false;
        }
        
        char buf[1024];
        if (fgets(buf, sizeof(buf), f) == NULL) {
            printf("Failed to read CA key file\n");
            fclose(f);
            tlvdb_free(select_db);
            tlvdb_free(gpo_db);
            tlvdb_free(records_db);
            return false;
        }
        
        fclose(f);
        
        ca_pk = emv_pk_parse_pk(buf);
        if (!ca_pk) {
            printf("Failed to parse CA public key\n");
            tlvdb_free(select_db);
            tlvdb_free(gpo_db);
            tlvdb_free(records_db);
            return false;
        }
    } else {
        // Try to find CA key in default locations
        ca_pk = emv_pk_get_ca_pk(rid, pk_index_tlv->value[0]);
        if (!ca_pk) {
            printf("CA Public Key not found\n");
            tlvdb_free(select_db);
            tlvdb_free(gpo_db);
            tlvdb_free(records_db);
            return false;
        }
    }
    
    // Recover Issuer Public Key
    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(ca_pk, records_db);
    if (!issuer_pk) {
        printf("Failed to recover Issuer Public Key\n");
        emv_pk_free(ca_pk);
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    printf("Successfully recovered Issuer Public Key:\n");
    printf("  RID: ");
    print_hex(issuer_pk->rid, 5);
    printf("\n  Index: %02x\n", issuer_pk->index);
    printf("  Modulus length: %zu bytes\n", issuer_pk->mlen);
    
    // SDA verification
    printf("Verifying SDA...\n");
    bool verified = emv_pki_verify_sig(issuer_pk, records_db, 0x93, 0, 0);
    
    printf("SDA verification %s\n", verified ? "SUCCESSFUL" : "FAILED");
    
    // Cleanup
    emv_pk_free(ca_pk);
    emv_pk_free(issuer_pk);
    tlvdb_free(select_db);
    tlvdb_free(gpo_db);
    tlvdb_free(records_db);
    
    return verified;
}

static void print_usage(void)
{
    printf("EMV SDA Verification Tool\n");
    printf("Usage: emv_sda [options]\n");
    printf("Card mode options:\n");
    printf("  -h, --help            Display this help message\n");
    printf("  -a, --aid AID         Application ID to select (hex)\n");
    printf("  -c, --cakey FILE      CA Public Key file\n");
    printf("  -r, --reader INDEX    Use specific reader by index\n");
    printf("\nManual mode options:\n");
    printf("  -m, --manual          Use manual data input instead of card\n");
    printf("  -s, --ssad HEX        Signed Static Application Data (hex)\n");
    printf("  -i, --issuer-cert HEX Issuer Certificate (hex)\n");
    printf("  -e, --issuer-exp HEX  Issuer Exponent (hex)\n");
    printf("  -x, --issuer-rem HEX  Issuer Remainder (hex, optional)\n");
    printf("  -d, --rid HEX         RID for CA key lookup (hex, 5 bytes)\n");
}

int main(int argc, char **argv)
{
    const char *aid_str = NULL;
    const char *ca_key_file = NULL;
    int reader_index = -1;
    bool manual_mode = false;
    
    // Manual mode parameters
    const char *ssad_hex = NULL;
    const char *issuer_cert_hex = NULL;
    const char *issuer_exp_hex = NULL;
    const char *issuer_rem_hex = NULL;
    const char *rid_hex = NULL;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--aid") == 0) {
            if (i + 1 < argc)
                aid_str = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cakey") == 0) {
            if (i + 1 < argc)
                ca_key_file = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--reader") == 0) {
            if (i + 1 < argc)
                reader_index = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--manual") == 0) {
            manual_mode = true;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--ssad") == 0) {
            if (i + 1 < argc)
                ssad_hex = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--issuer-cert") == 0) {
            if (i + 1 < argc)
                issuer_cert_hex = argv[++i];
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--issuer-exp") == 0) {
            if (i + 1 < argc)
                issuer_exp_hex = argv[++i];
        } else if (strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--issuer-rem") == 0) {
            if (i + 1 < argc)
                issuer_rem_hex = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--rid") == 0) {
            if (i + 1 < argc)
                rid_hex = argv[++i];
        }
    }
    
    // Default AID if not specified for card mode
    if (!manual_mode && !aid_str) {
        aid_str = "a0000000031010"; // Visa
    }
    
    // Initialize EMV configuration
    emv_config_init(NULL);
    
    // Initialize cryptographic subsystem
    emv_crypto_init();
    
    bool success = false;
    
    if (manual_mode) {
        // Check required parameters for manual mode
        if (!ssad_hex || !issuer_cert_hex || !issuer_exp_hex) {
            printf("Manual mode requires SSAD, issuer certificate, and issuer exponent\n");
            print_usage();
            return 1;
        }
        
        // Process manual SDA verification
        success = process_manual_sda_verification(ssad_hex, issuer_cert_hex, issuer_exp_hex, 
                                               issuer_rem_hex, ca_key_file, rid_hex);
    } else {
        // Card mode - use PC/SC to interact with physical card
        SCARDCONTEXT hContext;
        LONG result = scard_establish_context(&hContext);
        if (result != SCARD_S_SUCCESS) {
            printf("Failed to establish smart card context: %s\n", pcsc_stringify_error(result));
            return 1;
        }
        
        // [rest of the card mode code as before...]
        
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
        
        // [select reader, connect to card, etc. as before...]
        
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
        DWORD dwActiveProtocol= 0;
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
        
        // Process SDA verification
        success = process_sda_verification(&scard, aid_str, ca_key_file);
        
        // Cleanup
        scard_disconnect(hCard, SCARD_LEAVE_CARD);
        scard_release_context(hContext);
    }
    
    return success ? 0 : 1;
}
