// emv_dda.c - EMV Dynamic Data Authentication tool
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

static bool process_dda_verification(struct sc *scard, const char *aid_str, 
                                    const char *ca_key_file, bool verbose)
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
    
    if (verbose) {
        printf("PAN: ");
        print_hex(pan, pan_len);
        printf("\n");
    }
    
    // Get processing options
    printf("Getting processing options...\n");
    struct tlvdb *gpo_db = emv_get_processing_options(scard, NULL);
    if (!gpo_db) {
        printf("GET PROCESSING OPTIONS failed\n");
        tlvdb_free(select_db);
        return false;
    }
    
    // Check if DDA is supported
    const struct tlv *aip_tlv = tlvdb_get(gpo_db, 0x82, NULL);
    if (!aip_tlv || aip_tlv->len < 2) {
        printf("Application Interchange Profile not found or invalid\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        return false;
    }
    
    bool dda_supported = (aip_tlv->value[0] & 0x20) != 0;
    if (!dda_supported) {
        printf("DDA not supported by this card. AIP: %02x %02x\n", 
              aip_tlv->value[0], aip_tlv->value[1]);
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        return false;
    }
    
    printf("DDA supported by this card. AIP: %02x %02x\n", 
          aip_tlv->value[0], aip_tlv->value[1]);
    
    // Read application records
    printf("Reading application data...\n");
    struct tlvdb *records_db = NULL;
    const struct tlv *afl_tlv = tlvdb_get(gpo_db, 0x94, NULL);
    
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
    
    // Get RID from AID
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
    
    // Get Issuer Public Key Certificate
    const struct tlv *issuer_cert_tlv = tlvdb_get(records_db, 0x90, NULL);
    if (!issuer_cert_tlv) {
        printf("Issuer Public Key Certificate not found\n");
        emv_pk_free(ca_pk);
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    // Get Issuer PK Remainder (if any)
    const struct tlv *issuer_rem_tlv = tlvdb_get(records_db, 0x92, NULL);
    
    // Get Issuer PK Exponent
    const struct tlv *issuer_exp_tlv = tlvdb_get(records_db, 0x9F32, NULL);
    if (!issuer_exp_tlv) {
        printf("Issuer Public Key Exponent not found\n");
        emv_pk_free(ca_pk);
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
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
    
    // Get ICC Public Key Certificate
    const struct tlv *icc_cert_tlv = tlvdb_get(records_db, 0x9F46, NULL);
    if (!icc_cert_tlv) {
        printf("ICC Certificate not found\n");
        emv_pk_free(ca_pk);
        emv_pk_free(issuer_pk);
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    // Get ICC Public Key Exponent
    const struct tlv *icc_exp_tlv = tlvdb_get(records_db, 0x9F47, NULL);
    if (!icc_exp_tlv) {
        printf("ICC Public Key Exponent not found\n");
        emv_pk_free(ca_pk);
        emv_pk_free(issuer_pk);
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    // Get ICC Public Key Remainder
    const struct tlv *icc_rem_tlv = tlvdb_get(records_db, 0x9F48, NULL);
    
    // Recover ICC Public Key
    struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, records_db, pan, pan_len);
    if (!icc_pk) {
        printf("Failed to recover ICC Public Key\n");
        emv_pk_free(ca_pk);
        emv_pk_free(issuer_pk);
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    printf("Successfully recovered ICC Public Key:\n");
    printf("  RID: ");
    print_hex(icc_pk->rid, 5);
    printf("\n  Modulus length: %zu bytes\n", icc_pk->mlen);
    
    // Prepare data for Internal Authenticate
    // Generate unpredictable number
    unsigned char ddol_data[32] = {0};
    size_t ddol_data_len = 4; // Default UN size
    
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < ddol_data_len; i++) {
        ddol_data[i] = rand() & 0xFF;
    }
    
    // Check for DDOL
    const struct tlv *ddol_tlv = tlvdb_get(records_db, 0x9F49, NULL);
    if (ddol_tlv) {
        // Parse DDOL
        struct dol ddol = {
            .data = ddol_tlv->value,
            .len = ddol_tlv->len
        };
        
        // Create DDOL data
        struct tlvdb *temp_db = tlvdb_fixed(0x9F37, 4, ddol_data); // Unpredictable number
        
        // Process DDOL
        struct tlvdb *ddol_db = dol_process(0x9F49, &ddol, temp_db);
        tlvdb_free(temp_db);
        
        if (ddol_db) {
            const struct tlv *processed_ddol = &ddol_db->tag;
            if (processed_ddol->len <= sizeof(ddol_data)) {
                memcpy(ddol_data, processed_ddol->value, processed_ddol->len);
                ddol_data_len = processed_ddol->len;
            }
            tlvdb_free(ddol_db);
        }
    }
    
    // Perform Internal Authenticate
    printf("Performing INTERNAL AUTHENTICATE with challenge:\n  ");
    print_hex(ddol_data, ddol_data_len);
    printf("\n");
    
    struct tlvdb *ddol_db = tlvdb_fixed(0xAA, ddol_data_len, ddol_data);
    struct tlvdb *auth_db = emv_internal_authenticate(scard, ddol_db);
    tlvdb_free(ddol_db);
    
    if (!auth_db) {
        printf("INTERNAL AUTHENTICATE failed\n");
        emv_pk_free(ca_pk);
        emv_pk_free(issuer_pk);
        emv_pk_free(icc_pk);
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        return false;
    }
    
    // Extract Signed Dynamic Application Data
    const struct tlv *sdad_tlv = tlvdb_get(auth_db, 0x9F4B, NULL);
    if (!sdad_tlv) {
        printf("Signed Dynamic Application Data not found\n");
        emv_pk_free(ca_pk);
        emv_pk_free(issuer_pk);
        emv_pk_free(icc_pk);
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        tlvdb_free(records_db);
        tlvdb_free(auth_db);
        return false;
    }
    
    printf("Received Signed Dynamic Application Data:\n  ");
    print_hex(sdad_tlv->value, sdad_tlv->len);
    printf("\n");
    
    // Create a combined database for verification
    struct tlvdb *combined_db = tlvdb_fixed(0xFF, 0, NULL); // Dummy root
    tlvdb_add(combined_db, tlvdb_fixed(0x9F4B, sdad_tlv->len, sdad_tlv->value)); // SDAD
    tlvdb_add(combined_db, tlvdb_fixed(0xAA, ddol_data_len, ddol_data)); // Challenge data
    
    // Verify DDA signature
    printf("Verifying DDA signature...\n");
    bool verified = emv_pki_verify_sig(icc_pk, combined_db, 0x9F4B, 0xAA, 0);
    
    printf("DDA verification %s\n", verified ? "SUCCESSFUL" : "FAILED");
    
    // Dump all data in verbose mode
    if (verbose) {
        printf("\nSELECT Response:\n");
        tlvdb_dump(select_db, stdout);
        
        printf("\nGPO Response:\n");
        tlvdb_dump(gpo_db, stdout);
        
        printf("\nApplication Records:\n");
        tlvdb_dump(records_db, stdout);
        
        printf("\nINTERNAL AUTHENTICATE Response:\n");
        tlvdb_dump(auth_db, stdout);
    }
    
    // Cleanup
    emv_pk_free(ca_pk);
    emv_pk_free(issuer_pk);
    emv_pk_free(icc_pk);
    tlvdb_free(select_db);
    tlvdb_free(gpo_db);
    tlvdb_free(records_db);
    tlvdb_free(auth_db);
    tlvdb_free(combined_db);
    
    return verified;
}

static void print_usage(void)
{
    printf("EMV Dynamic Data Authentication Tool\n");
    printf("Usage: emv_dda [options]\n");
    printf("Options:\n");
    printf("  -h, --help            Display this help message\n");
    printf("  -a, --aid AID         Application ID to select (hex)\n");
    printf("  -c, --cakey FILE      CA Public Key file\n");
    printf("  -r, --reader INDEX    Use specific reader by index\n");
    printf("  -v, --verbose         Verbose output\n");
}

int main(int argc, char **argv)
{
    const char *aid_str = NULL;
    const char *ca_key_file = NULL;
    int reader_index = -1;
    bool verbose = false;
    
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
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
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
    
    // Process DDA verification
    bool success = process_dda_verification(&scard, aid_str, ca_key_file, verbose);
    
    // Cleanup
    scard_disconnect(hCard, SCARD_LEAVE_CARD);
    scard_release_context(hContext);
    
    return success ? 0 : 1;
}