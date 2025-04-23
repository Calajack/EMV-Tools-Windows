// emv_operations.c - High-level operations for EMV Tools
#include "emv_operations.h"
#include "emv_file_utils.h"
#include "emv_certificate_ops.h"
#include "emv_tags.h"
#include "emv_commands.h"
#include "emv_pk.h"
#include "crypto_windows.h"
#include "dol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

// Forward declaration of format_tlv_to_file function if it's not already in a header
static void format_tlv_to_file(const struct tlv* tlv, void* data);

// Helper to ensure directory exists
static bool ensure_directory_exists(const char* dir) {
    if (!dir || strlen(dir) == 0)
        return false;

    // Create path
    char path[MAX_PATH];
    strncpy(path, dir, sizeof(path) - 1);

    // Add trailing backslash if needed
    size_t len = strlen(path);
    if (path[len - 1] != '\\') {
        path[len] = '\\';
        path[len + 1] = '\0';
    }

    return CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

// Helper to format path with directory and filename
static void format_path(char* out_path, size_t out_size,
    const char* dir, const char* filename) {
    if (!out_path || !dir || !filename)
        return;

    // Create path
    strncpy(out_path, dir, out_size - 1);
    out_path[out_size - 1] = '\0';

    // Add trailing backslash if needed
    size_t len = strlen(out_path);
    if (len > 0 && out_path[len - 1] != '\\') {
        out_path[len] = '\\';
        out_path[len + 1] = '\0';
    }

    // Add filename
    strncat(out_path, filename, out_size - strlen(out_path) - 1);
}

// Helper to convert hex string to binary
static bool hex_to_bin(const char* hex, unsigned char* bin, size_t* bin_len) {
    if (!hex || !bin || !bin_len)
        return false;

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
        return false;

    size_t len = hex_len / 2;
    if (*bin_len < len)
        return false;

    *bin_len = len;

    for (size_t i = 0; i < len; i++) {
        char byte[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        bin[i] = (unsigned char)strtol(byte, NULL, 16);
    }

    return true;
}

// Helper function to format a TLV to a file - implementation of the forward declaration
static void format_tlv_to_file(const struct tlv* tlv, void* data) {
    if (!tlv || !data) return;

    FILE* f = (FILE*)data;

    const char* name = tlv_tag_get_name(tlv->tag);
    const char* desc = tlv_tag_get_description(tlv->tag);

    fprintf(f, "Tag: %04X", tlv->tag);
    if (name)
        fprintf(f, " (%s)", name);
    fprintf(f, "\n");

    fprintf(f, "Length: %zu bytes\n", tlv->len);
    fprintf(f, "Value: ");

    // Special handling for specific tags
    if (tlv->tag == 0x5A) { // PAN
        // Format PAN with spaces for readability
        for (size_t i = 0; i < tlv->len; i++) {
            fprintf(f, "%02X", tlv->value[i]);
            if ((i + 1) % 2 == 0 && i < tlv->len - 1) fprintf(f, " ");
        }
    }
    else if (tlv->tag == 0x5F24) { // Expiration Date
        if (tlv->len >= 3) {
            fprintf(f, "20%02X/%02X", tlv->value[0], tlv->value[1]);
        }
        else {
            // Regular hex dump for unexpected format
            for (size_t i = 0; i < tlv->len; i++) {
                fprintf(f, "%02X", tlv->value[i]);
            }
        }
    }
    else if (tlv->tag == 0x5F20) { // Cardholder Name
        // Print as ASCII if printable
        for (size_t i = 0; i < tlv->len; i++) {
            unsigned char c = tlv->value[i];
            if (c >= 32 && c <= 126) {
                fprintf(f, "%c", c);
            }
            else {
                fprintf(f, "\\x%02X", c);
            }
        }
    }
    else {
        // Default hex dump for other tags
        for (size_t i = 0; i < tlv->len; i++) {
            fprintf(f, "%02X", tlv->value[i]);
            if ((i + 1) % 16 == 0 && i < tlv->len - 1) fprintf(f, "\n       ");
        }
    }
    fprintf(f, "\n");

    if (desc) fprintf(f, "Description: %s\n", desc);
    fprintf(f, "\n");
}

// Perform a complete EMV transaction
bool emv_perform_transaction(const char* reader_name,
    const char* aid,
    const char* amount,
    bool online,
    const char* output_dir) {
    if (!reader_name || !output_dir)
        return false;

    if (!ensure_directory_exists(output_dir))
        return false;

    // Initialize card context
    SCARDCONTEXT hContext;
    LONG result = scard_establish_context(&hContext);
    if (result != SCARD_S_SUCCESS) {
        printf("Failed to establish smart card context: %s\n", pcsc_stringify_error(result));
        return false;
    }

    // Connect to card
    SCARDHANDLE hCard;
    DWORD dwActiveProtocol;
    result = scard_connect(hContext, reader_name, &hCard, &dwActiveProtocol);
    if (result != SCARD_S_SUCCESS) {
        printf("Failed to connect to card: %s\n", pcsc_stringify_error(result));
        scard_release_context(hContext);
        return false;
    }

    // Create SC structure for EMV commands
    struct sc scard = {
        .hContext = hContext,
        .hCard = hCard,
        .dwActiveProtocol = dwActiveProtocol
    };

    // Parse AID
    unsigned char aid_bin[16] = { 0 };
    size_t aid_len = sizeof(aid_bin);

    if (aid && !hex_to_bin(aid, aid_bin, &aid_len)) {
        printf("Invalid AID format\n");
        scard_disconnect(hCard, SCARD_LEAVE_CARD);
        scard_release_context(hContext);
        return false;
    }

    // If no AID provided, try PSE (Payment System Environment)
    struct tlvdb* select_db = NULL;
    if (!aid || aid_len == 0) {
        printf("No AID provided, selecting PSE...\n");
        unsigned char pse[] = { '1', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1' };

        select_db = emv_select(&scard, pse, sizeof(pse));
        if (!select_db) {
            // Try PPSE for contactless
            printf("PSE selection failed, trying PPSE...\n");
            unsigned char ppse[] = { '2', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1' };
            select_db = emv_select(&scard, ppse, sizeof(ppse));
        }

        if (select_db) {
            // Find first AID in PSE
            const struct tlv* aid_tlv = tlvdb_get(select_db, 0x4F, NULL);
            if (!aid_tlv) {
                // Try to look in FCI Template
                const struct tlv* fci_tlv = tlvdb_get(select_db, 0xA5, NULL);
                if (fci_tlv) {
                    struct tlvdb* fci_db = tlvdb_parse(fci_tlv->value, fci_tlv->len);
                    if (fci_db) {
                        const struct tlv* entry_tlv = tlvdb_get(fci_db, 0x61, NULL);
                        if (entry_tlv) {
                            struct tlvdb* entry_db = tlvdb_parse(entry_tlv->value, entry_tlv->len);
                            if (entry_db) {
                                aid_tlv = tlvdb_get(entry_db, 0x4F, NULL);
                                if (aid_tlv) {
                                    aid_len = aid_tlv->len;
                                    memcpy(aid_bin, aid_tlv->value, aid_len);
                                }
                                tlvdb_free(entry_db);
                            }
                        }
                        tlvdb_free(fci_db);
                    }
                }
            }
            else {
                aid_len = aid_tlv->len;
                memcpy(aid_bin, aid_tlv->value, aid_len);
            }

            tlvdb_free(select_db);
            select_db = NULL;
        }

        if (aid_len == 0) {
            printf("Could not find any AID on card\n");
            scard_disconnect(hCard, SCARD_LEAVE_CARD);
            scard_release_context(hContext);
            return false;
        }
    }

    // Select application
    printf("Selecting application: ");
    for (size_t i = 0; i < aid_len; i++) {
        printf("%02X", aid_bin[i]);
    }
    printf("\n");

    select_db = emv_select(&scard, aid_bin, aid_len);
    if (!select_db) {
        printf("Application selection failed\n");
        scard_disconnect(hCard, SCARD_LEAVE_CARD);
        scard_release_context(hContext);
        return false;
    }

    // Get processing options
    printf("Getting processing options...\n");
    struct tlvdb* gpo_db = emv_get_processing_options(&scard, NULL);
    if (!gpo_db) {
        printf("GET PROCESSING OPTIONS failed\n");
        tlvdb_free(select_db);
        scard_disconnect(hCard, SCARD_LEAVE_CARD);
        scard_release_context(hContext);
        return false;
    }

    // Read application records
    printf("Reading application data...\n");
    struct tlvdb* records_db = NULL;
    const struct tlv* afl_tlv = tlvdb_get(gpo_db, 0x94, NULL);

    if (afl_tlv) {
        // Get PAN for record reading
        unsigned char pan[10] = { 0 };
        size_t pan_len = 0;
        const struct tlv* pan_tlv = tlvdb_get(select_db, 0x5A, NULL);

        if (pan_tlv) {
            pan_len = pan_tlv->len > 10 ? 10 : pan_tlv->len;
            memcpy(pan, pan_tlv->value, pan_len);
        }

        struct tlvdb* afl_db = tlvdb_fixed(0x94, afl_tlv->len, afl_tlv->value);
        records_db = emv_read_records(&scard, pan[0], afl_db);
        tlvdb_free(afl_db);
    }

    if (!records_db) {
        printf("Failed to read application records\n");
        tlvdb_free(select_db);
        tlvdb_free(gpo_db);
        scard_disconnect(hCard, SCARD_LEAVE_CARD);
        scard_release_context(hContext);
        return false;
    }

    // Generate AC command (if needed)
    struct tlvdb* generate_ac_db = NULL;
    if (amount || online) {
        // Prepare CDOL1 data
        const struct tlv* cdol1_tlv = tlvdb_get(records_db, 0x8C, NULL);
        if (cdol1_tlv) {
            // Create DOL structure properly
            struct dol cdol1;
            cdol1.data = cdol1_tlv->value;
            cdol1.len = cdol1_tlv->len;

            // Create CDOL data
            struct tlvdb* cdol_data_db = tlvdb_fixed(0x9F66, 4, (unsigned char[]) { 0x86, 0x00, 0x00, 0x00 }); // TTQ

            // Add terminal country code (US)
            unsigned char country_code[2] = { 0x08, 0x40 };
            tlvdb_add(cdol_data_db, tlvdb_fixed(0x9F1A, sizeof(country_code), country_code));

            // Add terminal capabilities
            unsigned char term_caps[3] = { 0xE0, 0xB8, 0xC8 };
            tlvdb_add(cdol_data_db, tlvdb_fixed(0x9F33, sizeof(term_caps), term_caps));

            // Add transaction currency code (USD)
            unsigned char currency_code[2] = { 0x08, 0x40 };
            tlvdb_add(cdol_data_db, tlvdb_fixed(0x5F2A, sizeof(currency_code), currency_code));

            // Add transaction date
            time_t t = time(NULL);
            struct tm* tm = localtime(&t);
            unsigned char date[3] = {
                ((tm->tm_year + 1900) % 100) & 0xFF,
                (tm->tm_mon + 1) & 0xFF,
                tm->tm_mday & 0xFF
            };
            tlvdb_add(cdol_data_db, tlvdb_fixed(0x9A, sizeof(date), date));

            // Add transaction amount if provided
            if (amount) {
                unsigned long long value = strtoull(amount, NULL, 10);
                unsigned char amount_bin[6] = { 0 };

                // Convert to BCD
                for (int i = 5; i >= 0; i--) {
                    amount_bin[i] = (value % 10) | ((value / 10 % 10) << 4);
                    value /= 100;
                }

                tlvdb_add(cdol_data_db, tlvdb_fixed(0x9F02, sizeof(amount_bin), amount_bin));
            }
            else {
                // Zero amount
                unsigned char amount_bin[6] = { 0 };
                tlvdb_add(cdol_data_db, tlvdb_fixed(0x9F02, sizeof(amount_bin), amount_bin));
            }

            // Add unpredictable number
            srand((unsigned int)time(NULL));
            unsigned char un[4];
            for (int i = 0; i < 4; i++) {
                un[i] = rand() & 0xFF;
            }
            tlvdb_add(cdol_data_db, tlvdb_fixed(0x9F37, sizeof(un), un));

            // Process CDOL
            struct tlvdb* cdol_db = dol_process(0x8C, &cdol1, cdol_data_db);
            tlvdb_free(cdol_data_db);

            if (cdol_db) {
                // Generate AC
                printf("Generating cryptogram...\n");
                unsigned char ac_type = online ? 0x80 : 0x40; // ARQC or TC
                generate_ac_db = emv_generate_ac(&scard, ac_type, cdol_db);
                tlvdb_free(cdol_db);
            }
        }
    }

    // Create combined database with all transaction data
    struct tlvdb* transaction_db = tlvdb_fixed(0xFF, 0, NULL); // Dummy root
    tlvdb_add(transaction_db, select_db);
    tlvdb_add(transaction_db, gpo_db);
    tlvdb_add(transaction_db, records_db);
    if (generate_ac_db) {
        tlvdb_add(transaction_db, generate_ac_db);
    }

    // Export data to files
    char path[MAX_PATH];

    // Export TLV data
    format_path(path, sizeof(path), output_dir, "emv_transaction_data.txt");
    emv_export_tlv_data_to_file(transaction_db, path);

    // Export cardholder information
    format_path(path, sizeof(path), output_dir, "emv_card_data.txt");
    emv_export_cardholder_data_to_file(transaction_db, path);

    // Export certificate information
    format_path(path, sizeof(path), output_dir, "emv_certificates.txt");
    emv_extract_certificate_info(transaction_db, path);

    // Recover and verify certificates
    format_path(path, sizeof(path), output_dir, "emv_modulus.txt");
    char issuer_path[MAX_PATH], icc_path[MAX_PATH];
    format_path(issuer_path, sizeof(issuer_path), output_dir, "emv_issuer_certs.txt");
    format_path(icc_path, sizeof(icc_path), output_dir, "emv_icc_certs.txt");

    emv_recover_and_verify_certificates(transaction_db, NULL, path, issuer_path, icc_path);

    // Export cryptogram data if available
    if (generate_ac_db) {
        format_path(path, sizeof(path), output_dir, "emv_crm_data.txt");
        emv_export_cryptogram_to_file(transaction_db, path);
    }

    // Clean up
    tlvdb_free(transaction_db);
    scard_disconnect(hCard, SCARD_LEAVE_CARD);
    scard_release_context(hContext);

    printf("\nTransaction data exported to %s\n", output_dir);
    return true;
}

// Extract certificates from TLV data
bool emv_extract_certificates(const char* tlv_data_file,
    const char* ca_key_file,
    const char* output_dir) {
    if (!output_dir)
        return false;

    if (!ensure_directory_exists(output_dir))
        return false;

    // Load TLV data from file or use default
    struct tlvdb* db = NULL;

    if (tlv_data_file) {
        db = emv_import_tlv_data_from_file(tlv_data_file);
    }

    if (!db) {
        printf("No TLV data available\n");
        return false;
    }

    // Extract certificate information
    char path[MAX_PATH];
    format_path(path, sizeof(path), output_dir, "emv_certificates.txt");
    emv_extract_certificate_info(db, path);

    // Recover and verify certificates
    format_path(path, sizeof(path), output_dir, "emv_modulus.txt");
    char issuer_path[MAX_PATH], icc_path[MAX_PATH];
    format_path(issuer_path, sizeof(issuer_path), output_dir, "emv_issuer_certs.txt");
    format_path(icc_path, sizeof(icc_path), output_dir, "emv_icc_certs.txt");

    bool result = emv_recover_and_verify_certificates(db, ca_key_file, path, issuer_path, icc_path);

    tlvdb_free(db);

    return result;
}

// Generate test certificates
bool emv_generate_test_certificates(const char* rid,
    unsigned char index,
    const char* output_dir) {
    if (!rid || !output_dir)
        return false;

    if (!ensure_directory_exists(output_dir))
        return false;

    // Parse RID
    unsigned char rid_bin[5] = { 0 };
    size_t rid_len = sizeof(rid_bin);

    if (!hex_to_bin(rid, rid_bin, &rid_len) || rid_len != 5) {
        printf("Invalid RID format\n");
        return false;
    }

    // Create a test CA key (in a real implementation this would be properly generated)
    EMV_RSA_Key ca_key = { 0 };
    // We would initialize the key properly here

    // Set expiry date (2 years from now)
    time_t t = time(NULL);
    struct tm* tm = localtime(&t);
    unsigned int expire = ((tm->tm_year + 1900 + 2) % 100) * 10000 +
        (tm->tm_mon + 1) * 100 +
        tm->tm_mday;

    // Generate certificate chain
    char issuer_path[MAX_PATH], icc_path[MAX_PATH], cardholder_path[MAX_PATH];
    format_path(issuer_path, sizeof(issuer_path), output_dir, "emv_issuer_certs.txt");
    format_path(icc_path, sizeof(icc_path), output_dir, "emv_icc_certs.txt");
    format_path(cardholder_path, sizeof(cardholder_path), output_dir, "emv_card_data.txt");

    return emv_generate_certificate_chain(&ca_key, rid_bin, index, expire,
        issuer_path, icc_path, cardholder_path);
}

// Verify authentication
bool emv_verify_authentication(const char* tlv_data_file,
    const char* ca_key_file,
    const char* dynamic_data_file,
    const char* output_dir) {
    if (!output_dir)
        return false;

    if (!ensure_directory_exists(output_dir))
        return false;

    // Load TLV data from file or use default
    struct tlvdb* db = NULL;

    if (tlv_data_file) {
        db = emv_import_tlv_data_from_file(tlv_data_file);
    }

    if (!db) {
        printf("No TLV data available\n");
        return false;
    }

    // Load dynamic data for DDA if available
    struct tlvdb* dynamic_db = NULL;
    if (dynamic_data_file) {
        dynamic_db = emv_import_tlv_data_from_file(dynamic_data_file);
    }

    // Create result paths
    char sda_path[MAX_PATH], dda_path[MAX_PATH];
    format_path(sda_path, sizeof(sda_path), output_dir, "emv_sda_results.txt");
    format_path(dda_path, sizeof(dda_path), output_dir, "emv_dda_results.txt");

    // Verify SDA if data is present
    const struct tlv* ssad_tlv = tlvdb_get(db, 0x93, NULL);
    bool sda_result = false;
    if (ssad_tlv) {
        sda_result = emv_verify_ssad(db, ca_key_file, sda_path);
        printf("SDA verification: %s\n", sda_result ? "SUCCESSFUL" : "FAILED");
    }
    else {
        printf("No SDA data available\n");
    }

    // Verify DDA if data is present
    const struct tlv* sdad_tlv = tlvdb_get(db, 0x9F4B, NULL);
    bool dda_result = false;
    if (sdad_tlv) {
        dda_result = emv_verify_sdad(db, dynamic_db, ca_key_file, dda_path);
        printf("DDA verification: %s\n", dda_result ? "SUCCESSFUL" : "FAILED");
    }
    else {
        printf("No DDA data available\n");
    }

    // Clean up
    tlvdb_free(db);
    if (dynamic_db) {
        tlvdb_free(dynamic_db);
    }

    return sda_result || dda_result;
}

// Process cryptograms
bool emv_process_cryptograms(const char* tlv_data_file,
    const char* arc,
    const char* output_dir) {
    if (!output_dir)
        return false;

    if (!ensure_directory_exists(output_dir))
        return false;

    // Load TLV data from file or use default
    struct tlvdb* db = NULL;

    if (tlv_data_file) {
        db = emv_import_tlv_data_from_file(tlv_data_file);
    }

    if (!db) {
        printf("No TLV data available\n");
        return false;
    }

    // Check for cryptogram data
    const struct tlv* arqc_tlv = tlvdb_get(db, 0x9F26, NULL);
    if (!arqc_tlv) {
        printf("No cryptogram data available\n");
        tlvdb_free(db);
        return false;
    }

    // Create a test issuer key (in a real implementation this would be properly loaded)
    EMV_RSA_Key issuer_key = { 0 };
    // We would initialize the key properly here

    // Create result path
    char result_path[MAX_PATH];
    format_path(result_path, sizeof(result_path), output_dir, "emv_cryptogram_results.txt");

    // Verify ARQC
    bool arqc_result = emv_verify_arqc(db, &issuer_key, result_path);
    printf("ARQC verification: %s\n", arqc_result ? "SUCCESSFUL" : "FAILED");

    // Generate ARPC if ARC is provided
    if (arc) {
        // Parse ARC
        unsigned char arc_bin[2] = { 0 };
        size_t arc_len = sizeof(arc_bin);

        if (hex_to_bin(arc, arc_bin, &arc_len) && arc_len > 0) {
            emv_generate_arpc(&issuer_key, arqc_tlv->value, arqc_tlv->len,
                arc_bin, arc_len, result_path);
            printf("ARPC generation completed\n");
        }
        else {
            printf("Invalid ARC format\n");
        }
    }

    // Clean up
    tlvdb_free(db);

    return arqc_result;
}

// Dump card data
bool emv_dump_card_data(const char* reader_name,
    const char* aid,
    const char* output_dir) {
    if (!reader_name || !output_dir)
        return false;

    if (!ensure_directory_exists(output_dir))
        return false;

    // Initialize card context
    SCARDCONTEXT hContext;
    LONG result = scard_establish_context(&hContext);
    if (result != SCARD_S_SUCCESS) {
        printf("Failed to establish smart card context: %s\n", pcsc_stringify_error(result));
        return false;
    }

    // Connect to card
    SCARDHANDLE hCard;
    DWORD dwActiveProtocol;
    result = scard_connect(hContext, reader_name, &hCard, &dwActiveProtocol);
    if (result != SCARD_S_SUCCESS) {
        printf("Failed to connect to card: %s\n", pcsc_stringify_error(result));
        scard_release_context(hContext);
        return false;
    }

    // Create SC structure for EMV commands
    struct sc scard = {
        .hContext = hContext,
        .hCard = hCard,
        .dwActiveProtocol = dwActiveProtocol
    };

    // Create result path
    char dump_path[MAX_PATH];
    format_path(dump_path, sizeof(dump_path), output_dir, "emv_card_dump.txt");

    FILE* f = fopen(dump_path, "w");
    if (!f) {
        printf("Failed to create output file\n");
        scard_disconnect(hCard, SCARD_LEAVE_CARD);
        scard_release_context(hContext);
        return false;
    }

    // Get timestamp
    char timestamp[32];
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(f, "=== EMV Card Dump - %s ===\n\n", timestamp);

    // Get ATR (Answer To Reset)
    DWORD atrLen = 0;
    unsigned char atr[256];

    result = SCardStatus(hCard, NULL, NULL, NULL, NULL, atr, &atrLen);
    if (result == SCARD_S_SUCCESS && atrLen > 0) {
        fprintf(f, "ATR: ");
        for (DWORD i = 0; i < atrLen; i++) {
            fprintf(f, "%02X", atr[i]);
        }
        fprintf(f, "\n\n");
    }

    // If AID is specified, select it directly
    if (aid) {
        unsigned char aid_bin[16] = { 0 };
        size_t aid_len = sizeof(aid_bin);

        if (hex_to_bin(aid, aid_bin, &aid_len)) {
            fprintf(f, "Selecting AID: ");
            fprintf(f, "Selecting AID: ");
            for (size_t i = 0; i < aid_len; i++) {
                fprintf(f, "%02X", aid_bin[i]);
            }
            fprintf(f, "\n");

            struct tlvdb* select_db = emv_select(&scard, aid_bin, aid_len);
            if (select_db) {
                fprintf(f, "\n=== SELECT Response ===\n");
                tlvdb_visit(select_db, format_tlv_to_file, f);

                // Read application data
                struct tlvdb* gpo_db = emv_get_processing_options(&scard, NULL);
                if (gpo_db) {
                    fprintf(f, "\n=== GET PROCESSING OPTIONS Response ===\n");
                    tlvdb_visit(gpo_db, format_tlv_to_file, f);

                    // Read records if AFL is present
                    const struct tlv* afl_tlv = tlvdb_get(gpo_db, 0x94, NULL);
                    if (afl_tlv) {
                        // Get PAN for record reading
                        unsigned char pan[10] = { 0 };
                        size_t pan_len = 0;
                        const struct tlv* pan_tlv = tlvdb_get(select_db, 0x5A, NULL);

                        if (pan_tlv) {
                            pan_len = pan_tlv->len > 10 ? 10 : pan_tlv->len;
                            memcpy(pan, pan_tlv->value, pan_len);
                        }

                        struct tlvdb* afl_db = tlvdb_fixed(0x94, afl_tlv->len, afl_tlv->value);
                        struct tlvdb* records_db = emv_read_records(&scard, pan[0], afl_db);
                        tlvdb_free(afl_db);

                        if (records_db) {
                            fprintf(f, "\n=== Application Records ===\n");
                            tlvdb_visit(records_db, format_tlv_to_file, f);
                            tlvdb_free(records_db);
                        }
                    }

                    tlvdb_free(gpo_db);
                }

                tlvdb_free(select_db);
            }
            else {
                fprintf(f, "SELECT failed\n");
            }
        }
        else {
            fprintf(f, "Invalid AID format\n");
        }
    }
    else {
        // Try to select PSE
        fprintf(f, "Selecting PSE...\n");

        unsigned char pse[] = { '1', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1' };
        struct tlvdb* pse_db = emv_select(&scard, pse, sizeof(pse));

        if (pse_db) {
            fprintf(f, "\n=== PSE Directory ===\n");
            tlvdb_visit(pse_db, format_tlv_to_file, f);

            // Try to find AIDs
            // This would need to be properly implemented based on PSE structure
            tlvdb_free(pse_db);
        }
        else {
            // Try PPSE for contactless
            fprintf(f, "PSE selection failed, trying PPSE...\n");

            unsigned char ppse[] = { '2', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1' };
            struct tlvdb* ppse_db = emv_select(&scard, ppse, sizeof(ppse));

            if (ppse_db) {
                fprintf(f, "\n=== PPSE Directory ===\n");
                tlvdb_visit(ppse_db, format_tlv_to_file, f);

                // Try to find AIDs
                // This would need to be properly implemented based on PPSE structure
                tlvdb_free(ppse_db);
            }
            else {
                fprintf(f, "PPSE selection failed\n");
            }
        }
    }

    fclose(f);
    scard_disconnect(hCard, SCARD_LEAVE_CARD);
    scard_release_context(hContext);

    printf("Card data dumped to %s\n", dump_path);
    return true;
}
