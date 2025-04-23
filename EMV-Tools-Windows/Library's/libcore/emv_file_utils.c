// emv_file_utils.c - File utilities for EMV certificate and data management
#include "emv_file_utils.h"
#include "emv_pk.h"
#include "emv_tags.h"
#include "utils_windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

// Helper function to ensure directory exists
static bool ensure_directory_exists(const char *filename) {
    char path[MAX_PATH];
    strncpy(path, filename, sizeof(path) - 1);
    
    // Find last backslash
    char *last_slash = strrchr(path, '\\');
    if (last_slash) {
        *last_slash = '\0';
        return CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    }
    
    return true;
}

// Helper to format current timestamp
static void get_timestamp(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Export a certificate to a file
bool emv_export_certificate_to_file(const struct emv_pk *pk, const char *filename) {
    if (!pk || !filename) return false;
    
    ensure_directory_exists(filename);
    
    FILE *f = fopen(filename, "a");
    if (!f) return false;
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(f, "=== Certificate exported on %s ===\n", timestamp);
    
    // Output certificate metadata
    fprintf(f, "RID: ");
    for (int i = 0; i < 5; i++) {
        fprintf(f, "%02X", pk->rid[i]);
    }
    fprintf(f, "\n");
    
    fprintf(f, "Index: %02X\n", pk->index);
    fprintf(f, "Expiry: %06X\n", pk->expire);
    fprintf(f, "Hash Algorithm: %s\n", pk->hash_algo == 0 ? "SHA-1" : "SHA-256");
    
    // Output modulus
    fprintf(f, "Modulus (%zu bytes):\n", pk->mlen);
    for (size_t i = 0; i < pk->mlen; i++) {
        fprintf(f, "%02X", pk->modulus[i]);
        if ((i + 1) % 16 == 0 && i < pk->mlen - 1) fprintf(f, "\n");
    }
    fprintf(f, "\n");
    
    // Output exponent
    fprintf(f, "Exponent (%zu bytes):\n", pk->elen);
    for (size_t i = 0; i < pk->elen; i++) {
        fprintf(f, "%02X", pk->exp[i]);
    }
    fprintf(f, "\n");
    
    // Output hash
    fprintf(f, "Hash (%s):\n", pk->hash_algo == 0 ? "SHA-1 (20 bytes)" : "SHA-256 (32 bytes)");
    size_t hash_len = pk->hash_algo == 0 ? 20 : 32;
    for (size_t i = 0; i < hash_len; i++) {
        fprintf(f, "%02X", pk->hash[i]);
    }
    fprintf(f, "\n\n");
    
    fclose(f);
    return true;
}

// Export modulus to a file
bool emv_export_modulus_to_file(const struct emv_pk *pk, const char *filename) {
    if (!pk || !filename) return false;
    
    ensure_directory_exists(filename);
    
    FILE *f = fopen(filename, "a");
    if (!f) return false;
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(f, "=== Modulus exported on %s ===\n", timestamp);
    
    // Output RID and index for identification
    fprintf(f, "RID: ");
    for (int i = 0; i < 5; i++) {
        fprintf(f, "%02X", pk->rid[i]);
    }
    fprintf(f, "\n");
    
    fprintf(f, "Index: %02X\n", pk->index);
    
    // Output modulus in hex
    fprintf(f, "Modulus (%zu bytes):\n", pk->mlen);
    for (size_t i = 0; i < pk->mlen; i++) {
        fprintf(f, "%02X", pk->modulus[i]);
        if ((i + 1) % 16 == 0 && i < pk->mlen - 1) fprintf(f, "\n");
    }
    fprintf(f, "\n\n");
    
    fclose(f);
    return true;
}

// Append a modulus to the modulus file
bool emv_append_modulus_to_file(const struct emv_pk *pk, const char *filename) {
    // This is effectively the same as export_modulus_to_file as we're already appending
    return emv_export_modulus_to_file(pk, filename);
}

// Helper to match RID and index
static bool match_rid_index(const unsigned char *rid1, const unsigned char *rid2, 
                          unsigned char index1, unsigned char index2) {
    return (memcmp(rid1, rid2, 5) == 0 && index1 == index2);
}

// Find a modulus in the specified file by RID and index
struct emv_pk *emv_find_modulus_in_file(const char *filename, const unsigned char *rid, unsigned char index) {
    if (!filename || !rid) return NULL;
    
    // This would require parsing the text file which is complex
    // A better implementation would use a specific format or database
    // For now, let's use the existing function to try to find the CA key
    return emv_pk_get_ca_pk(rid, index);
}

// Helper to get tag name and format a TLV
static void format_tlv_to_file(FILE *f, const struct tlv *tlv) {
    if (!f || !tlv) return;
    
    const char *name = emv_tag_get_name(tlv->tag);
    const char *desc = emv_tag_get_description(tlv->tag);
    
    fprintf(f, "Tag: %04X", tlv->tag);
    if (name) fprintf(f, " (%s)", name);
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
    } else if (tlv->tag == 0x5F24) { // Expiration Date
        if (tlv->len >= 3) {
            fprintf(f, "20%02X/%02X", tlv->value[0], tlv->value[1]);
        } else {
            // Regular hex dump for unexpected format
            for (size_t i = 0; i < tlv->len; i++) {
                fprintf(f, "%02X", tlv->value[i]);
            }
        }
    } else if (tlv->tag == 0x5F20) { // Cardholder Name
        // Print as ASCII if printable
        for (size_t i = 0; i < tlv->len; i++) {
            unsigned char c = tlv->value[i];
            if (c >= 32 && c <= 126) {
                fprintf(f, "%c", c);
            } else {
                fprintf(f, "\\x%02X", c);
            }
        }
    } else {
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

// Visitor function for TLV database
static void tlv_file_visitor(const struct tlv *tlv, void *data) {
    FILE *f = (FILE *)data;
    format_tlv_to_file(f, tlv);
}

// Export TLV database items to a file
bool emv_export_tlv_data_to_file(const struct tlvdb *db, const char *filename) {
    if (!db || !filename) return false;
    
    ensure_directory_exists(filename);
    
    FILE *f = fopen(filename, "a");
    if (!f) return false;
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(f, "=== TLV Data exported on %s ===\n\n", timestamp);
    
    // Visit and output each TLV in the database
    tlvdb_visit(db, tlv_file_visitor, f);
    
    fprintf(f, "\n");
    fclose(f);
    return true;
}

// Export cardholder data to a file
bool emv_export_cardholder_data_to_file(const struct tlvdb *db, const char *filename) {
    if (!db || !filename) return false;
    
    ensure_directory_exists(filename);
    
    FILE *f = fopen(filename, "a");
    if (!f) return false;
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(f, "=== Cardholder Data exported on %s ===\n\n", timestamp);
    
    // Extract and format key cardholder info
    const struct tlv *pan_tlv = tlvdb_get(db, 0x5A, NULL);
    const struct tlv *name_tlv = tlvdb_get(db, 0x5F20, NULL);
    const struct tlv *exp_tlv = tlvdb_get(db, 0x5F24, NULL);
    const struct tlv *country_tlv = tlvdb_get(db, 0x5F28, NULL);
    const struct tlv *currency_tlv = tlvdb_get(db, 0x9F42, NULL);
    const struct tlv *lang_tlv = tlvdb_get(db, 0x5F2D, NULL);
    
    // Format PAN
    if (pan_tlv) {
        fprintf(f, "Primary Account Number (PAN): ");
        for (size_t i = 0; i < pan_tlv->len; i++) {
            fprintf(f, "%02X", pan_tlv->value[i]);
            if ((i + 1) % 2 == 0 && i < pan_tlv->len - 1) fprintf(f, " ");
        }
        fprintf(f, "\n");
    }
    
    // Format Cardholder Name
    if (name_tlv) {
        fprintf(f, "Cardholder Name: ");
        for (size_t i = 0; i < name_tlv->len; i++) {
            unsigned char c = name_tlv->value[i];
            if (c >= 32 && c <= 126) {
                fprintf(f, "%c", c);
            } else {
                fprintf(f, "\\x%02X", c);
            }
        }
        fprintf(f, "\n");
    }
    
    // Format Expiration Date
    if (exp_tlv && exp_tlv->len >= 3) {
        fprintf(f, "Expiration Date: 20%02X/%02X\n", exp_tlv->value[0], exp_tlv->value[1]);
    }
    
    // Format Country Code
    if (country_tlv && country_tlv->len >= 2) {
        fprintf(f, "Country Code: %02X%02X\n", country_tlv->value[0], country_tlv->value[1]);
    }
    
    // Format Currency Code
    if (currency_tlv && currency_tlv->len >= 2) {
        fprintf(f, "Currency Code: %02X%02X\n", currency_tlv->value[0], currency_tlv->value[1]);
    }
    
    // Format Language Preference
    if (lang_tlv) {
        fprintf(f, "Language Preference: ");
        for (size_t i = 0; i < lang_tlv->len; i++) {
            unsigned char c = lang_tlv->value[i];
            if (c >= 32 && c <= 126) {
                fprintf(f, "%c", c);
            } else {
                fprintf(f, "\\x%02X", c);
            }
        }
        fprintf(f, "\n");
    }
    
    fprintf(f, "\n");
    fclose(f);
    return true;
}

// Import TLV data from a file
struct tlvdb *emv_import_tlv_data_from_file(const char *filename) {
    // This requires a specific format file and parsing logic
    // For the current implementation, we'll just return NULL
    // A real implementation would parse the file format
    printf("TLV import not implemented yet - use manual file reading\n");
    return NULL;
}

// Export cryptogram data to a file
bool emv_export_cryptogram_to_file(const struct tlvdb *db, const char *filename) {
    if (!db || !filename) return false;
    
    ensure_directory_exists(filename);
    
    FILE *f = fopen(filename, "a");
    if (!f) return false;
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(f, "=== Cryptogram Data exported on %s ===\n\n", timestamp);
    
    // Extract cryptogram related data
    const struct tlv *arqc_tlv = tlvdb_get(db, 0x9F26, NULL);
    const struct tlv *cid_tlv = tlvdb_get(db, 0x9F27, NULL);
    const struct tlv *atc_tlv = tlvdb_get(db, 0x9F36, NULL);
    const struct tlv *tvr_tlv = tlvdb_get(db, 0x95, NULL);
    const struct tlv *tsi_tlv = tlvdb_get(db, 0x9B, NULL);
    
    // Format Application Cryptogram
    if (arqc_tlv) {
        fprintf(f, "Application Cryptogram: ");
        for (size_t i = 0; i < arqc_tlv->len; i++) {
            fprintf(f, "%02X", arqc_tlv->value[i]);
        }
        fprintf(f, "\n");
    }
    
    // Format Cryptogram Information Data
    if (cid_tlv && cid_tlv->len > 0) {
        fprintf(f, "Cryptogram Information Data: %02X (", cid_tlv->value[0]);
        switch (cid_tlv->value[0] & 0xC0) {
            case 0x00: fprintf(f, "AAC - Transaction declined"); break;
            case 0x40: fprintf(f, "TC - Transaction approved"); break;
            case 0x80: fprintf(f, "ARQC - Online authorization requested"); break;
            default: fprintf(f, "RFU"); break;
        }
        fprintf(f, ")\n");
    }
    
    // Format Application Transaction Counter
    if (atc_tlv && atc_tlv->len >= 2) {
        fprintf(f, "Application Transaction Counter: %02X%02X\n", atc_tlv->value[0], atc_tlv->value[1]);
    }
    
    // Format Terminal Verification Results
    if (tvr_tlv) {
        fprintf(f, "Terminal Verification Results: ");
        for (size_t i = 0; i < tvr_tlv->len; i++) {
            fprintf(f, "%02X", tvr_tlv->value[i]);
        }
        fprintf(f, "\n");
    }
    
    // Format Transaction Status Information
    if (tsi_tlv) {
        fprintf(f, "Transaction Status Information: ");
        for (size_t i = 0; i < tsi_tlv->len; i++) {
            fprintf(f, "%02X", tsi_tlv->value[i]);
        }
        fprintf(f, "\n");
    }
    
    fprintf(f, "\n");
    fclose(f);
    return true;
}

// Export a binary buffer to a file in hexadecimal format
bool emv_export_binary_to_file(const unsigned char *data, size_t data_len, const char *filename) {
    if (!data || !filename || data_len == 0) return false;
    
    ensure_directory_exists(filename);
    
    FILE *f = fopen(filename, "a");
    if (!f) return false;
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(f, "=== Binary Data exported on %s ===\n", timestamp);
    fprintf(f, "Size: %zu bytes\n", data_len);
    
    for (size_t i = 0; i < data_len; i++) {
        fprintf(f, "%02X", data[i]);
        if ((i + 1) % 16 == 0 && i < data_len - 1) fprintf(f, "\n");
    }
    
    fprintf(f, "\n\n");
    fclose(f);
    return true;
}

// Import hexadecimal data from a file to a binary buffer
unsigned char *emv_import_binary_from_file(const char *filename, size_t *data_len) {
    if (!filename || !data_len) return NULL;
    
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;
    
    // Read the file to count hex digits
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *file_content = malloc(file_size + 1);
    if (!file_content) {
        fclose(f);
        return NULL;
    }
    
    fread(file_content, 1, file_size, f);
    file_content[file_size] = '\0';
    fclose(f);
    
    // Count actual hex digits
    size_t hex_count = 0;
    for (size_t i = 0; i < file_size; i++) {
        char c = file_content[i];
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))
            hex_count++;
    }
    
    // Allocate buffer for binary data
    size_t binary_size = hex_count / 2;
    *data_len = binary_size;
    unsigned char *binary_data = malloc(binary_size);
    if (!binary_data) {
        free(file_content);
        return NULL;
    }
    
    // Convert hex to binary
    size_t binary_pos = 0;
    unsigned char byte_val = 0;
    bool high_nibble = true;
    
    for (size_t i = 0; i < file_size && binary_pos < binary_size; i++) {
        char c = file_content[i];
        unsigned char nibble;
        
        if (c >= '0' && c <= '9')
            nibble = c - '0';
        else if (c >= 'A' && c <= 'F')
            nibble = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            nibble = c - 'a' + 10;
        else
            continue; // Skip non-hex characters
            
        if (high_nibble) {
            byte_val = nibble << 4;
            high_nibble = false;
        } else {
            byte_val |= nibble;
            binary_data[binary_pos++] = byte_val;
            high_nibble = true;
        }
    }
    
    free(file_content);
    
    // If we're in the middle of a byte (odd number of nibbles), complete it
    if (!high_nibble && binary_pos < binary_size) {
        binary_data[binary_pos++] = byte_val;
    }
    
    *data_len = binary_pos;
    return binary_data;
}
