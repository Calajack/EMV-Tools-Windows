// EMV-Tools-Win.cpp - Main application for EMV Tools
#include <winscard.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <windows.h>
#include "scard_common.h"
#include "crypto_hash.h"
#include "emv_operations.h"
#include "emv_file_utils.h"
#include "emv_certificate_ops.h"

// Function to display available readers
void DisplayReaders() {
    SCARDCONTEXT hContext;
    LONG result = scard_establish_context(&hContext);
    if (result != SCARD_S_SUCCESS) {
        std::cout << "Failed to establish smart card context: "
            << pcsc_stringify_error(result) << std::endl;
        return;
    }

    char reader_names[MAX_READERS][MAX_READERNAME];
    DWORD readers_count = 0;
    if (!scard_list_readers(hContext, reader_names, &readers_count, MAX_READERS, MAX_READERNAME)) {
        std::cout << "Failed to list readers" << std::endl;
        scard_release_context(hContext);
        return;
    }

    if (readers_count == 0) {
        std::cout << "No readers found" << std::endl;
        scard_release_context(hContext);
        return;
    }

    std::cout << "Available readers:" << std::endl;
    for (DWORD i = 0; i < readers_count; i++) {
        std::cout << i << ": " << reader_names[i] << std::endl;
    }

    scard_release_context(hContext);
}

// Function to initialize Omnikey readers
void InitOmnikey() {
    SCardContext* ctx = scard_establish(SCARD_SCOPE_SYSTEM);
    if (!ctx) {
        std::cout << "Failed to establish smart card context" << std::endl;
        return;
    }

    // Connect to Omnikey reader
    if (scard_connect_ctx(ctx, "OMNIKEY CardMan 5x21 0", SCARD_SHARE_EXCLUSIVE) != SCARD_S_SUCCESS) {
        std::cout << "Failed to connect to Omnikey reader" << std::endl;
        return;
    }

    // Set LED to green
    scard_omnikey_set_led(ctx, OMNIKEY_LED_GREEN);
    std::cout << "Omnikey reader initialized with green LED" << std::endl;
}

// Function to parse command line arguments
std::vector<std::string> ParseArgs(int argc, char* argv[]) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++) {
        args.push_back(argv[i]);
    }
    return args;
}

// Function to display help
void DisplayHelp() {
    std::cout << "EMV Tools - Certificate and Data Operations" << std::endl;
    std::cout << "--------------------------------------------" << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  readers              - Display available readers" << std::endl;
    std::cout << "  init                 - Initialize Omnikey reader" << std::endl;
    std::cout << "  dump <reader> [aid]  - Dump card data" << std::endl;
    std::cout << "  transaction <reader> [aid] [amount] [online]  - Perform EMV transaction" << std::endl;
    std::cout << "  extract [file] [ca]  - Extract certificates from TLV data" << std::endl;
    std::cout << "  generate <rid> <idx> - Generate test certificates" << std::endl;
    std::cout << "  verify [file] [ca]   - Verify authentication on card data" << std::endl;
    std::cout << "  cryptogram [file] [arc] - Process cryptograms" << std::endl;
    std::cout << std::endl;
    std::cout << "All operations use the 'output' folder in the current directory" << std::endl;
    std::cout << "by default, unless specified otherwise." << std::endl;
}

// Main application entry point
int main(int argc, char* argv[]) {
    std::cout << "EMV Tools - Certificate and Data Operations" << std::endl;
    std::cout << "--------------------------------------------" << std::endl;

    std::vector<std::string> args = ParseArgs(argc, argv);

    // Check for command
    if (args.empty()) {
        DisplayHelp();
        return 0;
    }

    // Default output directory
    const char* output_dir = "output";
    CreateDirectoryA(output_dir, NULL);

    // Process commands
    std::string command = args[0];

    if (command == "readers") {
        DisplayReaders();
    }
    else if (command == "init") {
        InitOmnikey();
    }
    else if (command == "dump") {
        if (args.size() < 2) {
            std::cout << "Usage: dump <reader> [aid]" << std::endl;
            return 1;
        }

        const char* reader = args[1].c_str();
        const char* aid = (args.size() > 2) ? args[2].c_str() : NULL;

        emv_dump_card_data(reader, aid, output_dir);
    }
    else if (command == "transaction") {
        if (args.size() < 2) {
            std::cout << "Usage: transaction <reader> [aid] [amount] [online]" << std::endl;
            return 1;
        }

        const char* reader = args[1].c_str();
        const char* aid = (args.size() > 2 && args[2] != "online") ? args[2].c_str() : NULL;
        const char* amount = (args.size() > 3 && args[3] != "online") ? args[3].c_str() : NULL;
        bool online = (args.size() > 2 && args[2] == "online") ||
            (args.size() > 3 && args[3] == "online") ||
            (args.size() > 4 && args[4] == "online");

        emv_perform_transaction(reader, aid, amount, online, output_dir);
    }
    else if (command == "extract") {
        const char* tlv_file = (args.size() > 1) ? args[1].c_str() : NULL;
        const char* ca_file = (args.size() > 2) ? args[2].c_str() : NULL;

        emv_extract_certificates(tlv_file, ca_file, output_dir);
    }
    else if (command == "generate") {
        if (args.size() < 3) {
            std::cout << "Usage: generate <rid> <index>" << std::endl;
            return 1;
        }

        const char* rid = args[1].c_str();
        unsigned char index = (unsigned char)strtol(args[2].c_str(), NULL, 16);

        emv_generate_test_certificates(rid, index, output_dir);
    }
    else if (command == "verify") {
        const char* tlv_file = (args.size() > 1) ? args[1].c_str() : NULL;
        const char* ca_file = (args.size() > 2) ? args[2].c_str() : NULL;
        const char* dyn_file = (args.size() > 3) ? args[3].c_str() : NULL;

        emv_verify_authentication(tlv_file, ca_file, dyn_file, output_dir);
    }
    else if (command == "cryptogram") {
        const char* tlv_file = (args.size() > 1) ? args[1].c_str() : NULL;
        const char* arc = (args.size() > 2) ? args[2].c_str() : NULL;

        emv_process_cryptograms(tlv_file, arc, output_dir);
    }
    else {
        std::cout << "Unknown command: " << command << std::endl;
        DisplayHelp();
        return 1;
    }

    return 0;
}

#ifdef MANUAL_MODE
// For manual mode operations
extern "C" void manual_feed_response(const uint8_t* rsp, size_t len) {
    // Implementation would store data for manual testing
}
#endif

// Standard AIDs for reference
const uint8_t EMV_AIDs[][16] = {
    { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10 }, // Visa Credit
    { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10 }, // Visa Electron
    { 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10 }, // Mastercard Credit/debit
    { 0xA0, 0x00, 0x00, 0x00, 0x65, 0x10, 0x10 }, // JCB
    { 0xA0, 0x00, 0x00, 0x25, 0x01, 0x08, 0x01 }, // American Express
    { 0xA0, 0x00, 0x00, 0x01, 0x52, 0x30, 0x10 }, // Discover
    { 0xA0, 0x00, 0x03, 0x33, 0x01, 0x01, 0x01 }, // Unionpay
};
