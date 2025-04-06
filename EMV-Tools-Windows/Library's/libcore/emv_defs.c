// emv_defs.c - EMV definitions implementation
#include "emv_defs.h"

// AIP bit definitions
const aip_bit_t aip_bits[] = {
    { "CDA Supported", "Combined Dynamic Data Authentication/Application Cryptogram Generation Supported" },
    { "DDA Supported", "Dynamic Data Authentication Supported" },
    { "Cardholder Verification Supported", "Cardholder Verification is Supported" },
    { "Terminal Risk Management", "Terminal Risk Management is to be Performed" },
    { "Issuer Authentication Supported", "Issuer Authentication is Supported" },
    { "SDA Supported", "Static Data Authentication Supported" },
    { NULL, NULL }
};

// AUC bit definitions
const auc_bit_t auc_bits[] = {
    { "Domestic Cash", "Valid for Domestic Cash Transactions" },
    { "International Cash", "Valid for International Cash Transactions" },
    { "Domestic Goods", "Valid for Domestic Goods" },
    { "International Goods", "Valid for International Goods" },
    { "Domestic Services", "Valid for Domestic Services" },
    { "International Services", "Valid for International Services" },
    { "ATM", "Valid at ATMs" },
    { "Terminal", "Valid at Terminals other than ATMs" },
    { NULL, NULL }
};

// TVR bit definitions
const tvr_bit_t tvr_bits[] = {
    { "Offline Data Auth not performed", "Offline Data Authentication was not performed" }, 
    { "SDA failed", "SDA Failed" },
    { "ICC Data Missing", "ICC Data Missing" },
    { "Card on Terminal Exception File", "Card appears on terminal exception file" },
    { "DDA failed", "DDA Failed" },
    { "CDA failed", "CDA Failed" },
    { "SDA selected", "SDA was selected" },
    { NULL, NULL }
};
