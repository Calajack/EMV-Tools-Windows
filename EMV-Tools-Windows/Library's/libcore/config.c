
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define CONFIG_MAX_ENTRIES 128
#define CONFIG_MAX_KEY_LEN 64
#define CONFIG_MAX_VALUE_LEN 256


static struct {
    char key[CONFIG_MAX_KEY_LEN];
    char value[CONFIG_MAX_VALUE_LEN];
} config_entries[CONFIG_MAX_ENTRIES];

static int config_entry_count = 0;
static char config_file_path[MAX_PATH] = {0};

// Terminal parameters
static unsigned char terminal_country_code[2] = {0x08, 0x40}; // Default: United States
static unsigned char terminal_capabilities[3] = {0xE0, 0xB8, 0xC8};
static unsigned char additional_terminal_capabilities[5] = {0x6F, 0x00, 0xF0, 0xA0, 0x01};

bool emv_config_init(const char *config_file)
{
    FILE *f;
    char line[CONFIG_MAX_KEY_LEN + CONFIG_MAX_VALUE_LEN + 2];
    char *key, *value, *saveptr;
    
    // Reset configuration
    config_entry_count = 0;
    memset(config_entries, 0, sizeof(config_entries));
    
    // Set default config file path if not specified
    if (!config_file) {
        char module_path[MAX_PATH];
        GetModuleFileNameA(NULL, module_path, MAX_PATH);
        
        // Get directory part
        char *last_slash = strrchr(module_path, '\\');
        if (last_slash) {
            *(last_slash + 1) = '\0';
            snprintf(config_file_path, MAX_PATH, "%semv-tools.conf", module_path);
        } else {
            strcpy(config_file_path, "emv-tools.conf");
        }
    } else {
        strncpy(config_file_path, config_file, MAX_PATH - 1);
    }
    
    // Open configuration file
    f = fopen(config_file_path, "r");
    if (!f) {
        // No config file, just use defaults
        return true;
    }
    
    // Read configuration file
    while (fgets(line, sizeof(line), f) != NULL) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[len - 1] = '\0';
        
        // Split line into key=value
        key = strtok_s(line, "=", &saveptr);
        value = strtok_s(NULL, "=", &saveptr);
        
        if (key && value && config_entry_count < CONFIG_MAX_ENTRIES) {
            // Trim key and value
            while (*key == ' ') key++;
            while (*value == ' ') value++;
            
            size_t key_len = strlen(key);
            while (key_len > 0 && (key[key_len - 1] == ' ' || key[key_len - 1] == '\t')) {
                key[key_len - 1] = '\0';
                key_len--;
            }
            
            size_t value_len = strlen(value);
            while (value_len > 0 && (value[value_len - 1] == ' ' || value[value_len - 1] == '\t')) {
                value[value_len - 1] = '\0';
                value_len--;
            }
            
            // Store key-value pair
            strncpy(config_entries[config_entry_count].key, key, CONFIG_MAX_KEY_LEN - 1);
            strncpy(config_entries[config_entry_count].value, value, CONFIG_MAX_VALUE_LEN - 1);
            config_entry_count++;
        }
    }
    
    fclose(f);
    
    // Load terminal parameters
    emv_config_load_terminal_params();
    
    return true;
}

bool emv_config_load_terminal_params(void)
{
    const char *value;
    
    // Terminal country code
    value = emv_config_get_str("terminal.country_code", NULL);
    if (value && strlen(value) >= 4) {
        unsigned int country_code;
        if (sscanf_s(value, "%x", &country_code) == 1) {
            terminal_country_code[0] = (country_code >> 8) & 0xFF;
            terminal_country_code[1] = country_code & 0xFF;
        }
    }
    
    // Terminal capabilities
    value = emv_config_get_str("terminal.capabilities", NULL);
    if (value && strlen(value) >= 6) {
        unsigned int cap1, cap2, cap3;
        if (sscanf_s(value, "%2x%2x%2x", &cap1, &cap2, &cap3) == 3) {
            terminal_capabilities[0] = cap1 & 0xFF;
            terminal_capabilities[1] = cap2 & 0xFF;
            terminal_capabilities[2] = cap3 & 0xFF;
        }
    }
    
    // Additional terminal capabilities
    value = emv_config_get_str("terminal.additional_capabilities", NULL);
    if (value && strlen(value) >= 10) {
        unsigned int cap1, cap2, cap3, cap4, cap5;
        if (sscanf_s(value, "%2x%2x%2x%2x%2x", &cap1, &cap2, &cap3, &cap4, &cap5) == 5) {
            additional_terminal_capabilities[0] = cap1 & 0xFF;
            additional_terminal_capabilities[1] = cap2 & 0xFF;
            additional_terminal_capabilities[2] = cap3 & 0xFF;
            additional_terminal_capabilities[3] = cap4 & 0xFF;
            additional_terminal_capabilities[4] = cap5 & 0xFF;
        }
    }
    
    return true;
}

const char *emv_config_get_str(const char *key, const char *default_value)
{
    if (!key)
        return default_value;
    
    for (int i = 0; i < config_entry_count; i++) {
        if (strcmp(config_entries[i].key, key) == 0)
            return config_entries[i].value;
    }
    
    return default_value;
}

int emv_config_get_int(const char *key, int default_value)
{
    const char *str_value = emv_config_get_str(key, NULL);
    if (!str_value)
        return default_value;
    
    return atoi(str_value);
}

bool emv_config_get_bool(const char *key, bool default_value)
{
    const char *str_value = emv_config_get_str(key, NULL);
    if (!str_value)
        return default_value;
    
    if (strcmp(str_value, "true") == 0 || 
        strcmp(str_value, "yes") == 0 || 
        strcmp(str_value, "1") == 0)
        return true;
    
    if (strcmp(str_value, "false") == 0 || 
        strcmp(str_value, "no") == 0 || 
        strcmp(str_value, "0") == 0)
        return false;
    
    return default_value;
}

bool emv_config_set_str(const char *key, const char *value)
{
    if (!key || !value)
        return false;
    
    // Check if key already exists
    for (int i = 0; i < config_entry_count; i++) {
        if (strcmp(config_entries[i].key, key) == 0) {
            strncpy(config_entries[i].value, value, CONFIG_MAX_VALUE_LEN - 1);
            return true;
        }
    }
    
    // Add new entry if there's space
    if (config_entry_count < CONFIG_MAX_ENTRIES) {
        strncpy(config_entries[config_entry_count].key, key, CONFIG_MAX_KEY_LEN - 1);
        strncpy(config_entries[config_entry_count].value, value, CONFIG_MAX_VALUE_LEN - 1);
        config_entry_count++;
        return true;
    }
    
    return false;
}

bool emv_config_set_int(const char *key, int value)
{
    char str_value[16];
    snprintf(str_value, sizeof(str_value), "%d", value);
    return emv_config_set_str(key, str_value);
}

bool emv_config_set_bool(const char *key, bool value)
{
    return emv_config_set_str(key, value ? "true" : "false");
}

bool emv_config_save(const char *config_file)
{
    FILE *f;
    const char *file_path = config_file ? config_file : config_file_path;
    
    f = fopen(file_path, "w");
    if (!f)
        return false;
    
    fprintf(f, "# EMV Tools configuration file\n");
    fprintf(f, "# Generated automatically\n\n");
    
    for (int i = 0; i < config_entry_count; i++) {
        fprintf(f, "%s=%s\n", config_entries[i].key, config_entries[i].value);
    }
    
    fclose(f);
    return true;
}

unsigned char emv_config_get_terminal_country_code(void)
{
    return *((unsigned short*)terminal_country_code);
}

unsigned char emv_config_get_terminal_capabilities(void)
{
    return *((unsigned int*)terminal_capabilities);
}

unsigned char emv_config_get_additional_terminal_capabilities(void)
{
    return *((unsigned long long*)additional_terminal_capabilities);
}
