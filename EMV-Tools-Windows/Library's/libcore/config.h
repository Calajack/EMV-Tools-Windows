// config.h - Configuration system for EMV tools
#ifndef EMV_CONFIG_H
#define EMV_CONFIG_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the configuration system
 * @param config_file Path to configuration file (NULL for default)
 * @return true if initialization succeeded
 */
bool emv_config_init(const char *config_file);
bool emv_config_load_terminal_params(void);
const char *emv_config_get_str(const char *key, const char *default_value);
int emv_config_get_int(const char *key, int default_value);
bool emv_config_get_bool(const char *key, bool default_value);
bool emv_config_set_str(const char *key, const char *value);
bool emv_config_set_int(const char *key, int value);
bool emv_config_set_bool(const char *key, bool value);
bool emv_config_save(const char *config_file);

// Terminal capability parameters
unsigned char emv_config_get_terminal_country_code(void);
unsigned char emv_config_get_terminal_capabilities(void);
unsigned char emv_config_get_additional_terminal_capabilities(void);

#ifdef __cplusplus
}
#endif

#endif // EMV_CONFIG_H
