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

/**
 * Load terminal parameters from configuration
 * @return true if loading succeeded
 */
bool emv_config_load_terminal_params(void);

/**
 * Get string value from configuration
 * @param key Configuration key
 * @param default_value Default value if key not found
 * @return Configuration value or default if not found
 */
const char *emv_config_get_str(const char *key, const char *default_value);

/**
 * Get integer value from configuration
 * @param key Configuration key
 * @param default_value Default value if key not found
 * @return Configuration value or default if not found
 */
int emv_config_get_int(const char *key, int default_value);

/**
 * Get boolean value from configuration
 * @param key Configuration key
 * @param default_value Default value if key not found
 * @return Configuration value or default if not found
 */
bool emv_config_get_bool(const char *key, bool default_value);

/**
 * Set string value in configuration
 * @param key Configuration key
 * @param value Value to set
 * @return true if setting succeeded
 */
bool emv_config_set_str(const char *key, const char *value);

/**
 * Set integer value in configuration
 * @param key Configuration key
 * @param value Value to set
 * @return true if setting succeeded
 */
bool emv_config_set_int(const char *key, int value);

/**
 * Set boolean value in configuration
 * @param key Configuration key
 * @param value Value to set
 * @return true if setting succeeded
 */
bool emv_config_set_bool(const char *key, bool value);

/**
 * Save configuration to file
 * @param config_file Path to save to (NULL for default)
 * @return true if save succeeded
 */
bool emv_config_save(const char *config_file);

// Terminal capability parameters
unsigned char emv_config_get_terminal_country_code(void);
unsigned char emv_config_get_terminal_capabilities(void);
unsigned char emv_config_get_additional_terminal_capabilities(void);

#ifdef __cplusplus
}
#endif

#endif // EMV_CONFIG_H