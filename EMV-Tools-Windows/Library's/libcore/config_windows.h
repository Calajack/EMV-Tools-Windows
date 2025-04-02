#ifndef EMV_CONFIG_WINDOWS_H
#define EMV_CONFIG_WINDOWS_H

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the configuration system
void openemv_config_init(const char *config_file);

// Get a string value from config
const char *openemv_config_get_str(const char *key, const char *default_value);

// Get an integer value from config
int openemv_config_get_int(const char *key, int default_value);

#ifdef __cplusplus
}
#endif

#endif
