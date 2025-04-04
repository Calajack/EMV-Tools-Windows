#include <stdint.h>
#include "config_windows.h"
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simple implementation - you might want to use Windows registry or INI files
static char config_filename[MAX_PATH] = {0};

void openemv_config_init(const char *config_file)
{
    if (config_file)
        strncpy(config_filename, config_file, sizeof(config_filename) - 1);
}

const char *openemv_config_get_str(const char *key, const char *default_value)
{
    static char buffer[1024];
    
    // First try environment variables
    DWORD result = GetEnvironmentVariableA(key, buffer, sizeof(buffer));
    if (result > 0 && result < sizeof(buffer))
        return buffer;
        
    // Then try config file if available
    if (config_filename[0]) {
        char section[64] = "EMV";
        GetPrivateProfileStringA(section, key, default_value, 
                                buffer, sizeof(buffer), config_filename);
        return buffer;
    }
    
    return default_value;
}

int openemv_config_get_int(const char *key, int default_value)
{
    const char *str_value = openemv_config_get_str(key, NULL);
    if (!str_value)
        return default_value;
        
    return atoi(str_value);
}
