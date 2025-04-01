// utils_windows.c
#include "utils_windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int vasprintf(char **strp, const char *fmt, va_list ap)
{
    // First, determine required size
    va_list ap_copy;
    va_copy(ap_copy, ap);
    int size = _vscprintf(fmt, ap_copy) + 1; // +1 for null terminator
    va_end(ap_copy);
    
    // Allocate buffer
    *strp = (char*)malloc(size);
    if (!*strp)
        return -1;
    
    // Format string
    int ret = vsprintf_s(*strp, size, fmt, ap);
    if (ret < 0) {
        free(*strp);
        *strp = NULL;
    }
    
    return ret;
}

int asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vasprintf(strp, fmt, ap);
    va_end(ap);
    
    return ret;
}