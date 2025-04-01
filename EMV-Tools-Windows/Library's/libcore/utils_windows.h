// utils_windows.h
#ifndef EMV_UTILS_WINDOWS_H
#define EMV_UTILS_WINDOWS_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

// Windows implementation of asprintf
int asprintf(char **strp, const char *fmt, ...);
int vasprintf(char **strp, const char *fmt, va_list ap);

#ifdef __cplusplus
}
#endif

#endif