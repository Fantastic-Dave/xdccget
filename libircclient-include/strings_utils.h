#ifndef STRINGS_H
#define	STRINGS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stddef.h>

static inline bool str_equals(const char *str1, const char *str2) {
    return strcmp(str1, str2) == 0;
}

static inline bool strn_equals(const char *str1, const char *str2, size_t n) {
    return strncmp(str1, str2, n) == 0;
}

#ifdef	__cplusplus
}
#endif

#endif	/* STRINGS_H */

