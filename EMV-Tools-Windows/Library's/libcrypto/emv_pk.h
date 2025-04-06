#ifndef EMV_PK_H
#define EMV_PK_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define EMV_PK_MAX_EXP_LEN 3
#define EMV_PK_MAX_MOD_LEN 256

enum {
    HASH_SHA_1,
    HASH_SHA_256
};

enum {
    PK_RSA 
};

struct emv_pk {
    unsigned char rid[5];
    unsigned char index;
    unsigned expire;
    unsigned char pk_algo;
    unsigned char exp[EMV_PK_MAX_EXP_LEN];
    size_t elen;
    unsigned char* modulus;
    size_t mlen;
    unsigned char hash[32]; // Supports SHA-256 now
    unsigned char hash_algo;
    unsigned char pan[10]; // Add this field
};

typedef struct emv_pk emv_pk_t;

struct emv_pk *emv_pk_parse_pk(char *buf);
char *emv_pk_dump_pk(const struct emv_pk *pk);
bool emv_pk_verify(const struct emv_pk *pk);
struct emv_pk *emv_pk_new(size_t modlen, size_t explen);
void emv_pk_free(struct emv_pk *pk);

#endif
