#include "crypto_windows.h"
#include "emv_pk.h" 
#include <openssl/evp.h>
#include <stdlib.h>

// Crypto hash context
struct crypto_hash {
    EVP_MD_CTX *md_ctx;
    EVP_MD *md;
    unsigned char *hash;
    size_t hash_size;
};

struct crypto_hash *crypto_hash_open(unsigned hash_algo) {
    struct crypto_hash *ch = calloc(1, sizeof(struct crypto_hash));
    if (!ch) return NULL;
    
    ch->md_ctx = EVP_MD_CTX_new();
    if (!ch->md_ctx) {
        free(ch);
        return NULL;
    }
    
    // Select algorithm based on hash_algo
    if (hash_algo == HASH_SHA_1) {
        ch->md = (EVP_MD*)EVP_sha1();
        ch->hash_size = SHA_DIGEST_LENGTH;
    } else if (hash_algo == HASH_SHA_256) {
        ch->md = (EVP_MD*)EVP_sha256();
        ch->hash_size = SHA256_DIGEST_LENGTH;
    } else {
        EVP_MD_CTX_free(ch->md_ctx);
        free(ch);
        return NULL;
    }
    
    ch->hash = malloc(ch->hash_size);
    if (!ch->hash) {
        EVP_MD_CTX_free(ch->md_ctx);
        free(ch);
        return NULL;
    }
    
    if (EVP_DigestInit_ex(ch->md_ctx, ch->md, NULL) != 1) {
        free(ch->hash);
        EVP_MD_CTX_free(ch->md_ctx);
        free(ch);
        return NULL;
    }
    
    return ch;
}

void crypto_hash_write(struct crypto_hash *ch, const unsigned char *data, size_t len) {
    if (!ch || !data) return;
    EVP_DigestUpdate(ch->md_ctx, data, len);
}

unsigned char *crypto_hash_read(struct crypto_hash *ch) {
    if (!ch) return NULL;
    
    unsigned int len = ch->hash_size;
    if (EVP_DigestFinal_ex(ch->md_ctx, ch->hash, &len) != 1) {
        return NULL;
    }
    
    return ch->hash;
}

void crypto_hash_close(struct crypto_hash *ch) {
    if (!ch) return;
    if (ch->md_ctx) EVP_MD_CTX_free(ch->md_ctx);
    if (ch->hash) free(ch->hash);
    free(ch);
}

size_t crypto_hash_get_size(struct crypto_hash *ch) {
    return ch ? ch->hash_size : 0;
}
