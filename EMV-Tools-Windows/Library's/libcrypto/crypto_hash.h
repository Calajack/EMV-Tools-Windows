#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct crypto_hash;

struct crypto_hash *crypto_hash_open(unsigned hash_algo);
void crypto_hash_write(struct crypto_hash *ch, const unsigned char *data, size_t len);
unsigned char *crypto_hash_read(struct crypto_hash *ch);
void crypto_hash_close(struct crypto_hash *ch);
size_t crypto_hash_get_size(struct crypto_hash *ch);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_HASH_H
