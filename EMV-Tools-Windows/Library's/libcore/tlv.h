#ifndef TLV_H
#define TLV_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t tlv_tag_t;

// TLV structure (cache-aligned for Windows)
typedef struct __declspec(align(8)) {
    tlv_tag_t tag;
    size_t len;
    uint8_t* value;
} tlv_t;

// TLV Database node
typedef struct tlvdb {
    tlv_t tlv;
    struct tlvdb* next;
    struct tlvdb* child;
} tlvdb_t;

// Parser functions
tlvdb_t* tlvdb_parse(const uint8_t* buf, size_t len);
void tlvdb_free(tlvdb_t* tlvdb);

// Navigation
const tlv_t* tlvdb_get(const tlvdb_t* tlvdb, tlv_tag_t tag);

// Serialization
uint8_t* tlv_encode(const tlv_t* tlv, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif // TLV_H