// tlv.h - Windows compatible version
#ifndef EMV_TLV_H
#define EMV_TLV_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TLV tag constants from EMV specification */
#define TLV_TAG_CLASS_MASK       0xc0
#define TLV_TAG_COMPLEX          0x20
#define TLV_TAG_PRIMITIVE        0x00
#define TLV_TAG_APPLICATION      0x40
#define TLV_TAG_CONTEXT_SPECIFIC 0x80

/* TLV type */
typedef uint32_t tlv_tag_t;

/* TLV structure */
typedef struct tlv {
    uint8_t     type;   // Primitive/Constructed (add this)
    unsigned    tag;    // Existing
    size_t      len;    // Existing
    const uint8_t* value;  // Existing
} tlv_t;

/* TLV database structure */
struct tlvdb {
    struct tlv tag;
    struct tlvdb *next;
    struct tlvdb *parent;
    struct tlvdb *children;
};

/* TLV database element search helpers */
struct tlvdb_record {
    tlv_tag_t tag;
    const char *name;
    const char *(*get)(const struct tlv *tlv, unsigned *clen);
    bool (*parse)(const struct tlv *tlv);
};

/* Basic TLV manipulation */
bool tlv_parse_tl(const unsigned char **buf, size_t *len, struct tlv *tlv);
bool tlv_parse_tlv(const unsigned char **buf, size_t *len, struct tlv *tlv);

/* TLV database functions */
struct tlvdb *tlvdb_fixed(tlv_tag_t tag, size_t len, const unsigned char *value);
struct tlvdb *tlvdb_parse(const unsigned char *buf, size_t len);
struct tlvdb *tlvdb_parse_multi(const unsigned char *buf, size_t len);
struct tlvdb *tlvdb_decode(const struct tlvdb *tlvdb, tlv_tag_t tag, size_t *len, unsigned char **buf);

void tlvdb_free(struct tlvdb *tlvdb);
void tlvdb_add(struct tlvdb *tlvdb, struct tlvdb *other);
void tlvdb_visit(const struct tlvdb *tlvdb, void (*func)(const struct tlv *tlv, void *data), void *data);

const struct tlv *tlvdb_get(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev);
const struct tlvdb *tlvdb_get_tlvdb(const struct tlvdb *tlvdb, tlv_tag_t tag);
const struct tlvdb *tlvdb_find(const struct tlvdb *tlvdb, tlv_tag_t tag);
const struct tlvdb *tlvdb_find_next(const struct tlvdb *tlvdb, const struct tlvdb *prev);
const struct tlv *tlvdb_get_inchild(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev);
unsigned char *tlv_encode(const struct tlv *tlv, size_t *len);
struct tlvdb *tlvdb_elm_get_next(struct tlvdb *tlvdb);
struct tlvdb *tlvdb_elm_get_children(struct tlvdb *tlvdb);

/* Utility functions */
bool tlv_is_constructed(const struct tlv *tlv);
const char *tlv_tag_get_name(tlv_tag_t tag);
const char *tlv_tag_get_description(tlv_tag_t tag);
void tlv_tag_dump(const struct tlv *tlv, FILE *f, int level);
void tlvdb_dump(const struct tlvdb *tlvdb, FILE *f);

#ifdef __cplusplus
}
#endif

#endif
