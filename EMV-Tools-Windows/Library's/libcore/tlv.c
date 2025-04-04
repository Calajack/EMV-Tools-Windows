#include "tlv.h"
#include "emv_tags.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>

static bool tlv_parse_tag(const unsigned char **buf, size_t *len, tlv_tag_t *tag)
{
    if (*len == 0)
        return false;

    *tag = (*buf)[0];
    (*buf)++;
    (*len)--;

    // Handle multi-byte tags
    if ((*tag & 0x1F) == 0x1F) {
        while (*len != 0) {
            uint8_t b = (*buf)[0];
            (*buf)++;
            (*len)--;
            *tag = (*tag << 8) | b;
            if ((b & 0x80) == 0)
                break;
        }
    }

    return true;
}

static bool tlv_parse_len(const unsigned char **buf, size_t *len, size_t *out_len)
{
    if (*len == 0)
        return false;

    uint8_t b = (*buf)[0];
    (*buf)++;
    (*len)--;

    if (b < 0x80) {
        *out_len = b;
        return true;
    }

    if (b == 0x80 || b == 0xff) // Indefinite length not supported
        return false;

    b &= 0x7f;
    if (b > *len || b > sizeof(*out_len))
        return false;

    *out_len = 0;
    for (int i = 0; i < b; i++) {
        *out_len = (*out_len << 8) | (*buf)[0];
        (*buf)++;
        (*len)--;
    }

    return true;
}

bool tlv_parse_tl(const unsigned char **buf, size_t *len, struct tlv *tlv)
{
    if (!tlv_parse_tag(buf, len, &tlv->tag))
        return false;

    if (!tlv_parse_len(buf, len, &tlv->len))
        return false;

    tlv->value = NULL;

    return true;
}

bool tlv_parse_tlv(const unsigned char **buf, size_t *len, struct tlv *tlv)
{
    if (!tlv_parse_tl(buf, len, tlv))
        return false;

    if (tlv->len > *len)
        return false;

    tlv->value = (unsigned char *)*buf;
    *buf += tlv->len;
    *len -= tlv->len;

    return true;
}

bool tlv_is_constructed(const struct tlv *tlv)
{
    return tlv->tag & TLV_TAG_COMPLEX;
}

struct tlvdb *tlvdb_fixed(tlv_tag_t tag, size_t len, const unsigned char *value)
{
    struct tlvdb *tlvdb = calloc(1, sizeof(*tlvdb));
    if (!tlvdb)
        return NULL;

    tlvdb->tag.tag = tag;
    tlvdb->tag.len = len;
    tlvdb->tag.value = malloc(len);
    if (!tlvdb->tag.value) {
        free(tlvdb);
        return NULL;
    }

    memcpy(tlvdb->tag.value, value, len);

    return tlvdb;
}

void tlvdb_free(struct tlvdb *tlvdb)
{
    if (!tlvdb)
        return;

    tlvdb_free(tlvdb->next);
    tlvdb_free(tlvdb->children);

    if (tlvdb->tag.value)
        free(tlvdb->tag.value);

    free(tlvdb);
}

void tlvdb_add(struct tlvdb *tlvdb, struct tlvdb *other)
{
    if (!tlvdb || !other)
        return;

    // Find the end of the chain
    while (tlvdb->next)
        tlvdb = tlvdb->next;

    tlvdb->next = other;
}

struct tlvdb *tlvdb_parse(const unsigned char *buf, size_t len)
{
    if (!buf || !len)
        return NULL;

    struct tlvdb *tlvdb = NULL;
    struct tlv tlv;

    if (!tlv_parse_tlv(&buf, &len, &tlv))
        return NULL;

    tlvdb = tlvdb_fixed(tlv.tag, tlv.len, tlv.value);
    if (!tlvdb)
        return NULL;

    // Parse children for constructed tags
    if (tlv_is_constructed(&tlv)) {
        size_t child_len = tlv.len;
        const unsigned char *child_data = tlv.value;
        struct tlvdb *child_db = tlvdb_parse_multi(child_data, child_len);
        if (child_db) {
            tlvdb->children = child_db;
            child_db->parent = tlvdb;
        }
    }

    return tlvdb;
}

struct tlvdb *tlvdb_parse_multi(const unsigned char *buf, size_t len)
{
    if (!buf || !len)
        return NULL;

    struct tlvdb *result = NULL;
    struct tlvdb *last = NULL;
    struct tlvdb *new_db;
    size_t pos = 0;

    while (pos < len) {
        struct tlv tlv;
        const unsigned char *tmp = buf + pos;
        size_t tmp_len = len - pos;

        if (!tlv_parse_tlv(&tmp, &tmp_len, &tlv))
            break;

        pos = len - tmp_len - tlv.len;
        new_db = tlvdb_parse(buf + pos, tlv.len + tmp_len);
        if (!new_db)
            continue;

        if (!result) {
            result = new_db;
            last = result;
        } else {
            last->next = new_db;
            last = new_db;
        }

        pos += tlv.len;
    }

    return result;
}

const struct tlv *tlvdb_get(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev)
{
    if (!tlvdb)
        return NULL;

    // If we have previous element, start from next
    if (prev) {
        tlvdb = tlvdb->next;
    }

    while (tlvdb) {
        if (tlvdb->tag.tag == tag)
            return &tlvdb->tag;
        tlvdb = tlvdb->next;
    }

    return NULL;
}

const struct tlvdb *tlvdb_get_tlvdb(const struct tlvdb *tlvdb, tlv_tag_t tag)
{
    if (!tlvdb)
        return NULL;

    while (tlvdb) {
        if (tlvdb->tag.tag == tag)
            return tlvdb;
        tlvdb = tlvdb->next;
    }

    return NULL;
}

const struct tlvdb *tlvdb_find(const struct tlvdb *tlvdb, tlv_tag_t tag)
{
    if (!tlvdb)
        return NULL;

    if (tlvdb->tag.tag == tag)
        return tlvdb;

    // Try children
    const struct tlvdb *child = tlvdb_find(tlvdb->children, tag);
    if (child)
        return child;

    // Try next
    return tlvdb_find(tlvdb->next, tag);
}

const struct tlvdb *tlvdb_find_next(const struct tlvdb *tlvdb, const struct tlvdb *prev)
{
    if (!tlvdb || !prev)
        return NULL;

    tlv_tag_t tag = prev->tag.tag;

    // Start from the next element
    tlvdb = prev->next;
    while (tlvdb) {
        // Found it
        if (tlvdb->tag.tag == tag)
            return tlvdb;

        // Try children
        const struct tlvdb *child = tlvdb_find(tlvdb->children, tag);
        if (child)
            return child;

        // Go to next
        tlvdb = tlvdb->next;
    }

    return NULL;
}

const struct tlv *tlvdb_get_inchild(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev)
{
    if (!tlvdb)
        return NULL;

    // Find the root
    while (tlvdb->parent)
        tlvdb = tlvdb->parent;

    // Find the first occurrence
    const struct tlvdb *found = tlvdb_find(tlvdb, tag);
    if (!found)
        return NULL;

    // If no previous element, return the first one
    if (!prev)
        return &found->tag;

    // Otherwise, find the next one
    found = tlvdb_find_next(tlvdb, found);
    return found ? &found->tag : NULL;
}

void tlvdb_visit(const struct tlvdb *tlvdb, void (*func)(const struct tlv *tlv, void *data), void *data)
{
    if (!tlvdb || !func)
        return;

    func(&tlvdb->tag, data);

    tlvdb_visit(tlvdb->children, func, data);
    tlvdb_visit(tlvdb->next, func, data);
}

unsigned char *tlv_encode(const struct tlv *tlv, size_t *len)
{
    if (!tlv || !len)
        return NULL;

    size_t size = 0;
    tlv_tag_t tag = tlv->tag;
    size_t tag_len = 1;

    // Determine tag length
    while ((tag >> 8) != 0) {
        tag_len++;
        tag >>= 8;
    }

    // Determine length encoding
    size_t len_len = 1;
    if (tlv->len >= 128) {
        size_t tmp = tlv->len;
        len_len = 1;
        while (tmp > 0) {
            len_len++;
            tmp >>= 8;
        }
    }

    // Total size
    size = tag_len + len_len + tlv->len;
    unsigned char *data = malloc(size);
    if (!data)
        return NULL;

    // Encode tag
    tag = tlv->tag;
    for (int i = tag_len - 1; i >= 0; i--) {
        data[i] = tag & 0xff;
        tag >>= 8;
    }

    // Encode length
    if (tlv->len < 128) {
        data[tag_len] = tlv->len;
    } else {
        size_t tmp = tlv->len;
        data[tag_len] = 0x80 + (len_len - 1);
        for (int i = len_len - 1; i > 0; i--) {
            data[tag_len + i] = tmp & 0xff;
            tmp >>= 8;
        }
    }

    // Copy value
    memcpy(data + tag_len + len_len, tlv->value, tlv->len);

    *len = size;
    return data;
}

void tlv_tag_dump(const struct tlv *tlv, FILE *f, int level)
{
    if (!tlv || !f)
        return;

    for (int i = 0; i < level; i++)
        fprintf(f, "  ");

    fprintf(f, "Tag: %04x (", tlv->tag);

    const char *name = tlv_tag_get_name(tlv->tag);
    if (name)
        fprintf(f, "%s", name);
    else
        fprintf(f, "Unknown");

    fprintf(f, "), len: %zu\n", tlv->len);

    if (tlv->len > 0) {
        for (int i = 0; i < level + 1; i++)
            fprintf(f, "  ");

        fprintf(f, "Data:");
        for (size_t i = 0; i < tlv->len; i++)
            fprintf(f, " %02x", tlv->value[i]);
        fprintf(f, "\n");
    }
}

void tlvdb_dump(const struct tlvdb *tlvdb, FILE *f)
{
    if (!tlvdb || !f)
        return;

    tlv_tag_dump(&tlvdb->tag, f, 0);

    if (tlvdb->children) {
        fprintf(f, "Children:\n");
        tlvdb_dump(tlvdb->children, f);
    }

    if (tlvdb->next) {
        fprintf(f, "Next:\n");
        tlvdb_dump(tlvdb->next, f);
    }
}

// Get tag name implementation - this would need to be filled with EMV tag names
//const char *tlv_tag_get_name(tlv_tag_t tag)
//{
 //   switch (tag) {
//        case 0x82: return "Application Interchange Profile";
//        case 0x84: return "Dedicated File (DF) Name";
//        case 0x95: return "Terminal Verification Results";
//        default: return NULL;
//    }
//
// Get tag description implementation
//const char *tlv_tag_get_description(tlv_tag_t tag)
//{
 //   // Similar to tlv_tag_get_name, but with descriptions
 //   return NULL;
//}

struct tlvdb *tlvdb_elm_get_next(struct tlvdb *tlvdb)
{
    return tlvdb ? tlvdb->next : NULL;
}

struct tlvdb *tlvdb_elm_get_children(struct tlvdb *tlvdb)
{
    return tlvdb ? tlvdb->children : NULL;
}

struct tlvdb *tlvdb_decode(const struct tlvdb *tlvdb, tlv_tag_t tag, size_t *len, unsigned char **buf)
{
    if (!tlvdb || !len || !buf)
        return NULL;

    const struct tlv *tlv = tlvdb_get(tlvdb, tag, NULL);
    if (!tlv)
        return NULL;

    *len = tlv->len;
    *buf = malloc(tlv->len);
    if (!*buf)
        return NULL;

    memcpy(*buf, tlv->value, tlv->len);

    return tlvdb_fixed(tag, *len, *buf);
}

// Use the emv_tags module for tag names
static const char* emv_tag_get_name(uint32_t tag)
{
    // Look up the tag name in a predefined table
    for (size_t i = 0; i < sizeof(emv_tags) / sizeof(emv_tags[0]); i++) {
        if (emv_tags[i].tag == tag)
            return emv_tags[i].name;
    }
    return NULL;
}

// Use the emv_tags module for tag descriptions
static const char* emv_tag_get_description(uint32_t tag)
{
    // Look up the tag description
    for (size_t i = 0; i < sizeof(emv_tags) / sizeof(emv_tags[0]); i++) {
        if (emv_tags[i].tag == tag)
            return emv_tags[i].description;
    }
    return NULL;
}
