// dol.c - Data Object List implementation
#include "dol.h"
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

static size_t dol_get_pos(const struct dol *dol, size_t pos, 
                          size_t *tag_start, size_t *tag_length,
                          size_t *len_start, size_t *len_length)
{
    if (!dol || !dol->data || !dol->len)
        return 0;

    size_t i = 0;
    size_t count = 0;

    while (i < dol->len) {
        if (count == pos && tag_start)
            *tag_start = i;

        // Get tag
        if ((dol->data[i] & 0x1f) == 0x1f) {
            // Multi-byte tag
            i++;
            if (i >= dol->len)
                return 0;
                
            while (i < dol->len && (dol->data[i] & 0x80))
                i++;
            i++;
        } else {
            i++;
        }

        if (i >= dol->len)
            return 0;

        if (count == pos) {
            if (tag_length)
                *tag_length = i - *tag_start;
            if (len_start)
                *len_start = i;
        }

        // Get length
        size_t len_bytes = 1;
        if (dol->data[i] > 0x80) {
            len_bytes = dol->data[i] & 0x7f;
            len_bytes++; // Include the length byte itself
        }
        i += len_bytes;

        if (i > dol->len)
            return 0;

        if (count == pos) {
            if (len_length)
                *len_length = len_bytes;
            size_t data_len;
            if (dol->data[*len_start] < 0x80) {
                data_len = dol->data[*len_start];
            } else {
                size_t len_size = dol->data[*len_start] & 0x7f;
                data_len = 0;
                for (size_t j = 1; j <= len_size; j++) {
                    data_len = (data_len << 8) | dol->data[*len_start + j];
                }
            }
            return data_len;
        }

        count++;
    }

    return 0;
}

static tlv_tag_t dol_get_tag_internal(const struct dol *dol, size_t pos, 
                                     size_t *start, size_t *length)
{
    if (!dol || !dol->data || !dol->len)
        return 0;

    size_t tag_start, tag_length;
    size_t len_start, len_length;

    if (!dol_get_pos(dol, pos, &tag_start, &tag_length, &len_start, &len_length))
        return 0;

    tlv_tag_t tag = 0;
    for (size_t i = 0; i < tag_length; i++) {
        tag = (tag << 8) | dol->data[tag_start + i];
    }

    if (start)
        *start = tag_start;
    if (length)
        *length = tag_length;

    return tag;
}

size_t dol_count(const struct dol *dol)
{
    if (!dol || !dol->data || !dol->len)
        return 0;

    size_t i = 0;
    size_t count = 0;

    while (i < dol->len) {
        // Get tag
        if ((dol->data[i] & 0x1f) == 0x1f) {
            // Multi-byte tag
            i++;
            if (i >= dol->len)
                return count;
                
            while (i < dol->len && (dol->data[i] & 0x80))
                i++;
            i++;
        } else {
            i++;
        }

        if (i >= dol->len)
            return count;

        // Get length
        size_t len_bytes = 1;
        if (dol->data[i] > 0x80) {
            len_bytes = dol->data[i] & 0x7f;
            len_bytes++; // Include the length byte itself
        }
        i += len_bytes;

        if (i > dol->len)
            return count;

        count++;
    }

    return count;
}

tlv_tag_t dol_get_tag(const struct dol *dol, size_t pos)
{
    return dol_get_tag_internal(dol, pos, NULL, NULL);
}

size_t dol_get_len(const struct dol *dol, size_t pos)
{
    if (!dol || !dol->data || !dol->len)
        return 0;

    size_t tag_start, tag_length;
    size_t len_start, len_length;

    size_t data_len = dol_get_pos(dol, pos, &tag_start, &tag_length, &len_start, &len_length);
    return data_len;
}

size_t dol_size(const struct dol *dol)
{
    if (!dol || !dol->data || !dol->len)
        return 0;

    size_t count = dol_count(dol);
    size_t total_size = 0;

    for (size_t i = 0; i < count; i++) {
        total_size += dol_get_len(dol, i);
    }

    return total_size;
}

size_t dol_fill(const struct dol *dol, const struct tlvdb *tlvdb, unsigned char *data, size_t len)
{
    if (!dol || !dol->data || !dol->len || !data || !len)
        return 0;

    size_t count = dol_count(dol);
    size_t pos = 0;

    for (size_t i = 0; i < count; i++) {
        tlv_tag_t tag = dol_get_tag(dol, i);
        size_t data_len = dol_get_len(dol, i);

        if (pos + data_len > len)
            return 0;

        const struct tlv *tlv = tlvdb_get(tlvdb, tag, NULL);
        if (tlv) {
            size_t copy_len = tlv->len > data_len ? data_len : tlv->len;
            memcpy(data + pos, tlv->value, copy_len);

            // Pad with zeros if needed
            if (copy_len < data_len)
                memset(data + pos + copy_len, 0, data_len - copy_len);
        } else {
            // Tag not found, fill with zeros
            memset(data + pos, 0, data_len);
        }

        pos += data_len;
    }

    return pos;
}

struct tlvdb *dol_parse(const struct dol *dol, const unsigned char *data, size_t len)
{
    if (!dol || !dol->data || !dol->len || !data || !len)
        return NULL;

    size_t count = dol_count(dol);
    size_t pos = 0;
    struct tlvdb *db = NULL;

    for (size_t i = 0; i < count; i++) {
        tlv_tag_t tag = dol_get_tag(dol, i);
        size_t data_len = dol_get_len(dol, i);

        if (pos + data_len > len)
            break;

        struct tlvdb *tag_db = tlvdb_fixed(tag, data_len, data + pos);
        if (tag_db) {
            if (!db) {
                db = tag_db;
            } else {
                tlvdb_add(db, tag_db);
            }
        }

        pos += data_len;
    }

    return db;
}

struct tlvdb *dol_process(tlv_tag_t tag, const struct dol *dol, const struct tlvdb *tlvdb)
{
    if (!dol || !dol->data || !dol->len || !tlvdb)
        return NULL;

    size_t data_len = dol_size(dol);
    if (data_len == 0 || data_len > DOL_MAX_SIZE)
        return NULL;

    unsigned char *data = malloc(data_len);
    if (!data)
        return NULL;

    size_t filled_len = dol_fill(dol, tlvdb, data, data_len);
    if (filled_len != data_len) {
        free(data);
        return NULL;
    }

    struct tlvdb *db = tlvdb_fixed(tag, data_len, data);
    free(data);

    return db;
}