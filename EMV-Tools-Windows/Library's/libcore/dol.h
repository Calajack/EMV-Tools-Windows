// dol.h - Data Object List processing
#ifndef EMV_DOL_H
#define EMV_DOL_H

#include <stddef.h>
#include <stdbool.h>
#include "tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Maximum size for a constructed DOL
 */
#define DOL_MAX_SIZE 256

/**
 * Structure describing Data Object List
 */
struct dol {
    const unsigned char *data;
    size_t len;
};

/**
 * @brief Get number of entries in DOL
 * @param dol DOL to process
 * @return Number of entries in the DOL
 */
size_t dol_count(const struct dol *dol);

/**
 * @brief Get tag of DOL entry
 * @param dol DOL to process
 * @param pos Position in DOL (0-based)
 * @return Tag value or 0 if error
 */
tlv_tag_t dol_get_tag(const struct dol *dol, size_t pos);

/**
 * @brief Get length of DOL entry
 * @param dol DOL to process
 * @param pos Position in DOL (0-based)
 * @return Length value or 0 if error
 */
size_t dol_get_len(const struct dol *dol, size_t pos);

/**
 * @brief Calculate packed size of filled DOL
 * @param dol DOL to process
 * @return Size of DOL data if packed
 */
size_t dol_size(const struct dol *dol);

/**
 * @brief Fill DOL with data from TLV database
 * @param dol DOL to fill
 * @param tlvdb TLV database
 * @param data Buffer to store data 
 * @param len Length of buffer
 * @return Size of filled data or 0 on error
 */
size_t dol_fill(const struct dol *dol, const struct tlvdb *tlvdb, unsigned char *data, size_t len);

/**
 * @brief Create a TLV database from DOL
 * @param dol DOL to process
 * @param data Data to fill the DOL
 * @param len Length of data
 * @return TLV database with filled DOL or NULL on error
 */
struct tlvdb *dol_parse(const struct dol *dol, const unsigned char *data, size_t len);

/**
 * @brief Fill DOL from TLV database and create new TLV database entry
 * @param tag Tag for the resulting entry
 * @param dol DOL to fill
 * @param tlvdb TLV database
 * @return TLV database with new entry or NULL on error
 */
struct tlvdb *dol_process(tlv_tag_t tag, const struct dol *dol, const struct tlvdb *tlvdb);

#ifdef __cplusplus
}
#endif EMV_DOL_H

#endif 
