#include "color_bitmap.h"
#include "common_log.h"
#include "tyche_cross_alloc.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif




/**
 * @brief Set all bits to zero
 * 
 * @param cbm caller allocated bitmap
 */
void color_bitmap_init(color_bitmap_t *cbm) {
    CROSS_MEMSET(cbm, 0, sizeof(color_bitmap_t));
}

/**
 * @brief Set all bits to the values specified in @raw
 * 
 * @param cbm caller allocated bitmap
 * @param raw caller allocated array to initialize bitmap with
 */
void color_bitmap_from_raw(color_bitmap_t *cbm, uint8_t raw[TYCHE_COLOR_BYTES]) {
    CROSS_MEMCPY(cbm->data, raw, sizeof(cbm->data));
}

/**
 * @brief Get the number of "payload bits". Due to alignment this
 * might be smaller than the internally allocated amount of bits
 * 
 * @param cbm initialized bitmap
 * @return size_t Number of payload bits
 */
size_t color_bitmap_get_bit_count(color_bitmap_t *cbm) {
    return TYCHE_COLOR_COUNT;
}

/**
 * @brief Size of the bitmap in bytes. Due to alignment this might
 * be larger than multyplying payload bits with 8. Use color_bitmap_get_bit_count
 * to get number of "payload bits"
 * 
 * @param cbm initialized bitmap
 * @return size_t number of bytes of the internal buffer
 */
size_t color_bitmap_get_byte_count(color_bitmap_t *cbm) {
    return TYCHE_COLOR_BYTES;
}

/**
 * @brief Change the value bit at @bit_idx to @value.
 * Panics on out of bounds
 * 
 * @param cbm  initialized bitmap
 * @param bit_idx bit that we want to manipulate
 * @param value  new value for bit
 */
void color_bitmap_set(color_bitmap_t *cbm, size_t bit_idx, bool value) {
    size_t byte_idx;
    size_t byte_offset;
    if( bit_idx >= color_bitmap_get_bit_count(cbm) ) {
        ERROR("Out of bounds bit idx %lu, max idx is %lu", bit_idx, color_bitmap_get_bit_count(cbm));
        FAIL();
    }

    byte_idx = bit_idx / 8;
    byte_offset = bit_idx % 8;

    if( value ) {
        uint8_t mask = ( (uint8_t)0x1  << byte_offset);
        cbm->data[byte_idx] |= mask;       
    } else {
        uint8_t mask = ~( (uint8_t)0x1  << byte_offset);
        cbm->data[byte_idx] &= mask;
    }
}

/**
 * @brief Get the value of bit at @bit_idx
 * Panics on out of bounds
 *
 * @param cbm initialized bitmap
 * @param bit_idx bit whoose value we want to get
 * @return true if bit is set
 * @return false if bit is not set
 */
bool color_bitmap_get(color_bitmap_t *cbm, size_t bit_idx) {
size_t byte_idx;
    size_t byte_offset;
    uint8_t selection_mask;
    if( bit_idx >= color_bitmap_get_bit_count(cbm) ) {
        ERROR("Out of bounds bit idx %lu, max idx is %lu", bit_idx, color_bitmap_get_bit_count(cbm));
        FAIL();
    }
    byte_idx = bit_idx / 8;
    byte_offset = bit_idx % 8;
    selection_mask = ((uint8_t)0x1) << byte_offset;
    return cbm->data[byte_idx] & selection_mask;
}

/**
 * @brief Convenience function that sets all bits to 1.
 * Faster than repeated calls to set individual bits
 * 
 * @param cbm intialized bitmap
 * @param value new value for all bits
 */
void color_bitmap_set_all(color_bitmap_t *cbm, bool value) {
    CROSS_MEMSET(cbm->data,value, sizeof(cbm->data));
}

/**
 * @brief Check if self is subset of other
 * 
 * @param self initialized bitmap
 * @param other initialized bitmap
 * @return true if self is subset of other
 * @return false  if self is not subset of other
 */
bool color_bitmap_is_subset_of(color_bitmap_t *self, color_bitmap_t *other) {
    size_t idx_last_full_byte, idx;

    if( sizeof(self->data) == 1) {
        idx_last_full_byte = 0;
    } else if( (color_bitmap_get_bit_count(self) % 8) == 0) {
        idx_last_full_byte = sizeof(self->data) - 1;
    } else {
        idx_last_full_byte = sizeof(self->data) - 2;
    }

    //check "full" bytes
    for(idx = 0; idx < idx_last_full_byte +1; idx++) {
        if( (self->data[idx] | other->data[idx]) != other->data[idx] ) {
            return false;
        }
    }

    //if last byte has some trailing bits, discard them before comparing
    if( idx_last_full_byte != sizeof(self->data) - 1) {
        size_t mask;
        uint8_t self_payload,other_payload;
        size_t payload_bit_count = color_bitmap_get_bit_count(self) % 8;
        if( payload_bit_count == 0) {
            FAIL();
        }

        mask = ~((uint8_t)0xff) << payload_bit_count;
        self_payload = self->data[idx_last_full_byte+1] & mask;
        other_payload = other->data[idx_last_full_byte+1] & mask;
        if( (self_payload | other_payload) != other_payload) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Get pointer to internal buffer
 * 
 * @param cbm initialized bitmap
 * @return const uint8_t*  pointer to internal buffer
 */
const uint8_t *color_bitmap_get_raw(color_bitmap_t *cbm) {
    return cbm->data;
}