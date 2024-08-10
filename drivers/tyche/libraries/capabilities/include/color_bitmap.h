#ifndef COLOR_BITMAP_H
#define COLOR_BITMAP_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#endif

//Number of colors of the memory coloring functions. Used when we iterate and
//allocate color bitmaps
#define TYCHE_COLOR_COUNT 64 //TODO: make dynamic by requesting info from tyche?
//number of bytes required to represent TYCHE_COLOR_COUNTS. Might be larger
// if color count is not a multiple of 8
#define TYCHE_COLOR_BYTES ((TYCHE_COLOR_COUNT + 7) / 8)

typedef struct color_bitmap {
	uint8_t data[TYCHE_COLOR_BYTES];
} color_bitmap_t;

void color_bitmap_init(color_bitmap_t *cbm);
void color_bitmap_from_raw(color_bitmap_t *cbm, uint8_t raw[TYCHE_COLOR_BYTES]);
size_t color_bitmap_get_bit_count(color_bitmap_t *cbm);
size_t color_bitmap_get_byte_count(color_bitmap_t *cbm);

void color_bitmap_set(color_bitmap_t *cbm, size_t bit_idx, bool value);
bool color_bitmap_get(color_bitmap_t *cbm, size_t bit_idx);
void color_bitmap_set_all(color_bitmap_t *cbm, bool value);

bool color_bitmap_is_subset_of(color_bitmap_t *self, color_bitmap_t *other);

const uint8_t *color_bitmap_get_raw(color_bitmap_t *cbm);

#endif