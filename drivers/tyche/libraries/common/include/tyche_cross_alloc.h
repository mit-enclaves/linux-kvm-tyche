#ifndef TYCHE_CROSS_ALLOC_H
#define TYCHE_CROSS_ALLOC_H
/* Macros for memory manipulation that work in Kernel space as well as in
 * no stdlib C userspace
 */
#ifdef __KERNEL__
#include <linux/string.h>
#define CROSS_MEMSET(dst, value, bytes) memset(dst, value, bytes)
#define CROSS_MEMCPY(dst, src, bytes) memcpy(dst, src, bytes)
#else
#include <stdlib.h>
#define CROSS_MEMSET(dst, value, bytes)                      \
	do {                                                 \
		size_t idx;                                  \
		for (idx = 0; idx < bytes; idx++) {          \
			((unsigned char *)dst)[idx] = value; \
		}                                            \
	} while (0);
#define CROSS_MEMCPY(dst, src, bytes)                        \
	do {                                                 \
		size_t idx;                                  \
		for (idx = 0; idx < bytes; idx++) {          \
			((unsigned char *)dst)[idx] =        \
				((unsigned char *)src)[idx]; \
		}                                            \
	} while (0);
#endif

#endif