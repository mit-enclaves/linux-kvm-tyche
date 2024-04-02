#ifndef __COMMON_LOG_H__
#define __COMMON_LOG_H__

#ifndef TYCHE_USER_SPACE
#include <linux/kernel.h>
#else 
#if TYCHE_USER_SPACE == 1
#include <stdio.h>
#include <stdlib.h>
#endif
#endif

// ————————————————————————————————— Macros ————————————————————————————————— //


#ifndef TYCHE_USER_SPACE
#define TEST(cond)                                                             \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printk(KERN_ERR "[%s:%d] %s: cond failed\n", __FILE__, \
			       __LINE__, __func__);                            \
		}                                                              \
	} while (0);

#define LOG(...)                                                       \
	do {                                                           \
		printk(KERN_NOTICE "[@%s:%d %s] ", __FILE__, __LINE__, \
		       __func__);                                      \
		printk(KERN_NOTICE __VA_ARGS__);                       \
		printk("\n");                                          \
	} while (0);

#define DEBUG(...) \
	do {       \
	} while (0);

#define ERROR(...)                                                             \
	do {                                                                   \
		printk(KERN_ERR "[@%s:%d %s] ", __FILE__, __LINE__, __func__); \
		printk(KERN_ERR __VA_ARGS__);                                  \
		printk("\n");                                                  \
	} while (0);

#else

#if TYCHE_USER_SPACE == 1

#define TEST(cond)                                                          \
	do {                                                                \
		if (!(cond)) {                                              \
			fprintf(stderr, "[%s:%d] %s\n", __FILE__, __LINE__, \
				__func__);                                  \
			abort();                                            \
		}                                                           \
	} while (0);

#define LOG(...)                                                          \
	do {                                                              \
		printf("[LOG @%s:%d %s] ", __FILE__, __LINE__, __func__); \
		printf(__VA_ARGS__);                                      \
		printf("\n");                                             \
	} while (0);

#ifdef TYCHE_DEBUG
#define DEBUG(...)                                                          \
	do {                                                                \
		printf("[DEBUG @%s:%d %s] ", __FILE__, __LINE__, __func__); \
		printf(__VA_ARGS__);                                        \
		printf("\n");                                               \
	} while (0);
#else
#define DEBUG(...) do {} while(0);
#endif

#define ERROR(...)                                              \
  do {                                                          \
    printf("[ERROR @%s:%d %s] ", __FILE__, __LINE__, __func__); \
    printf(__VA_ARGS__);                                        \
    printf("\n");                                               \
  } while (0);

#elif TYCHE_USER_SPACE == 2

#define TEST(cond) \
	do {       \
	} while (0);

#define LOG(...) \
	do {     \
	} while (0);

#define DEBUG(...) \
	do {       \
	} while (0);

#define ERROR(...) \
	do {       \
	} while (0);

#endif /* value TYCHE_USER_SPACE */
#endif /* ifdef TYCHE_USER_SPACE */

#endif /* __COMMON_LOG_H__ */
