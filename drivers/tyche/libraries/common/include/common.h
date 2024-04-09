#ifndef __COMMON_H__
#define __COMMON_H__

// ————————————————— Unify success and failure return codes ————————————————— //
#define SUCCESS (0)
#define FAILURE (-1)

// —————————————————————————————— Common Types —————————————————————————————— //

typedef unsigned long long usize;
#define UNINIT_USIZE (~((usize)0))

#endif
