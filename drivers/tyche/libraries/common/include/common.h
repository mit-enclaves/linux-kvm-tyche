#ifndef __COMMON_H__
#define __COMMON_H__

// ————————————————— Unify success and failure return codes ————————————————— //
#define SUCCESS (0)
#define FAILURE (-1)

typedef enum tyche_switch_res_e {
	SWITCH_SYNC = 0,
	SWITCH_ERROR = 1,
	SWITCH_EXCEPTION = 2,
} tyche_switch_res_e;

#define TYCHE_SYNTHETHIC_EXIT_REASON (1000)

// —————————————————————————————— Common Types —————————————————————————————— //

typedef unsigned long long usize;
#define UNINIT_USIZE (~((usize)0))

#endif
