#ifndef __INCLUDE_TYCHE_REGISTER_MAP_H__
#define __INCLUDE_TYCHE_REGISTER_MAP_H__

/// General purpose map.
/// @warn: This must be the same as in the monitor.
/// @TODO: there are duplicated entries such as cr3 that belongs to multiple
/// groups...
typedef enum reg_gp_t {
	REG_GP_RAX = 0xff007000,
	REG_GP_RBX = 0xff007002,
	REG_GP_RCX = 0xff007004,
	REG_GP_RDX = 0xff007006,
	REG_GP_RBP = 0xff007008,
	REG_GP_RSI = 0xff00700a,
	REG_GP_RDI = 0xff00700c,
	REG_GP_R8 = 0xff00700e,
	REG_GP_R9 = 0xff007010,
	REG_GP_R10 = 0xff007012,
	REG_GP_R11 = 0xff007014,
	REG_GP_R12 = 0xff007016,
	REG_GP_R13 = 0xff007018,
	REG_GP_R14 = 0xff00701a,
	REG_GP_R15 = 0xff00701c,
	REG_GP_LSTAR = 0xff00701e,
	REG_GP_RSP = 0x0000681c,
	REG_GP_RIP = 0x0000681e,
	REG_GP_CR3 = 0x00006802,
} reg_gp_t;

#endif /*__INCLUDE_TYCHE_REGISTER_MAP_H__*/
