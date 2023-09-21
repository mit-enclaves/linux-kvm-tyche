#ifndef __INCLUDE_TYCHE_REGISTER_MAP_H__
#define __INCLUDE_TYCHE_REGISTER_MAP_H__

/// Register groups that can be set for an unsealed domain.
/// @warn: This must be the same as in the monitor.
typedef enum register_group_t
{
  TYCHE_REG_GP = 0,
  TYCHE_REG_CR = 1,
  TYCHE_REG_16 = 2,
  TYCHE_REG_32 = 3,
  TYCHE_REG_64 = 4,
  TYCHE_REG_NAT = 5,
} register_group_t;

/// General purpose map.
/// @warn: This must be the same as in the monitor.
/// @TODO: there are duplicated entries such as cr3 that belongs to multiple
/// groups...
typedef enum reg_gp_t
{
  REG_GP_RAX = 0,
  REG_GP_RBX = 1,
  REG_GP_RCX = 2,
  REG_GP_RDX = 3,
  REG_GP_RBP = 4,
  REG_GP_RSI = 5,
  REG_GP_RDI = 6,
  REG_GP_R8 = 7,
  REG_GP_R9 = 8,
  REG_GP_R10 = 9,
  REG_GP_R11 = 10,
  REG_GP_R12 = 11,
  REG_GP_R13 = 12,
  REG_GP_R14 = 13,
  REG_GP_R15 = 14,
  REG_GP_RSP = 15,
  REG_GP_RIP = 16,
  REG_GP_CR3 = 17,
  REG_GP_LSTAR = 18,
} reg_gp_t;

#endif /*__INCLUDE_TYCHE_REGISTER_MAP_H__*/
