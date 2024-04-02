#ifndef __INCLUDE_TYCHE_API_H__
#define __INCLUDE_TYCHE_API_H__

#include "tyche_capabilities_types.h"
#include "tyche_register_map.h"

/// Copied from the tyche source code
typedef enum tyche_monitor_call_t {
	TYCHE_CREATE_DOMAIN = 1,
	TYCHE_SEAL_DOMAIN = 2,
	TYCHE_SEND = 3,
	TYCHE_SEGMENT_REGION = 4,
	TYCHE_REVOKE = 5,
	TYCHE_DUPLICATE = 6,
	TYCHE_ENUMERATE = 7,
	TYCHE_SWITCH = 8,
	TYCHE_EXIT = 9,
	TYCHE_DEBUG = 10,
	TYCHE_CONFIGURE = 11,
	TYCHE_SEND_REGION = 12,
	TYCHE_CONFIGURE_CORE = 13,
	TYCHE_GET_CONFIG_CORE = 14,
	TYCHE_ALLOC_CORE_CONTEXT = 15,
	TYCHE_READ_ALL = 16,
	TYCHE_WRITE_ALL = 17,
	TYCHE_WRITE_FIELDS = 18,
	TYCHE_SELF_CONFIG = 19,
	TYCHE_ENCLAVE_ATTESTATION = 20,
	TYCHE_REVOKE_ALIASED_REGION = 21,
	TYCHE_SERIALIZE_ATTESTATION = 22,
} tyche_monitor_call_t;

typedef enum tyche_configurations_t {
	TYCHE_CONFIG_PERMISSIONS = 0,
	TYCHE_CONFIG_TRAPS = 1,
	TYCHE_CONFIG_CORES = 2,
	TYCHE_NR_CONFIGS = 3,
} tyche_configurations_t;

typedef enum tyche_perm_value_t {
	TYCHE_PERM_SPAWN = (1 << 0),
	TYCHE_PERM_SEND = (1 << 1),
	TYCHE_PERM_DUPLICATE = (1 << 2),
	TYCHE_PERM_ALIAS = (1 << 3),
	TYCHE_PERM_CARVE = (1 << 4),
} tyche_perm_value_t;

#define TYCHE_CAPA_NULL ((capa_index_t)0)

/// Defined in capabilities/src/domain.rs
#define CAPAS_PER_DOMAIN ((capa_index_t)100)

/// A type to pass arguments and receive when calling tyche.
typedef struct vmcall_frame_t {
	// Vmcall id.
	usize vmcall;

	// Arguments.
	usize arg_1;
	usize arg_2;
	usize arg_3;
	usize arg_4;
	usize arg_5;
	usize arg_6;

	// Results.
	usize value_1;
	usize value_2;
	usize value_3;
	usize value_4;
	usize value_5;
	usize value_6;
} vmcall_frame_t;

// —————————————————————————————————— API ——————————————————————————————————— //

int tyche_call(vmcall_frame_t *frame);

int tyche_create_domain(capa_index_t *management, int aliased);

int tyche_set_domain_config(capa_index_t management, tyche_configurations_t idx,
			    usize value);

int tyche_set_self_core_config(usize field, usize value);

int tyche_set_domain_core_config(capa_index_t management, usize core, usize idx,
				 usize value);

int tyche_get_domain_core_config(capa_index_t management, usize core, usize idx,
				 usize *value);

int tyche_alloc_core_context(capa_index_t management, usize core);

int tyche_seal(capa_index_t *transition, capa_index_t management);

int tyche_segment_region(usize is_shared, capa_index_t capa,
			 capa_index_t *to_send, capa_index_t *revoke,
			 usize start, usize end, usize prot);

int tyche_send(capa_index_t dest, capa_index_t capa);

int tyche_send_aliased(capa_index_t dest, capa_index_t capa, int is_repeat,
		       usize alias, usize size);

int tyche_share(capa_index_t *left, capa_index_t dest, capa_index_t capa,
		usize a1, usize a2, usize a3);

int tyche_revoke(capa_index_t id);

int tyche_revoke_region(capa_index_t id, capa_index_t child, paddr_t gpa,
			paddr_t size);

int tyche_serialize_attestation(usize addr, usize size, usize *written);

int tyche_switch(capa_index_t *transition_handle,
		 usize exit_frame[TYCHE_EXIT_FRAME_SIZE]);

int tyche_read_gp_registers(capa_index_t management, usize core,
			    usize regs[TYCHE_GP_REGS_SIZE]);

int tyche_write_fields(capa_index_t management, usize core, usize *fields,
		       usize *values, int size);

int tyche_duplicate(capa_index_t *new_capa, capa_index_t capa);

#endif
