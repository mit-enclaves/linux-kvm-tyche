#ifndef __INCLUDE_TYCHE_API_H__
#define __INCLUDE_TYCHE_API_H__

//luca: c definition of the apis

#include "common.h"
#include "linux/types.h"
#include "tyche_capabilities_types.h"
#include "tyche_register_map.h"

#ifndef __KERNEL__
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#endif

#define TYCHE_DATA_BUF_MAX_BYTES 256
/**
 * @brief Statically allocated buffer for receiving data from tyche
 * Dimensions must be changed in sync with the tyche counterpart
 * 
 */
typedef struct {
	uint8_t raw[TYCHE_DATA_BUF_MAX_BYTES];
	// number of valid bytes in raw
	size_t used_bytes;
} tyche_data_buf_t;

int tyche_data_buf_from_raw(tyche_data_buf_t *buf, uint8_t *raw,
			    size_t raw_len);

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
	TYCHE_TEST_CALL = 30,
	TYCHE_GET_HPAS = 31,
	TYCHE_SEND_REGION_REPEAT = 32,
	TYCHE_SEND_DATA = 33,
	TYCHE_GET_DATA = 34,
} tyche_monitor_call_t;

typedef enum tyche_configurations_t {
	TYCHE_CONFIG_PERMISSIONS = 0,
	TYCHE_CONFIG_TRAPS = 1,
	TYCHE_CONFIG_CORES = 2,
	TYCHE_CONFIG_R16 = 3,
	TYCHE_CONFIG_W16 = 4,
	TYCHE_CONFIG_R32 = 5,
	TYCHE_CONFIG_W32 = 6,
	TYCHE_CONFIG_R64 = 7,
	TYCHE_CONFIG_W64 = 8,
	TYCHE_CONFIG_RNAT = 9,
	TYCHE_CONFIG_WNAT = 10,
	TYCHE_CONFIG_RGP = 11,
	TYCHE_CONFIG_WGP = 12,
	TYCHE_NR_CONFIGS = 13,
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

typedef uint8_t tyche_data_handle_t;
typedef union {
	usize as_usize[3];
	uint8_t as_bytes[3 * sizeof(usize)];
} tyche_send_get_chunk_t;

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
			 usize start, usize end, access_rights_t rights);

int tyche_send(capa_index_t dest, capa_index_t capa);

int tyche_send_aliased(capa_index_t dest, capa_index_t capa, int is_repeat,
		       usize alias, usize size, access_rights_t rights);

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

int tyche_get_hpas(uint64_t start_gpa, size_t length, uint64_t *out_start_hpa,
		   uint64_t *out_end_hpa);

int tyche_send_data(tyche_data_handle_t handle, uint8_t *data, size_t data_len,
		    bool mark_ready, tyche_data_handle_t *out_handle);

int tyche_send_all(uint8_t *data, size_t len, tyche_data_handle_t *out_handle);

int tyche_get_all_data(tyche_data_handle_t handle, tyche_data_buf_t *recv_buf);

#endif
