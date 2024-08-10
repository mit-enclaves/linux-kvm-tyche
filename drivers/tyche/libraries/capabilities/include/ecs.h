#ifndef __INCLUDE_HARDWARE_CAPABILITIES_H__
#define __INCLUDE_HARDWARE_CAPABILITIES_H__

#include "common.h"
#include "tyche_capabilities_types.h"

#ifndef __KERNEL__
#include <stdint.h>
#include <stddef.h>
#endif

// —————————————————————————————————— API ——————————————————————————————————— //
typedef struct {
	uint8_t raw[TYCHE_COLOR_BYTES + 1];
} serialized_resource_kind_t;

/// Enumerate the next capability with index >= idx.
int enumerate_capa(capa_index_t idx, capa_index_t *next, capability_t *capa);

int deserialize_access_rights_t(usize serialized_flags,
				serialized_resource_kind_t *serialized_rk,
				access_rights_t *out);
int serialize_access_rights_t(access_rights_t *rights,
			      usize *out_serialized_flags,
			      serialized_resource_kind_t *serialized_rk);

#endif
