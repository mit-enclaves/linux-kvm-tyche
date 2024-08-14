#include "ecs.h"
#include "color_bitmap.h"
#include "common_log.h"
#include "tyche_api.h"
#include "common.h"
#include "tyche_cross_alloc.h"
#include "tyche_capabilities.h"
#include "tyche_capabilities_types.h"

#ifdef __KERNEL__
#include "linux/string.h"
#else
#include <string.h>
#endif


/**
 * @brief Deserialize the access_rights_t struct
*/
int deserialize_access_rights_t(usize serialized_flags,
				       serialized_resource_kind_t* serialized_rk,
				       access_rights_t *out)
{
	uint8_t type_id;
  type_id = serialized_rk->raw[0];

	out->flags = serialized_flags;
	out->kind = type_id;
  color_bitmap_init(&(out->color_bm));

	if (type_id == RK_RAM) {
    color_bitmap_from_raw(&(out->color_bm), serialized_rk->raw+1);
	}
  return SUCCESS;
}

/**
 * @brief Special deserialze for the slightly tweaked format used by enumerate
 * 
 * @param serialized_flags 
 * @param serialized_rk 
 * @param out 
 * @return int 
 */
static int deserialize_access_rights_t_from_enum(usize serialized_capa_and_flags,
				       serialized_resource_kind_t* serialized_rk,
				       access_rights_t *out) {
  return deserialize_access_rights_t(serialized_capa_and_flags >> 8, serialized_rk, out);
}

/**
 * @brief Serializes the access_rights_t struct for usage with tyche
*/
int serialize_access_rights_t(access_rights_t* in_rights, usize* out_serialized_flags, serialized_resource_kind_t* out_serialized_rk) {

    *out_serialized_flags = in_rights->flags;
    switch (in_rights->kind) {
    case RK_RAM: {
      out_serialized_rk->raw[0] = RK_RAM;
      CROSS_MEMCPY(out_serialized_rk->raw+1, color_bitmap_get_raw(&(in_rights->color_bm)), color_bitmap_get_byte_count(&(in_rights->color_bm)));
      break;
    }
    case RK_Device: {
     out_serialized_rk->raw[0] = RK_Device;
     CROSS_MEMSET(out_serialized_rk->raw+1,0, TYCHE_COLOR_BYTES);
      break;
    }
    default:
      ERROR("Unknown access right kind %d", in_rights->kind);
      FAIL();
	    break;
    }

    return 0;
}

int enumerate_capa(capa_index_t idx, capa_index_t *next, capability_t *capa) {
  vmcall_frame_t frame;
  capa_index_t token = 0;
  if (capa == NULL) {
    goto fail;
  }
  frame.vmcall = TYCHE_ENUMERATE;
  frame.arg_1 = idx;
  if (tyche_call(&frame) != SUCCESS) {
    goto fail;
  }

  // Next token
  token = frame.value_6;
  if (token == 0) {
    // No more capa
    goto fail;
  }

  // Setup the capability with the values in the registers.
  capa->local_id = frame.value_6 - 1; // value_4 is the **next** token
  capa->capa_type = frame.value_3 & 0xFF;

  // Parse the information encoded from AccessRights.as_bits().
  switch (capa->capa_type) {
  case Region: {
	  access_rights_t rights;
    tyche_data_buf_t recv_buf;
    serialized_resource_kind_t* serialized_rk;
	  //we need to free this
	  tyche_data_handle_t data_handle = frame.value_4;
	  //fetch additional data
	  if (tyche_get_all_data(data_handle, &recv_buf)) {
		  goto fail;
	  }
    if( recv_buf.used_bytes < sizeof(serialized_resource_kind_t)) {
      ERROR("Expected to receive %lu bytes but received only %lu", sizeof(serialized_resource_kind_t),recv_buf.used_bytes);
      goto fail;
    }
    serialized_rk = (serialized_resource_kind_t*)recv_buf.raw;
	  if (deserialize_access_rights_t_from_enum(frame.value_3, serialized_rk,
					   &rights)) {
		  ERROR("failed to deserialize access rights");
		  return FAILURE;
	  }
	  capa->info.region.start = frame.value_1;
	  capa->info.region.end = frame.value_2;
	  capa->info.region.rights = rights;
	  /*{
      LOG("enumerate Region: start 0x%013llx end 0x%013llx ", capa->info.region.start, capa->info.region.end);
		  print_access_rights_t(&rights);
	  }*/
	  break;
  }
  case RegionRevoke: {
	  access_rights_t rights;
    tyche_data_buf_t recv_buf;
    serialized_resource_kind_t* serialized_rk;
	  //we need to free this
	  tyche_data_handle_t data_handle = frame.value_4;
	  //fetch additional data
	  if (tyche_get_all_data(data_handle, &recv_buf)) {
		  goto fail;
	  }
    if( recv_buf.used_bytes < sizeof(serialized_resource_kind_t)) {
      ERROR("Expected to receive %lu bytes but received only %lu", sizeof(serialized_resource_kind_t),recv_buf.used_bytes);
      goto fail;
    }
    serialized_rk = (serialized_resource_kind_t*)recv_buf.raw;
	  if (deserialize_access_rights_t_from_enum(frame.value_3, serialized_rk,
					   &rights)) {
		  ERROR("failed to deserialize access rights");
		  return FAILURE;
	  }

	  capa->info.revoke_region.start = frame.value_1;
	  capa->info.revoke_region.end = frame.value_2;
	  capa->info.revoke_region.rights = rights;
	  break;
  }
  case Management:
    capa->info.management.id = frame.value_1;
    capa->info.management.status = frame.value_2;
    break;
  case Channel:
    capa->info.channel.id = frame.value_1;
    break;
  case Switch:
    capa->info.transition.id = frame.value_1;
    break;
  }

  if (next != NULL) {
    *next = token;
  }
  // Everything went well.
  return SUCCESS;
fail:
  return FAILURE;
}
