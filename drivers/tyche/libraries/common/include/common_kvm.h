#ifndef __COMMON_KVM_H__
#define __COMMON_KVM_H__

// —————————— Encoding memory access and segment tpe in kvm flags ——————————— //
/* The first bit in the kvm memory region flags that we can use */
#define KVM_FLAGS_USABLE_IDX (2)
/* Begining of the memory access rights in the KVM flags */
#define KVM_FLAGS_MEM_ACCESS_RIGHTS_IDX (KVM_FLAGS_USABLE_IDX)
/* The number of bits used to encore the memory access in kvm flags */
#define KVM_FLAGS_MEM_ACCESS_RIGHTS_SIZE (6)
/* The mask for access right in kvm flags */
#define KVM_FLAGS_MEM_ACCESS_RIGHTS_MASK \
	(0b111111U << KVM_FLAGS_MEM_ACCESS_RIGHTS_IDX)
/* Begining of the segment type in the KVM flags */
#define KVM_FLAGS_SEGMENT_TYPE_IDX \
	(KVM_FLAGS_MEM_ACCESS_RIGHTS_IDX + KVM_FLAGS_MEM_ACCESS_RIGHTS_SIZE)
/* The number of bits used to encode the segment type in kvm flags */
#define KVM_FLAGS_SEGMENT_TYPE_SIZE (3)
/* The mask for the segment type in kvm flags */
#define KVM_FLAGS_SEGMENT_TYPE_MASK (0b111U << KVM_FLAGS_SEGMENT_TYPE_IDX)
/* Marker to signal encoding is present*/
#define KVM_FLAGS_ENCODING_PRESENT \
	(0b1U << (KVM_FLAGS_SEGMENT_TYPE_IDX + KVM_FLAGS_SEGMENT_TYPE_SIZE))

#endif /*__COMMON_KVM_H__*/
