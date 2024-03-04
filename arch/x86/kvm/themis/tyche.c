#include "tyche.h"
#include "asm/kvm_host.h"
#include "domains.h"
#include "linux/kvm_host.h"
#include "vmx.h"
#include "../mmu/mmu_internal.h"
#include "common_kvm.h"

// ———————————————————————— Static helper functions ————————————————————————— //

static int translate_reg(int reg, usize *res)
{
	if (res == NULL) {
		goto failure;
	}
	switch (reg) {
	case VCPU_REGS_RAX:
		*res = REG_GP_RAX;
		break;
	case VCPU_REGS_RCX:
		*res = REG_GP_RCX;
		break;
	case VCPU_REGS_RDX:
		*res = REG_GP_RDX;
		break;
	case VCPU_REGS_RBX:
		*res = REG_GP_RBX;
		break;
	case VCPU_REGS_RSP:
		*res = GUEST_RSP;
		break;
	case VCPU_REGS_RBP:
		*res = REG_GP_RBP;
		break;
	case VCPU_REGS_RSI:
		*res = REG_GP_RSI;
		break;
	case VCPU_REGS_RDI:
		*res = REG_GP_RDI;
		break;
	case VCPU_REGS_R8:
		*res = REG_GP_R8;
		break;
	case VCPU_REGS_R9:
		*res = REG_GP_R9;
		break;
	case VCPU_REGS_R10:
		*res = REG_GP_R10;
		break;
	case VCPU_REGS_R11:
		*res = REG_GP_R11;
		break;
	case VCPU_REGS_R12:
		*res = REG_GP_R12;
		break;
	case VCPU_REGS_R13:
		*res = REG_GP_R13;
		break;
	case VCPU_REGS_R14:
		*res = REG_GP_R14;
		break;
	case VCPU_REGS_R15:
		*res = REG_GP_R15;
		break;
	case VCPU_REGS_RIP:
		*res = GUEST_RIP;
		break;
	default:
		goto failure;
	}
	return SUCCESS;
failure:
	return FAILURE;
}

// —————————————————————————————— API to tyche —————————————————————————————— //

int write_domain_config(struct vcpu_vmx *vmx, usize idx, usize value)
{
	struct kvm *kvm = vmx->vcpu.kvm;
	struct kvm_vmx *kvm_vmx = to_kvm_vmx(kvm);

	// Check we have a domain.
	if (kvm_vmx->domain == NULL) {
		ERROR("The tyche domain is null");
		goto failure;
	}

	if (driver_set_domain_core_config(kvm_vmx->domain, vmx->vcpu.vcpu_id,
					  idx, value) != SUCCESS) {
		ERROR("Unable to set the domain core config");
		goto failure;
	}
	return SUCCESS;
failure:
	// TODO error here?
	return FAILURE;
}

usize read_domain_config(struct vcpu_vmx *vmx, usize idx)
{
	usize value = 0;
	struct kvm *kvm = vmx->vcpu.kvm;
	struct kvm_vmx *kvm_vmx = to_kvm_vmx(kvm);

	// Check we have a domain.
	if (kvm_vmx->domain == NULL) {
		ERROR("The tyche domain is null");
		goto failure;
	}
	if (driver_get_domain_core_config(kvm_vmx->domain, vmx->vcpu.vcpu_id,
					  idx, &value) != SUCCESS) {
		ERROR("Unable to get the domain core config.");
		BUG_ON(1);
		goto failure;
	}
	return value;
failure:
	printk(KERN_ERR "Failed to read domain configuration.\n");
	return 0;
}

void clear_bits_domain_config(struct vcpu_vmx *vmx, usize field, usize mask)
{
	write_domain_config(vmx, field, read_domain_config(vmx, field) & ~mask);
}

void set_bits_domain_config(struct vcpu_vmx *vmx, usize field, usize mask)
{
	write_domain_config(vmx, field, read_domain_config(vmx, field) | mask);
}

usize read_domain_register(struct vcpu_vmx *vmx, int reg)
{
	usize tyche_reg = 0, value = 0;
	if (WARN_ON_ONCE((unsigned int)reg >= NR_VCPU_REGS))
		return 0;
	if (translate_reg(reg, &tyche_reg) != SUCCESS) {
		ERROR("Invalid register value %d", reg);
		return 0;
	}
	value = read_domain_config(vmx, tyche_reg);
	vmx->vcpu.arch.regs[reg] = (unsigned long)value;
	return value;
}

int write_domain_register(struct vcpu_vmx *vmx, int reg, usize val)
{
	usize tyche_reg = 0;
	if (WARN_ON_ONCE((unsigned int)reg >= NR_VCPU_REGS))
		return FAILURE;
	if (translate_reg(reg, &tyche_reg) != SUCCESS) {
		ERROR("Invalid register value %d", reg);
		return FAILURE;
	}
	if (write_domain_config(vmx, tyche_reg, val) != SUCCESS) {
		ERROR("Failed to write register.");
		return FAILURE;
	}
	return SUCCESS;
}

void read_all_gp_registers(struct vcpu_vmx *vmx)
{
	int i = 0;
	for (i = VCPU_REGS_RAX; i < NR_VCPU_REGS; i++) {
		read_domain_register(vmx, i);
	}
}

void write_all_gp_registers(struct vcpu_vmx *vmx)
{
	int i = 0;
	for (i = VCPU_REGS_RAX; i < NR_VCPU_REGS; i++) {
		write_domain_register(vmx, i, vmx->vcpu.arch.regs[i]);
	}
}

// ————————————————————————— MMU-related Functions —————————————————————————— //

static int mmu_pages_are_contiguous(struct kvm_memory_slot *slot, bool write)
{
	kvm_pfn_t pfn = __gfn_to_pfn_memslot(slot, slot->base_gfn, false, false,
					     NULL, write, NULL, NULL);
	int i = 0;
	if (pfn == KVM_PFN_NOSLOT || pfn == KVM_PFN_ERR_RO_FAULT) {
		// For the moment ignore these entries.
		pr_err("Wrong type of memory segment %llx\n", pfn);
		BUG_ON(1);
		return 0;
	}
	for (i = 1; i < slot->npages; i++) {
		gfn_t gfn = slot->base_gfn + i;
		kvm_pfn_t npfn = __gfn_to_pfn_memslot(slot, gfn, false, false,
						      NULL, write, NULL, NULL);
		if (npfn != (pfn + i)) {
			return 0;
		}
	}
	return 1;
}

/// Checks if all the pages in the slot are mapped to the same PA.
static int mmu_pages_all_the_same(struct kvm_memory_slot *slot, bool write)
{
	int i = 0;
	kvm_pfn_t pfn = __gfn_to_pfn_memslot(slot, slot->base_gfn, false, false,
					     NULL, write, NULL, NULL);
	if (pfn == KVM_PFN_NOSLOT || pfn == KVM_PFN_ERR_RO_FAULT) {
		// For the moment ignore these entries.
		pr_err("Wrong type of memory segment %llx\n", pfn);
		return 0;
	}
	for (i = 1; i < slot->npages; i++) {
		gfn_t gfn = slot->base_gfn + i;
		kvm_pfn_t npfn = __gfn_to_pfn_memslot(slot, gfn, false, false,
						      NULL, write, NULL, NULL);
		if (npfn != pfn) {
			return 0;
		}
	}
	return 1;
}

static void mmu_pages_dump(struct kvm_memory_slot *slot, bool write)
{
	int i = 0;
	pr_err("[Dumping] base gfn: %llx, npages: %ld\n", slot->base_gfn,
	       slot->npages);
	for (i = 0; i < slot->npages; i++) {
		gfn_t gfn = slot->base_gfn + i;
		kvm_pfn_t pfn = __gfn_to_pfn_memslot(slot, gfn, false, false,
						     NULL, write, NULL, NULL);
		pr_err("[Mapping] gpa: %llx, hpa: %llx, i: %d\n", gfn, pfn, i);
	}
	BUG_ON(1);
}

static int map_segment(driver_domain_t *dom, usize user_addr, usize hfn,
		       usize gfn, usize npages, segment_type_t tpe,
		       memory_access_right_t rights)
{
	if (driver_add_raw_segment(dom, user_addr, hfn << PAGE_SHIFT,
				   npages << PAGE_SHIFT) != SUCCESS) {
		ERROR("Unable to addr raw segment");
		return FAILURE;
	}

	if (driver_mprotect_domain(dom, user_addr, npages << PAGE_SHIFT, rights,
				   tpe, gfn << PAGE_SHIFT) != SUCCESS) {
		ERROR("Unable to mprotect the segment.");
		return FAILURE;
	}

	if (driver_commit_regions(dom) != SUCCESS) {
		ERROR("Unable to mprotect the segment.");
		return FAILURE;
	}

	/*pr_err("[PF mapped] hpa: %llx, gpa: %llx, hva: %llx | npages: %lld | tpe: %d | prot: %d\n",
	       hfn << PAGE_SHIFT, gfn << PAGE_SHIFT, user_addr, npages, tpe,
	       rights);*/

	return SUCCESS;
}

static int parse_kvm_flags(u32 flags, memory_access_right_t *rights,
			   segment_type_t *tpe)
{
	if (rights == NULL || tpe == NULL) {
		ERROR("Rights or tpe is NULL");
		goto failure;
	}
	// Default behaviour when no encoding.
	if ((flags & KVM_FLAGS_ENCODING_PRESENT) == 0) {
		*tpe = SHARED;
		*rights = MEM_READ | MEM_EXEC | MEM_SUPER | MEM_ACTIVE;
		if (!(flags & KVM_MEM_READONLY)) {
			*rights |= MEM_WRITE;
		}
		return SUCCESS;
	}
	// When we have an encoding.
	*tpe = (flags & KVM_FLAGS_SEGMENT_TYPE_MASK) >>
	       KVM_FLAGS_SEGMENT_TYPE_IDX;
	*rights = (flags & KVM_FLAGS_MEM_ACCESS_RIGHTS_MASK) >>
		  KVM_FLAGS_MEM_ACCESS_RIGHTS_IDX;
	// Quick check for consistency between mem readonly and mem access rights.
	if (((flags & KVM_MEM_READONLY) != 0) && ((*rights & MEM_WRITE) != 0)) {
		ERROR("KVM mem readonly but mem access right has write access");
		goto failure;
	}
	return SUCCESS;
failure:
	return FAILURE;
}

static int map_eager(driver_domain_t *dom, struct kvm_memory_slot *slot,
		     bool write)
{
	int i = 0;
	unsigned int seg_count = 0;
	kvm_pfn_t base_pfn = __gfn_to_pfn_memslot(
		slot, slot->base_gfn, false, false, NULL, write, NULL, NULL);
	gfn_t base_gfn = slot->base_gfn;
	usize nb_pages = 1;
	segment_type_t tpe = 0;
	memory_access_right_t rights = 0;

	if (parse_kvm_flags(slot->flags, &rights, &tpe) != SUCCESS) {
		ERROR("Unable to parse the flags...");
		return FAILURE;
	}

	for (i = 1; i <= slot->npages; i++) {
		gfn_t gfn = slot->base_gfn + i;
		usize gnpages = gfn - base_gfn;
		kvm_pfn_t npfn = __gfn_to_pfn_memslot(slot, gfn, false, false,
						      NULL, write, NULL, NULL);
		if (i == slot->npages) {
			goto perform_mapping;
		}
		// Contiguous.
		if (npfn == base_pfn + nb_pages) {
			nb_pages++;
			continue;
		}
		// Case where it is the same page.
		if (npfn == base_pfn) {
			//TODO handle that case.
			if (nb_pages != 1) {
				if (tpe != SHARED) {
					BUG_ON(1);
				}
				goto perform_mapping;
			}
			tpe = SHARED_REPEAT;
			continue;
		}

perform_mapping:
		// We are attacking a new segment, lets map the current one.
		if (map_segment(dom,
				slot->userspace_addr +
					((base_gfn - slot->base_gfn)
					 << PAGE_SHIFT),
				base_pfn, base_gfn, gnpages, tpe,
				rights) != SUCCESS) {
			ERROR("Unable to map segment eagerly");
			return FAILURE;
		}
		seg_count++;
		// Reset all the values.
		nb_pages = 1;
		base_gfn = gfn;
		base_pfn = npfn;
		tpe = SHARED;
	}
	//pr_err("eager mapper used %u segments\n", seg_count);
	return SUCCESS;
}

/// Add a mapping for the domain.
/// Inspired by kvm_tdp_mmu_map.
int tyche_mmu_map(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	struct kvm *kvm = vcpu->kvm;
	int ret = RET_PF_FIXED;
	kvm_pfn_t pfn = 0;
	int is_repeat = 0;
	segment_type_t tpe = 0;
	memory_access_right_t rights = 0;

	//TODO(aghosn) Not sure we need this.
	//kvm_mmu_hugepage_adjust(vcpu, fault);
	//trace_kvm_mmu_spte_requested(fault);

	struct kvm_vmx *vmx = to_kvm_vmx(kvm);
	if (vmx->domain == NULL) {
		ERROR("Embedded domain is null");
		return RET_PF_INVALID;
	}

	rcu_read_lock();

	if (unlikely(!fault->slot)) {
		//pr_err("This is probably mmio: %llx.", fault->addr);
		//tyche_print_all_slots(vcpu);
		rcu_read_unlock();
		return RET_PF_EMULATE;
	}

	//TODO obviously some are not contiguous soooo let's have a look shall we.
	if (mmu_pages_are_contiguous(fault->slot, fault->write)) {
		goto map_segment;
	}
	if (mmu_pages_all_the_same(fault->slot, fault->write)) {
		// Might be mmio as a repeated entry.
		is_repeat = 1;
		//seg_tpe = SHARED_REPEAT;
		goto map_segment;
	}
	//ERROR("Pages are distinct, attempt eager mapper.\n");
	//mmu_pages_dump(fault->slot, fault->write);
	if (map_eager(vmx->domain, fault->slot, fault->write) != SUCCESS) {
		ERROR("Failure in map eager");
	}
	goto unlock;

map_segment:
	if (parse_kvm_flags(fault->slot->flags, &rights, &tpe) != SUCCESS) {
		ERROR("Unable to parse the kvm flags");
		ret = RET_PF_INVALID;
		goto unlock;
	}
	// Handle the repeat case.
	if (is_repeat) {
		switch (tpe) {
		case SHARED:
			tpe = SHARED_REPEAT;
			break;
		case CONFIDENTIAL:
			tpe = CONFIDENTIAL_REPEAT;
			break;
		default:
			ERROR("We detected a repeat but base type is already repeat %d",
			      tpe);
			ret = RET_PF_INVALID;
			goto unlock;
		}
	}
	pfn = __gfn_to_pfn_memslot(fault->slot, fault->slot->base_gfn, false,
				   false, NULL, fault->write, NULL, NULL);
	if (map_segment(vmx->domain, fault->slot->userspace_addr, pfn,
			fault->slot->base_gfn, fault->slot->npages, tpe,
			rights) != SUCCESS) {
		pr_err("Map segment failed.\n");
		ret = RET_PF_INVALID;
		BUG_ON(1);
		goto unlock;
	}
unlock:
	rcu_read_unlock();
	return ret;
}

/// Delete the domain regions. There is a write lock on kvm->mmu_lock.
int tyche_delete_regions(struct kvm *kvm)
{
	struct kvm_vmx *vmx = to_kvm_vmx(kvm);
	if (vmx->domain == NULL) {
		ERROR("Domain is null!");
		return FAILURE;
	}
	return driver_delete_domain_regions(vmx->domain);
}

/// Assume this is locked.
void tyche_print_all_slots(struct kvm_vcpu *vcpu)
{
	struct kvm_memslots *slots = kvm_vcpu_memslots(vcpu);
	struct kvm_memory_slot *slot = NULL;
	int bkt = 0;
	kvm_for_each_memslot(slot, bkt, slots) {
		pr_err("[PAS] gpa: %llx, hva: %lx, npages: %ld | prot: %u | cont: %d, repeat: %d\n",
		       slot->base_gfn << PAGE_SHIFT, slot->userspace_addr,
		       slot->npages, slot->flags,
		       mmu_pages_are_contiguous(slot, false),
		       mmu_pages_all_the_same(slot, false));
	}
}
