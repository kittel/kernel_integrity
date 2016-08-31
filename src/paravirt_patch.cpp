#include "paravirt_patch.h"

#include "elffile.h"
#include "elfloader.h"
#include "kernel_headers.h"
#include "paravirt_state.h"


DEF_NATIVE(pv_irq_ops, irq_disable, "cli");
DEF_NATIVE(pv_irq_ops, irq_enable, "sti");
DEF_NATIVE(pv_irq_ops, restore_fl, "pushq %rdi; popfq");
DEF_NATIVE(pv_irq_ops, save_fl, "pushfq; popq %rax");
DEF_NATIVE(pv_cpu_ops, iret, "iretq");
DEF_NATIVE(pv_mmu_ops, read_cr2, "movq %cr2, %rax");
DEF_NATIVE(pv_mmu_ops, read_cr3, "movq %cr3, %rax");
DEF_NATIVE(pv_mmu_ops, write_cr3, "movq %rdi, %cr3");
DEF_NATIVE(pv_mmu_ops, flush_tlb_single, "invlpg (%rdi)");
DEF_NATIVE(pv_cpu_ops, clts, "clts");
DEF_NATIVE(pv_cpu_ops, wbinvd, "wbinvd");

DEF_NATIVE(pv_cpu_ops, irq_enable_sysexit, "swapgs; sti; sysexit");
DEF_NATIVE(pv_cpu_ops, usergs_sysret64, "swapgs; sysretq");
DEF_NATIVE(pv_cpu_ops, usergs_sysret32, "swapgs; sysretl");
DEF_NATIVE(pv_cpu_ops, swapgs, "swapgs");

DEF_NATIVE(, mov32, "mov %edi, %eax");
DEF_NATIVE(, mov64, "mov %rdi, %rax");


namespace kernint {

ParavirtPatcher::ParavirtPatcher(ParavirtState *pvstate)
	:
	pvstate{pvstate} {}

void ParavirtPatcher::add_nops(void *insns, uint8_t len) {
	while (len > 0) {
		unsigned int noplen = len;
		if (noplen > ASM_NOP_MAX) {
			noplen = ASM_NOP_MAX;
		}
		memcpy(insns, (void *)this->pvstate->ideal_nops[noplen], noplen);
		insns = (void *)((char *)insns + noplen);
		len -= noplen;
	}
}

uint8_t ParavirtPatcher::patch_nop(void) {
	return 0;
}

uint8_t ParavirtPatcher::patch_ignore(unsigned len) {
	return len;
}

uint8_t ParavirtPatcher::patch_insns(void *insnbuf,
                                     unsigned len,
                                     const char *start,
                                     const char *end) {
	uint8_t insn_len = end - start;

	if (insn_len > len || start == nullptr) {
		insn_len = len;
	} else {
		memcpy(insnbuf, start, insn_len);
	}

	return insn_len;
}

uint8_t ParavirtPatcher::patch_jmp(void *insnbuf,
                                   uint64_t target,
                                   uint64_t addr,
                                   uint8_t len) {
	if (len < 5) {
		return len;
	}

	uint32_t delta = target - (addr + 5);

	*((uint8_t *)insnbuf) = 0xe9;

	// TODO: warning: cast from 'char *' to 'uint32_t *' (aka 'unsigned int *') increases required alignment from 1 to 4
	*((uint32_t *)((char *)insnbuf + 1)) = delta;

	std::cout << "Patching jump @ " << std::hex << addr << std::dec
	          << std::endl;

	return 5;
}

uint8_t ParavirtPatcher::patch_call(void *insnbuf,
                                    uint64_t target,
                                    uint16_t tgt_clobbers,
                                    uint64_t addr,
                                    uint16_t site_clobbers,
                                    uint8_t len) {
	if (tgt_clobbers & ~site_clobbers) {
		return len;
	}
	if (len < 5) {
		return len;
	}

	uint32_t delta = target - (addr + 5);

	*((uint8_t *)insnbuf) = 0xe8;
	// TODO: warning: cast from 'char *' to 'uint32_t *' (aka 'unsigned int *') increases required alignment from 1 to 4
	*((uint32_t *)((char *)insnbuf + 1)) = delta;

	return 5;
}

uint64_t ParavirtPatcher::get_call_destination(uint32_t type) {
	// These structs contain a function pointers.
	// In memory they are directly after each other.
	// Thus type is an index into the resulting array.

	if (type < this->pvstate->pv_init_ops.size())
		return this->pvstate->pv_init_ops.memberByOffset(type).getRawValue<uint64_t>(false);
	type -= this->pvstate->pv_init_ops.size();

	if (type < this->pvstate->pv_time_ops.size())
		return this->pvstate->pv_time_ops.memberByOffset(type).getRawValue<uint64_t>(false);
	type -= this->pvstate->pv_time_ops.size();

	if (type < this->pvstate->pv_cpu_ops.size())
		return this->pvstate->pv_cpu_ops.memberByOffset(type).getRawValue<uint64_t>(false);
	type -= this->pvstate->pv_cpu_ops.size();

	if (type < this->pvstate->pv_irq_ops.size())
		return this->pvstate->pv_irq_ops.memberByOffset(type).getRawValue<uint64_t>(false);
	type -= this->pvstate->pv_irq_ops.size();

	if (type < this->pvstate->pv_apic_ops.size())
		return this->pvstate->pv_apic_ops.memberByOffset(type).getRawValue<uint64_t>(false);
	type -= this->pvstate->pv_apic_ops.size();

	if (type < this->pvstate->pv_mmu_ops.size())
		return this->pvstate->pv_mmu_ops.memberByOffset(type).getRawValue<uint64_t>(false);
	type -= this->pvstate->pv_mmu_ops.size();

	if (type < this->pvstate->pv_lock_ops.size())
		return this->pvstate->pv_lock_ops.memberByOffset(type).getRawValue<uint64_t>(false);

	return 0;
}

uint8_t ParavirtPatcher::paravirt_patch_default(uint32_t type,
                                                uint16_t clobbers,
                                                void *insnbuf,
                                                uint64_t addr,
                                                uint8_t len) {
	uint8_t ret = 0;
	// Get Memory of paravirt_patch_template + type
	uint64_t opfunc = this->get_call_destination(type);

	if (!opfunc) {
		// opfunc == nullptr
		/* If there's no function, patch it with a ud2a (BUG) */
		// If this is a module this is a bug anyway so this should not happen.
		// ret = this->patch_insns(insnbuf, len, ud2a, ud2a+sizeof(ud2a));
		// If this the kernel this can happen and is only filled with nops
		ret = patch_nop();
	} else if (opfunc == this->pvstate->nopFuncAddress) {
		/* If the operation is a nop, then nop the callsite */
		ret = patch_nop();
	}
	/* identity functions just return their single argument */
	else if (opfunc == this->pvstate->ident32NopFuncAddress) {
		ret = this->patch_insns(insnbuf, len, start__mov32, end__mov32);
	} else if (opfunc == this->pvstate->ident64NopFuncAddress) {
		ret = this->patch_insns(insnbuf, len, start__mov64, end__mov64);
	} else if (type == this->pvstate->pv_cpu_opsOffset +
	                   this->pvstate->pv_cpu_ops.memberOffset("iret") ||
	           type == this->pvstate->pv_cpu_opsOffset +
	                   this->pvstate->pv_cpu_ops.memberOffset("irq_enable_sysexit") ||
	           type == this->pvstate->pv_cpu_opsOffset +
	                   this->pvstate->pv_cpu_ops.memberOffset("usergs_sysret32") ||
	           type == this->pvstate->pv_cpu_opsOffset +
	                   this->pvstate->pv_cpu_ops.memberOffset("usergs_sysret64")) {
		/* If operation requires a jmp, then jmp */
		// std::cout << "Patching jump!" << std::endl;
		ret = this->patch_jmp(insnbuf, opfunc, addr, len);
		// TODO add Jump Target
		// if (!_paravirtJump.contains(opfunc)) {
		//    _paravirtJump.append(opfunc);
		// }
	} else {
		/* Otherwise call the function; assume target could
		   clobber any caller-save reg */
		ret = this->patch_call(insnbuf, opfunc, CLBR_ANY, addr, clobbers, len);
		// TODO add call target
		// if (!_paravirtCall.contains(opfunc)) {
		//    _paravirtCall.append(opfunc);
		// }
	}
	return ret;
}

uint32_t ParavirtPatcher::paravirtNativePatch(uint32_t type,
                                              uint16_t clobbers,
                                              void *ibuf,
                                              unsigned long addr,
                                              unsigned len) {
	uint32_t ret = 0;

#define PATCH_SITE(ops, x) \
	else if (type == this->pvstate->ops##Offset + this->pvstate->ops.memberOffset("" #x)) {   \
		ret = this->patch_insns(ibuf, len, start_##ops##_##x, end_##ops##_##x); \
	}

	if (false) {
	}
	PATCH_SITE(pv_irq_ops, restore_fl)
	PATCH_SITE(pv_irq_ops, save_fl)
	PATCH_SITE(pv_irq_ops, irq_enable)
	PATCH_SITE(pv_irq_ops, irq_disable)
	// PATCH_SITE(pv_cpu_ops, iret)
	PATCH_SITE(pv_cpu_ops, irq_enable_sysexit)
	PATCH_SITE(pv_cpu_ops, usergs_sysret32)
	PATCH_SITE(pv_cpu_ops, usergs_sysret64)
	PATCH_SITE(pv_cpu_ops, swapgs)
	PATCH_SITE(pv_mmu_ops, read_cr2)
	PATCH_SITE(pv_mmu_ops, read_cr3)
	PATCH_SITE(pv_mmu_ops, write_cr3)
	PATCH_SITE(pv_cpu_ops, clts)
	PATCH_SITE(pv_mmu_ops, flush_tlb_single)
	PATCH_SITE(pv_cpu_ops, wbinvd)

	else {
		ret = paravirt_patch_default(type, clobbers, ibuf, addr, len);
	}
#undef PATCH_SITE
	return ret;
}

void ParavirtPatcher::applyParainstr(ElfLoader *target) {
	uint64_t count   = 0;
	SectionInfo info = target->elffile->findSectionWithName(".parainstructions");
	if (!info.index) {
		return;
	}

	// TODO add paravirt entries
	// bool addParavirtEntries = false;
	// if(context.paravirtEntries.size() == 0) addParavirtEntries = true;

	// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'kernint::paravirt_patch_site *' increases required alignment from 1 to 8
	paravirt_patch_site *start = (paravirt_patch_site *)info.index;
	paravirt_patch_site *end = (paravirt_patch_site *)(info.index + info.size);

	char insnbuf[254];

	// noreplace_paravirt is 0 in the kernel
	// http://lxr.free-electrons.com/source/arch/x86/kernel/alternative.c#L45
	// if (noreplace_paravirt) return;

	for (paravirt_patch_site *p = start; p < end; p++) {
		unsigned int used;

		count += 1;

		// BUG_ON(p->len > MAX_PATCH_LEN);
		// parainstructions: impossible length
		assert(p->len < 255);

		// TODO readd when needed
		// if(addParavirtEntries) {
		//    this->paravirtEntries.insert((uint64_t) p->instr);
		//}

		// p->instr points to text segment in memory
		// let it point to the address in the elf binary
		uint8_t *instrInElf = p->instr;
		instrInElf -= (uint64_t) target->textSegment.memindex;
		instrInElf += (uint64_t) target->textSegment.index;

		/* prep the buffer with the original instructions */
		memcpy(insnbuf, instrInElf, p->len);

		// p->instrtype is used as an offset to an array of pointers.
		// Here we only use ist as Offset.
		used = this->paravirtNativePatch(p->instrtype * 8,
		                                 p->clobbers,
		                                 insnbuf,
		                                 (unsigned long)p->instr,
		                                 p->len);

		/* Pad the rest with nops */
		this->add_nops(insnbuf + used, p->len - used);  // add_nops
		memcpy(instrInElf, insnbuf, p->len);      // memcpy
	}
}

} // namespace kernint
