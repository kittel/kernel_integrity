#include "elfkernelspaceloader.h"

#include <cassert>
#include <cstring>
#include <fstream>
#include <iostream>
#include <typeinfo>

#include "elfkernelloader.h"
#include "elfmoduleloader.h"
#include "exceptions.h"
#include "helpers.h"
#include "kernel_headers.h"
#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"


namespace kernint {

ElfKernelspaceLoader::ElfKernelspaceLoader(ElfFile *elffile, ParavirtState *pvstate)
	:
	ElfLoader(elffile),
	pvpatcher{pvstate} {}


void ElfKernelspaceLoader::applyMcount(const SectionInfo &info,
                                       ParavirtPatcher *patcher) {
	// See ftrace_init_module in kernel/trace/ftrace.c

	uint64_t *mcountStart = reinterpret_cast<uint64_t *>(info.index);
	uint64_t *mcountStop  = reinterpret_cast<uint64_t *>(info.index + info.size);

	for (uint64_t *i = mcountStart; i < mcountStop; i++) {
		patcher->add_nops(
			(void *)(this->textSegmentContent.data() +
			         ((uint64_t)(*i) -
			          (uint64_t) this->textSegment.memindex)),
			5);
	}
}

void ElfKernelspaceLoader::applyAltinstr(ParavirtPatcher *patcher) {
	uint64_t count     = 0;
	uint64_t count_all = 0;
	uint8_t *instr;
	uint8_t *replacement;
	unsigned char insnbuf[255 - 1];

	SectionInfo altinst = this->elffile->findSectionWithName(".altinstructions");
	if (!altinst.index) {
		return;
	}

	SectionInfo altinstreplace;
	altinstreplace = this->elffile->findSectionWithName(".altinstr_replacement");

	// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'struct alt_instr *' increases required alignment from 1 to 4
	struct alt_instr *start = (struct alt_instr *)altinst.index;
	struct alt_instr *end   = (struct alt_instr *)(altinst.index + altinst.size);

	this->updateSectionInfoMemAddress(altinstreplace);

	// Find boot_cpu_data in kernel
	Variable *boot_cpu_data_var = this->elffile->symbols->findVariableByName("boot_cpu_data");
	assert(boot_cpu_data_var);

	Instance boot_cpu_data  = boot_cpu_data_var->getInstance();
	Instance x86_capability = boot_cpu_data.memberByName("x86_capability");

	uint32_t cpuCaps[10] = {0};
	for (uint8_t i = 0; i < 10; i++) {
		cpuCaps[i] = x86_capability.arrayElem(i).getRawValue<uint32_t>(false);
	}

	for (struct alt_instr *a = start; a < end; a++) {
		count_all += 1;

		if (!((cpuCaps[a->cpuid / 32] >> (a->cpuid % 32)) & 0x1)) {
			continue;
		}

		count += 1;

		instr       = ((uint8_t *)&a->instr_offset) + a->instr_offset;
		replacement = ((uint8_t *)&a->repl_offset) + a->repl_offset;

		// If this is the a kernel then adjust the address of the
		// instruction to replace
		if (dynamic_cast<ElfKernelLoader *>(this)) {
			instr -= (reinterpret_cast<uint64_t>(this->textSegment.index) - reinterpret_cast<uint64_t>(this->elffile->getFileContent()));
		}

		memcpy(insnbuf, replacement, a->replacementlen);

		// 0xe8 is a relative jump; fix the offset.
		if (insnbuf[0] == 0xe8 && a->replacementlen == 5) {
			// If replacement is in the altinstr_replace section fix the offset.
			if (replacement >= (uint8_t *)altinstreplace.index &&
			    replacement < (uint8_t *)altinstreplace.index + altinstreplace.size) {
				// TODO: warning: cast from 'unsigned char *' to 'int32_t *' (aka 'int *') increases required alignment from 1 to 4
				*(int32_t *)(insnbuf + 1) -= (altinstreplace.index - this->textSegment.index) - (altinstreplace.memindex - this->textSegment.memindex);
			}
			*(int32_t *)(insnbuf + 1) += replacement - instr;
		}

		// add_nops
		patcher->add_nops(insnbuf + a->replacementlen, a->instrlen - a->replacementlen);
		if (((uint64_t)instr) % 0x1000 == 0x70) {
			std::cout << "Found in " << this->getName() << std::endl;
		}
		memcpy(instr, insnbuf, a->instrlen);
	}
}


void ElfKernelspaceLoader::applySmpLocks() {
	SectionInfo info = this->elffile->findSectionWithName(".smp_locks");
	if (!info.index)
		return;
	this->updateSectionInfoMemAddress(info);

	unsigned char lock = 0;
	uint64_t count     = 0;

	// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'int32_t *' (aka 'int *') increases required alignment from 1 to 4
	int32_t *smpLocksStart = (int32_t *)info.index;
	int32_t *smpLocksStop  = (int32_t *)(info.index + info.size);

	// Find boot_cpu_data in kernel
	Variable *boot_cpu_data_var = this->elffile->symbols->findVariableByName("boot_cpu_data");
	assert(boot_cpu_data_var);

	Instance boot_cpu_data  = boot_cpu_data_var->getInstance();
	Instance x86_capability = boot_cpu_data.memberByName("x86_capability");
	if (!((x86_capability.arrayElem(X86_FEATURE_UP / 32).getRawValue<uint32_t>(false) >> (X86_FEATURE_UP % 32)) & 0x1)) {
		/* turn lock prefix into DS segment override prefix */
		lock = 0x3e;
	} else {
		/* turn DS segment override prefix into lock prefix */
		lock = 0xf0;
	}

	bool addSmpEntries = false;

	if (this->smpOffsets.size() == 0)
		addSmpEntries = true;

	for (int32_t *poff = smpLocksStart; poff < smpLocksStop; poff++) {
		count += 1;
		uint8_t *ptr = (uint8_t *)poff + *poff;

		// Adapt offset in ELF
		int32_t offset = (info.index - this->textSegment.index) -
		                 (info.memindex - this->textSegment.memindex);
		ptr -= offset;

		if (this->textSegment.containsElfAddress((uint64_t)ptr)) {
			*ptr = lock;

			if (addSmpEntries) {
				this->smpOffsets.insert((uint64_t)ptr -
				                        (uint64_t)this->textSegment.index);
			}
		}
	}
}


void ElfKernelspaceLoader::applyJumpEntries(uint64_t jumpStart,
                                            uint32_t numberOfEntries,
                                            ParavirtPatcher *patcher) {
	uint64_t count = 0;
	// Apply the jump tables after the segments are adjacent
	// jump_label_apply_nops() =>
	// http://lxr.free-electrons.com/source/arch/x86/kernel/module.c#L205
	// the entry type is 0 for disable and 1 for enable

	bool addJumpEntries = false;
	if (this->jumpEntries.size() == 0)
		addJumpEntries = true;

	// TODO: warning: cast from 'unsigned char *' to 'struct jump_entry *' increases required alignment from 1 to 8
	struct jump_entry *startEntry = (struct jump_entry *)this->jumpTable.data();
	struct jump_entry *endEntry = (struct jump_entry *)(this->jumpTable.data() + this->jumpTable.size());

	BaseType *jump_entry_bt = this->elffile->symbols->findBaseTypeByName("jump_entry");
	BaseType *static_key_bt = this->elffile->symbols->findBaseTypeByName("static_key");
	for (uint32_t i = 0; i < numberOfEntries; i++) {
		Instance jumpEntry = Instance(nullptr, 0);
		if (dynamic_cast<ElfKernelLoader *>(this)) {
			uint64_t instanceAddress = 0;

			// This is not a real array in memory but has more readability
			instanceAddress = (uint64_t) & ((struct jump_entry *)jumpStart)[i];

			jumpEntry = jump_entry_bt->getInstance(instanceAddress);

			// Do not apply jump entries to .init.text
			uint64_t codeAddress = jumpEntry.memberByName("code").getValue<uint64_t>();
			if (codeAddress > (uint64_t) this->textSegment.memindex + this->textSegment.size) {
				continue;
			}
		} else if (dynamic_cast<ElfModuleLoader *>(this)) {
			assert(false);
			//TODO!!!!
			//jumpEntry = context.currentModule.member("jump_entries").arrayElem(i);
		}

		uint64_t keyAddress = jumpEntry.memberByName("key").getValue<uint64_t>();

		Instance key     = static_key_bt->getInstance(keyAddress);
		uint64_t enabled = key.memberByName("enabled")
		                      .memberByName("counter")
		                      .getValue<int64_t>();

		uint64_t codeEntry = jumpEntry.memberByName("code").getValue<uint64_t>();
		for (struct jump_entry *entry = startEntry; entry < endEntry; entry++) {
			// Check if current elf entry is current kernel entry
			if (codeEntry == entry->code) {
				count += 1;
				uint64_t patchOffset = entry->code - (uint64_t) this->textSegment.memindex;

				char *patchAddress = (char *)(patchOffset + (uint64_t) this->textSegmentContent.data());

				int32_t destination = entry->target - (entry->code + 5);
				if (addJumpEntries) {
					this->jumpEntries.insert(
						std::pair<uint64_t, int32_t>(entry->code, destination));
					this->jumpDestinations.insert(entry->target);
				}

				if (enabled) {
					*patchAddress = (char)0xe9;
					// TODO: warning: cast from 'char *' to 'int32_t *' (aka 'int *') increases required alignment from 1 to 4
					*((int32_t *)(patchAddress + 1)) = destination;
				} else {
					patcher->add_nops(patchAddress, 5);
				}
			}
		}
	}
}

} // namespace kernint
