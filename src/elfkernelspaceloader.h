#ifndef ELFKERNELSPACELOADER_H
#define ELFKERNELSPACELOADER_H

#include "elfloader.h"
#include "kernel.h"
#include "paravirt_patch.h"


class ElfKernelspaceLoader : public ElfLoader, public Kernel {
	friend class KernelValidator;
public:
	ElfKernelspaceLoader(ElfFile *elffile, ParavirtState *pvstate);
	virtual ~ElfKernelspaceLoader() = default;

protected:
	void applyMcount(const SectionInfo &info, ParavirtPatcher *patcher);
	void applyAltinstr(ParavirtPatcher *patcher);
	void applySmpLocks();
	void applyJumpEntries(uint64_t jumpStart,
	                      uint32_t numberOfEntries,
	                      ParavirtPatcher *patcher);

	std::map<uint64_t, int32_t> jumpEntries;
	std::set<uint64_t> jumpDestinations;
	std::set<uint64_t> smpOffsets;

	ParavirtPatcher pvpatcher;
};

#endif
