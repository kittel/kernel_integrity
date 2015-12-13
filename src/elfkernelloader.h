#ifndef ELFKERNELOADER_H
#define ELFKERNELOADER_H

#include "elfloader.h"
#include "kernel.h"
#include "paravirt_patch.h"


class ElfKernelLoader : public ElfLoader, public Kernel {
	friend class KernelValidator;

public:
	ElfKernelLoader(ElfFile *elffile);
	virtual ~ElfKernelLoader();

	ElfLoader *getModuleForAddress(uint64_t address);
	ElfLoader *getModuleForCodeAddress(uint64_t address);

	const std::string &getName() const override;
	Kernel *getKernel() override;

protected:
	std::string name;
	ParavirtPatcher pvpatcher;

	SectionInfo vvarSegment;
	SectionInfo dataNosaveSegment;

	uint64_t fentryAddress;
	uint64_t genericUnrolledAddress;

	uint64_t idt_tableAddress;
	uint64_t nmi_idt_tableAddress;
	uint64_t sinittextAddress;
	uint64_t irq_entries_startAddress;

	int apply_relocate();

	void updateSectionInfoMemAddress(SectionInfo &info);

	virtual void initText();
	virtual void initData();

	bool isDataAddress(uint64_t addr);
};

#include "elfkernelloader64.h"

#endif  /* ELFKERNELOADER_H */
