#ifndef KERNINT_ELFKERNELOADER_H_
#define KERNINT_ELFKERNELOADER_H_

#include "elfkernelspaceloader.h"
#include "paravirt_patch.h"


namespace kernint {

class ElfKernelLoader : public ElfKernelspaceLoader, public Kernel {
	friend class KernelValidator;

public:
	ElfKernelLoader(ElfFile *elffile);
	virtual ~ElfKernelLoader();

	ElfKernelspaceLoader *getModuleForAddress(uint64_t address);
	ElfKernelspaceLoader *getModuleForCodeAddress(uint64_t address);

	const std::string &getName() const override;
	Kernel *getKernel() override;

	bool isDataAddress(uint64_t addr) override;
protected:
	std::string name;

	SectionInfo vvarSegment;
	SectionInfo dataNosaveSegment;

	uint64_t fentryAddress;
	uint64_t genericUnrolledAddress;

	uint64_t idt_tableAddress;
	uint64_t nmi_idt_tableAddress;
	uint64_t sinittextAddress;
	uint64_t irq_entries_startAddress;

	int apply_relocate();

	void updateSectionInfoMemAddress(SectionInfo &info) override;

	void initText() override;
	void initData() override;

};

} // namespace kernint

// TODO: REMOVE!!!
#include "elfkernelloader64.h"

#endif
