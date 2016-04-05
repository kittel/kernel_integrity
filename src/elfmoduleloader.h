#ifndef ELFMODULELOADER_H
#define ELFMODULELOADER_H

#include "elfkernelspaceloader.h"
#include "paravirt_patch.h"

class ElfModuleLoader : public ElfKernelspaceLoader {
public:
	ElfModuleLoader(ElfFile *elffile,
	                const std::string &name="",
	                Kernel *kernel=nullptr);
	virtual ~ElfModuleLoader();

	const std::string &getName() const override;
	Kernel *getKernel() override;


protected:
	void updateSectionInfoMemAddress(SectionInfo &info);
	uint64_t findMemAddressOfSegment(SectionInfo &info);

	virtual void initText();
	virtual void initData();

	void loadDependencies();

	bool isDataAddress(uint64_t addr);

	std::string modName;
	Kernel *kernel;
};

#include "elfmoduleloader64.h"

#endif  /* ELFMODULELOADER_H */
