#ifndef KERNINT_KERNELVALIDATOR_H_
#define KERNINT_KERNELVALIDATOR_H_

#include <cstdint>
#include <map>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"


namespace kernint {

class ElfKernelLoader;
class ElfKernelspaceLoader;

class KernelValidator {
public:
	KernelValidator(ElfKernelLoader *kernelLoader,
	                const std::string &targetsFile="");
	virtual ~KernelValidator();

	uint64_t validatePages();
	void validatePage(page_info_t *page);
	void setOptions(bool lm=false, bool cv=true, bool pe=true);
	ElfKernelLoader *getKernelLoader(){ return this->kernelLoader; }

	static ElfKernelLoader *loadKernel(const std::string &dirName);

private:
	struct {
		bool loopMode;
		bool codeValidation;
		bool pointerExamination;
	} options;

	ElfKernelLoader *kernelLoader;
	std::map<uint64_t, uint64_t> stackAddresses;
	std::multimap<uint64_t, uint64_t> callTargets;

	uint64_t globalCodePtrs;

	void validateCodePage(page_info_t *page, ElfKernelspaceLoader *elf);
	bool isValidJmpLabel(uint8_t *pageInMem,
	                     uint64_t codeAddress,
	                     int32_t i,
	                     ElfKernelspaceLoader *elf);

	void validateDataPage(page_info_t *page, ElfKernelspaceLoader *elf);
	void validateStackPage(uint8_t *memory,
	                       uint64_t stackBottom,
	                       uint64_t stackEnd);

	void updateStackAddresses();

	uint64_t findCodePtrs(page_info_t *page, uint8_t *pageInMem);
	uint64_t isReturnAddress(uint8_t *ptr, uint32_t offset, uint64_t index);
};

} // namespace kernint

#endif /* KERNELVALIDATOR_H */
