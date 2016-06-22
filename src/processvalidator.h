#ifndef KERNINT_PROCESSVALIDATOR_H_
#define KERNINT_PROCESSVALIDATOR_H_

#include <memory>

#include "elffile.h"
#include "elfloader.h"
#include "helpers.h"
#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"
#include "process.h"

namespace kernint {

/**
 * This is an instance of our Process Manager.
 * It conducts the loading and validation process by instances of
 * TaskManager, ElfUserspaceLoader and VMIInstance
 *
 * validatePage:    Check the given page for mutations.
 * checkEnv:        Validate the envVars, using the given default values
 * getStackContent: Read the given amount of bytes from the program stack
 * printVMAs:       print the memory mapping for the main binary
 */
class ProcessValidator {
public:
	ProcessValidator(ElfKernelLoader *kl,
	                 Process *process,
	                 VMIInstance *vmi);
	virtual ~ProcessValidator();

	std::vector<uint8_t> getStackContent(size_t readAmount) const;

	int checkEnvironment(const std::map<std::string, std::string> &inputMap);
	int validateProcess();

protected:
	VMIInstance *vmi;
	ElfKernelLoader *kl;
	int32_t pid;

	Process *process;

	// TODO: remove the hardcoding of those
	constexpr static uint64_t stdStackTop  = 0x7ffffffdd000;
	constexpr static uint64_t stdStackBot  = 0x7ffffffff000;
	constexpr static uint16_t stdPageSize  = 0x1000;

	void validateCodePage(const VMAInfo *vma) const;
	void validateDataPage(const VMAInfo *vma) const;
	int validatePage(page_info_t *page);
};

} // namespace kernint

#endif /* PROCESSVALIDATOR_H */
