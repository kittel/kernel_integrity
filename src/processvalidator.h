#ifndef PROCESSVALIDATOR_H
#define PROCESSVALIDATOR_H

#include <memory>

#include "elffile.h"
#include "elfloader.h"
#include "helpers.h"
#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"
#include "process.h"

/**
 * This is an instance of our Process Manager.
 * It conducts the loading and validation process by instances of
 * TaskManager, ElfProcessLoader and VMIInstance
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
	int validatePage(page_info_t *page);

protected:
private:
	VMIInstance *vmi;
	ElfKernelLoader *kl;
	int32_t pid;

	Process *process;

	ElfProcessLoader *vdsoLoader;

	std::unordered_map<uint64_t, ElfProcessLoader *> addrToLoaderMap;
	std::unordered_map<std::string, RelSym> relSymMap;

	ElfProcessLoader *lastLoader;

	constexpr static uint64_t stdStackTop  = 0x7ffffffdd000;
	constexpr static uint64_t stdStackBot  = 0x7ffffffff000;
	constexpr static uint64_t dynVDSOAddr  = 0x7ffff7ffa000;
	constexpr static uint64_t statVDSOAddr = 0x7ffff7ffd000;
	constexpr static uint16_t stdPageSize  = 0x1000;

	int evalLazy(uint64_t start, uint64_t addr);
	int _validatePage(page_info_t *page);

	void processLoadRel();
	void announceSyms(ElfProcessLoader *lib);

	ElfProcessLoader *findLoaderByAddress(const uint64_t addr) const;
	ElfProcessLoader *findLoaderByName(const std::string &name) const;
	RelSym *findSymbolByName(const std::string &name);

	const std::set<ElfProcessLoader *> getMappedLibs() const;
	SectionInfo *getSegmentForAddress(uint64_t addr);

	void validateCodePage(const VMAInfo *vma) const;
	void validateDataPage(const VMAInfo *vma) const;

	std::unordered_map<std::basic_string<char>, RelSym>* getSymMap();

};

#endif /* PROCESSVALIDATOR_H */
