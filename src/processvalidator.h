#ifndef PROCESSVALIDATOR_H
#define PROCESSVALIDATOR_H

#include <memory>

#include "elffile.h"
#include "elfloader.h"

#include "libvmiwrapper/libvmiwrapper.h"
#include "libdwarfparser/libdwarfparser.h"

#include "helpers.h"
#include "taskmanager.h"

/**
 * This is an instance of our Process Manager.
 * It conducts the loading and validation process by instances of
 * TaskManager, ElfProcessLoader and VMIInstance
 *
 * validatePage:    Check the given page for mutations.
 * loadExec:        Load the trusted Executable for validation
 * getProcessEnv:   Load the environment vars of the main process
 * checkEnv:        Validate the envVars, using the given default values
 * getStackContent: Read the given amount of bytes from the program stack
 * getHeapContent:  [dito]                                          heap
 * printVMAs:       print the memory mapping for the main binary
 */
class ProcessValidator{
public:
	ProcessValidator(ElfKernelLoader *kl, const std::string &binaryName,
	                 VMIInstance *vmi, int32_t pid);
	virtual ~ProcessValidator();
	int validatePage(page_info_t *page, int32_t pid);
	void getProcessEnvironment(VMIInstance *vmi, int32_t pid,
	                           uint32_t aslr_off=0);
	int checkEnvironment(const std::map<std::string, std::string> &inputMap);
	std::vector<uint8_t> getStackContent(VMIInstance *vmi, int32_t pid,
	                                     uint32_t aslr_off,
	                                     uint32_t readAmount);
	std::vector<uint8_t> getHeapContent(VMIInstance *vmi,
	                                    int32_t pid,
	                                    uint32_t readAmount);
	void printVMAs();
protected:

private:
	VMIInstance* vmi;
	ElfKernelLoader* kl;
	int32_t pid;

	ElfProcessLoader *execLoader;
	std::string binaryName;

	ElfProcessLoader* vdsoLoader;
	std::map<std::string, std::string> envMap;
	TaskManager tm;

	std::vector<VMAInfo> mappedVMAs;
	std::map<VMAInfo*, ElfProcessLoader*> vmaToLoaderMap;
	// contains only start-addresses
	std::unordered_map<uint64_t, ElfProcessLoader*> addrToLoaderMap;
	std::unordered_map<std::string, RelSym*> relSymMap;

	ElfProcessLoader *lastLoader;

	const uint64_t stdStackTop = 0x7ffffffdd000;
	const uint64_t stdStackBot = 0x7ffffffff000;
	const uint64_t dynVDSOAddr = 0x7ffff7ffa000;
	const uint64_t statVDSOAddr = 0x7ffff7ffd000;
	const uint16_t stdPageSize = 0x1000;

	int evalLazy(uint64_t start, uint64_t addr);
	int _validatePage(page_info_t *page, int32_t pid);

	ElfProcessLoader *loadExec(const std::string &pathName);

	void updateMemindexes();
	void processLoadRel();
	void announceSyms(ElfProcessLoader* lib);

	ElfProcessLoader* getLoaderForAddress(uint64_t addr,
	                                      ElfProcessLoader* backup);
	ElfProcessLoader *findLoaderByName(const std::string &name) const;

	std::set<ElfProcessLoader *> getMappedLibs();
	SectionInfo* getSegmentForAddress(uint64_t addr);

	void validateCodePage(VMAInfo* vma);
	void validateDataPage(VMAInfo* vma);
};

#endif /* PROCESSVALIDATOR_H */
