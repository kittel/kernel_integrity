#ifndef PROCESSVALIDATOR_H
#define PROCESSVALIDATOR_H

#include "elffile.h"
#include "elfloader.h"

#include "libvmiwrapper/libvmiwrapper.h"
#include "libdwarfparser/libdwarfparser.h"

#include "helpers.h"
#include "taskmanager.h"

/* This is an instance of our Process Manager.
 * It conducts the loading and validation process by instances of
 * TaskManager, ElfProcessLoader and VMIInstance
 *
 * validatePage:    Check the given page for mutations.
 * loadExec:        Load the trusted Executable for validation
 * getProcessEnv:   Load the environment vars of the main process
 * checkEnv:        Validate the envVars, using the given default values
 * getStackContent: Read the given amount of bytes from the program stack
 * getHeapContent:  [dito]                                          heap
 * printProcImage:  print the currently loaded process image
 * printVMAs:       print the memory mapping for the main binary
 * printSuppLibs:   print the loaded libraries
 */
class ProcessValidator{
	public:
		ProcessValidator(std::string dirName, VMIInstance* vmi, int32_t pid,
                         std::string vdsoPath, std::string libPath,
						 std::string kernPath);
		virtual ~ProcessValidator();
		int validatePage(page_info_t *page, int32_t pid);
		void getProcessEnvironment(VMIInstance *vmi, int32_t pid,
								uint32_t aslr_off=0);
		int checkEnvironment(std::map<std::string, std::string> inputMap);
		std::vector<uint8_t> getStackContent(VMIInstance *vmi, int32_t pid,
												uint32_t aslr_off,
												uint32_t readAmount);
		std::vector<uint8_t> getHeapContent(VMIInstance *vmi,
											int32_t pid,
											uint32_t readAmount);
		void printProcessImage();
		void printVMAs();
		void printSuppliedLibraries();
	protected:

	private:
		VMIInstance* vmi;
		int32_t pid;
		ElfProcessLoader64* execLoader;
		ElfProcessLoader64* vdsoLoader;
		std::map<std::string, std::string> envMap;
		std::vector<ElfProcessLoader64*> suppliedLibraries;
		TaskManager tm;

		std::vector<VMAInfo*> mappedVMAs;
		std::map<VMAInfo*, ElfProcessLoader64*> vmaToLoaderMap;
		// contains only start-addresses
		std::unordered_map<uint64_t, ElfProcessLoader64*> addrToLoaderMap;
		std::unordered_map<std::string, RelSym*> relSymMap;

		ElfProcessLoader64 *lastLoader;

		const uint64_t stdStackTop = 0x7ffffffdd000;
		const uint64_t stdStackBot = 0x7ffffffff000;
		const uint64_t dynVDSOAddr = 0x7ffff7ffa000;
		const uint64_t statVDSOAddr = 0x7ffff7ffd000;
		const uint16_t stdPageSize = 0x1000;
		std::string vdsoPath;

		int evalLazy(uint64_t start, uint64_t addr);
		int _validatePage(page_info_t *page, int32_t pid);
		int loadExec(std::string pathName);
		void initSuppliedLibraries(const char *path);
		void initVDSO(const char *path);
		void updateMemindexes();
		void buildMaps(std::vector<VMAInfo*> vec);
		void processLoadRel();
		void announceSyms(ElfProcessLoader64* lib);

		ElfProcessLoader64* getLibByName(std::string name);
		ElfProcessLoader64* getLoaderForAddress(uint64_t addr,
												ElfProcessLoader64* backup);
		std::vector<ElfProcessLoader64*> getMappedLibs();
		SegmentInfo* getSegmentForAddress(uint64_t addr);
};

#endif /* PROCESSVALIDATOR_H */
