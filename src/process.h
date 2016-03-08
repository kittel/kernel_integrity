#ifndef PROCESS_H_
#define PROCESS_H_

#include "elffile.h"
#include "libdwarfparser/symbolmanager.h"

class Instance;
class Kernel;
class ElfLoader;
class ElfProcessLoader;
class VMAInfo;

class Process {
public:
	Process(const std::string &binaryName, Kernel *kernel, pid_t pid);
	virtual ~Process() = default;

	ElfProcessLoader *getExecLoader();

	const std::string &getName() const;

	/**
	 * Check if the given pid is still scheduled in the kernel.
	 * + checks if libs the same and position
	 * + check if name is the same
	 * -> check via processes library map.
	 */
	bool isRunning() const;

	/**
	 * Return the pointer to the associated kernel
	 */
	Kernel *getKernel() const;
	pid_t getPID() const;

	ElfLoader *loadLibrary(const std::string &libraryName);
	SymbolManager symbols;

	std::vector<uint8_t> *getDataSegmentForLib(const std::string &name);
	SectionInfo *getSectionInfoForLib(const std::string &name);
	SegmentInfo *getSegmentInfoForLib(const std::string &name);

	SectionInfo *setSectionInfoForLib(const std::string &name);
	SegmentInfo *setSegmentInfoForLib(const std::string &name);

	const std::vector<VMAInfo> &getMappedVMAs() const;
	void printVMAs() const;
	const VMAInfo *findVMAByName(const std::string &name) const;
	const VMAInfo *findVMAByAddress(const uint64_t address) const;

protected:
	Kernel *kernel;

	Instance *task_struct;
	pid_t pid;

	ElfProcessLoader *execLoader;
	std::string binaryName;

	std::vector<VMAInfo> mappedVMAs;

	std::vector<std::string> getArgv();
	std::unordered_map<std::string, std::string> getEnv();

	ElfProcessLoader *findLibByName(const std::string &name);
	typedef std::unordered_map<std::string, ElfLoader*> LibraryMap;
	LibraryMap libraryMap;

	typedef std::unordered_map<std::string, std::vector<uint8_t>> DataSegmentMap;
	DataSegmentMap dataSegmentMap;
	typedef std::unordered_map<std::string, SectionInfo> DataSectionInfoMap;
	DataSectionInfoMap dataSectionInfoMap;
	typedef std::unordered_map<std::string, SegmentInfo> DataSegmentInfoMap;
	DataSegmentInfoMap dataSegmentInfoMap;
};

#endif
