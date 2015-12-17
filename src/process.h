#ifndef PROCESS_H_
#define PROCESS_H_

#include "elffile.h"
#include "libdwarfparser/symbolmanager.h"

class Instance;
class Kernel;
class ElfLoader;
class ElfProcessLoader;

class Process {
public:
	Process(const std::string &binaryName, Kernel *kernel);
	virtual ~Process() = default;

	ElfProcessLoader *getExecLoader();

	const std::string &getName();

	std::unordered_map<std::string, RelSym> *getSymMap();
	RelSym *findSymbolByName(const std::string &name);

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
	
	ElfLoader *loadLibrary(const std::string &libraryName);
	SymbolManager symbols;

	std::vector<uint8_t> *getDataSegmentForLib(const std::string &name);
	SectionInfo *getSectionInfoForLib(const std::string &name);
	SegmentInfo *getSegmentInfoForLib(const std::string &name);
	
	SectionInfo *setSectionInfoForLib(const std::string &name);
	SegmentInfo *setSegmentInfoForLib(const std::string &name);

protected:
	Kernel *kernel;
	Instance *task_struct;
	pid_t pid;

	ElfProcessLoader *execLoader;
	std::string binaryName;

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
