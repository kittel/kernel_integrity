#ifndef KERNINT_PROCESS_H_
#define KERNINT_PROCESS_H_

#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "elffile.h"
#include "libdwarfparser/symbolmanager.h"


class Instance;

namespace kernint {

class Kernel;
class ElfLoader;
class ElfUserspaceLoader;
class VMAInfo;


/**
 * Tracks a userland process.
 * Can reproduce the loading actions done in a VM
 * on a working copy (the image) to verify correctness.
 */
class Process {
public:
	Process(const std::string &binaryName, Kernel *kernel, pid_t pid);

	Process(Process &&) = delete;
	Process(const Process &) = delete;
	Process &operator =(Process &&) = delete;
	Process &operator =(const Process &) = delete;

	virtual ~Process();

	ElfUserspaceLoader *getExecLoader();

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

	ElfUserspaceLoader *findLoaderByAddress(const uint64_t addr) const;
	ElfUserspaceLoader *findLoaderByFileName(const std::string &name) const;
	const ElfUserspaceLoader *getExecLoader() const;

	SectionInfo *getSegmentForAddress(uint64_t addr);

	/**
	 * Perform all load time relocations,
	 * for the executable and all libraries.
	 */
	void processLoadRel();

	/**
	 * Register symbols from a loader.
	 * Find the matching mapping
	 * from the mapping list and add its virtual base address
	 * to the symbol addresses.
	 */
	void registerSyms(ElfUserspaceLoader *loader,
	                  const std::vector<const VMAInfo *> &mappings);

protected:
	Kernel *kernel;

	Instance *task_struct;
	pid_t pid;

	ElfUserspaceLoader *execLoader;
	ElfUserspaceLoader *vdsoLoader;
	std::string binaryName;

	std::vector<VMAInfo> mappedVMAs;

	std::vector<std::string> getArgv();
	std::unordered_map<std::string, std::string> getEnv();

	typedef std::unordered_map<std::string, std::vector<uint8_t>> DataSegmentMap;
	DataSegmentMap dataSegmentMap;
	typedef std::unordered_map<std::string, SectionInfo> DataSectionInfoMap;
	DataSectionInfoMap dataSectionInfoMap;
	typedef std::unordered_map<std::string, SegmentInfo> DataSegmentInfoMap;
	DataSegmentInfoMap dataSegmentInfoMap;
};

} // namespace kernint

#endif
