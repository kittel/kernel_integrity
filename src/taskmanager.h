#ifndef KERNINT_TASKMANAGER_H_
#define KERNINT_TASKMANAGER_H_

#include <cstdlib>
#include <iostream>
#include <unordered_map>

#include "libdwarfparser/instance.h"
#include "libdwarfparser/libdwarfparser.h"
#include "libdwarfparser/variable.h"
#include "libvmiwrapper/libvmiwrapper.h"

#include "process.h"
#include "helpers.h"

#define PAGESIZE 0x1000

namespace kernint {

/**
 * This class contains the extracted information of an address space's VMAs
 *
 * @start : start address of the VMA in the virtual address space of the task
 * @end   : end     "
 * @ino   : inode nr of the backing file. 0, if backed by no file
 * @name  : filename, empty if backed by no file
 * @off   : offset of the VMA from file beginning, if existant
 *          IMPORTANT: the offset is given in PAGE_SIZE units (0x1000)
 */
class VMAInfo {
public:
	uint64_t start;
	uint64_t end;
	uint64_t ino;
	uint64_t off;
	uint64_t flags;
	std::string name;

	VMAInfo(uint64_t start,
	        uint64_t end,
	        uint64_t ino,
	        uint64_t off,
	        uint64_t flags,
	        std::string name);
	~VMAInfo();

	void print() const;

	enum {
		VM_READ     = 0x00000001,
		VM_WRITE    = 0x00000002,
		VM_EXEC     = 0x00000004,
		VM_SHARED   = 0x00000008,
		VM_MAYREAD  = 0x00000010,
		VM_MAYWRITE = 0x00000020,
		VM_MAYEXEC  = 0x00000040,
		VM_MAYSHARE = 0x00000080
	};
};

/**
 * This class provides the interface for the kernel data structures
 *    - task_struct
 *    - mm_struct
 *    - vm_area_struct
 * in the VMIInstance.
 *
 * The most important function is getVMAInfo(pid_t), which provides the caller
 * with all necessary information about current memory mapping of the task.
 */
class TaskManager {

public:
	TaskManager(Kernel *kernel);
	~TaskManager();

	void init();

	Instance getTaskForPID(pid_t pid) const;
	std::vector<VMAInfo> getVMAInfo(pid_t pid);

	/**
	 * Read the name of the executable for a given PID
	 */

	std::string getTaskExeName(pid_t pid) const;

	/**
	 * Fetches the arguments for the task (aka argv)
	 */
	std::vector<std::string> getArgForTask(pid_t pid) const;

	/**
	 * Returns the environment variable mapping for a pid.
	 */
	std::unordered_map<std::string, std::string> getEnvForTask(pid_t pid) const;

	/** Set the path where libraries are loaded from. */
	void setLibraryDir(const std::string &dirName);

	/** get the vdso (currently hardcoded to vdso_image_64) */
	ElfLoader *loadVDSO();

	/** load a shared library by name */
	ElfLoader *loadLibrary(const std::string &libraryName);

	/** determine the absolute path of a library */
	std::string findLibraryFile(const std::string &libName);

	/** try to return an already loaded library by name */
	ElfUserspaceLoader *findLibByName(const std::string &name);

	/** create an executable from a process */
	ElfUserspaceLoader *loadExec(Process *process);

protected:
	Instance initTask;

	/**
	 * Memory holder of all processes observed.
	 */
	std::unordered_map<pid_t, Process> processes;

	std::unordered_map<std::string, Process *> processMap;


	using LibraryMap = std::unordered_map<std::string, ElfLoader *>;

	/**
	 * Maps library name to elfloader, these are the known raw
	 * library images.
	 */
	LibraryMap libraryMap;

	std::vector<std::string> libDirName;

	Kernel *kernel;

private:
	Instance getMMStruct(Instance *task) const;
	Instance nextTask(Instance &task) const;
	std::string getPathFromDentry(Instance& dentry) const;
};

} // namespace kernint

#endif
