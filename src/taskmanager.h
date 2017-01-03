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
 */
class VMAInfo {
public:
	uint64_t start;   // !< start address of the VMA in the virtual address space of the task
	uint64_t end;     // !< end address, like above
	uint64_t ino;     // !< inode nr of the backing file. 0, if backed by no file
	uint64_t off;     // !< offset of the VMA from file beginning, if existant
	                  // IMPORTANT: the offset is given in PAGE_SIZE units (0x1000)
	uint64_t flags;
	std::string name; // !< filename, empty if backed by no file

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

	/**
	 * Get the task struct for some pid.
	 */
	Instance getTaskForPID(pid_t pid) const;

	/**
	 * Get the list of tasks.
	 */
	std::vector<std::pair<pid_t,Instance>> getTasks() const;

	/**
	 * Get all the mappings for a pid.
	 */
	std::vector<VMAInfo> getVMAInfo(pid_t pid);

	/**
	 * @param pid Task to check
	 * @returns Returns true, if a corresponding task still exists
	 *
	 * Check if a task has terminated
	 */
	bool terminated(pid_t pid) const;

	/**
	 * @param pid Task to check
	 * @returns Returns true, if the task is a kernel task
	 *
	 * Check if given task is a kernel task
	 */
	bool isKernelTask(pid_t pid) const;

	/**
	 * @param task Instance of task_struct of task
	 * @returns Returns true, if the task is a kernel task
	 *
	 * Check if given task is a kernel task
	 */
	bool isKernelTask(const Instance &task) const;

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

	/** Set the path where the root of the vm begins */
	void setRootDir(const std::string &dirName);

	/** get the vdso (currently hardcoded to vdso_image_64) */
	ElfUserspaceLoader *loadVDSO(Process *process);

	/** load a shared library by name */
	ElfLoader *loadLibrary(const std::string &libraryName,
	                       Process *process);

	/** determine the absolute path of a library */
	std::string findLibraryFile(const std::string &libName);

	/** try to return an already loaded library by name */
	ElfUserspaceLoader *findLibByName(const std::string &name);

	/** create an executable from a process */
	ElfUserspaceLoader *loadExec(Process *process);

	/**
	 * Remove all the libraries from the list,
	 * this is used to analyze another process after one was
	 * analyzed already.
	 */
	void cleanupLibraries();

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


	/**
	 * search paths for userspace libraries to load
	 * this is the LD_LIBRARY_PATH
	 */
	std::vector<std::string> ldLibraryPaths;

	/**
	 * root folder of the vm on the kernint-running machine.
	 */
	std::string rootPath;

	std::vector<uint8_t> vdsoData;
	uint64_t vdsoVvarPageOffset;

	Kernel *kernel;

private:
	Instance nextTask(Instance &task) const;
	std::string getPathFromDentry(Instance& dentry) const;
};

} // namespace kernint

#endif
