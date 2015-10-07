#ifndef TASKMANAGER_H
#define TASKMANAGER_H

#include <map>
#include <iostream>
#include <stdlib.h>
#include "helpers.h"
#include "libdwarfparser/instance.h"
#include "libdwarfparser/variable.h"
#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

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
class VMAInfo{
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

	void print();

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
	TaskManager();
	~TaskManager();

	Instance getTaskForPID(pid_t pid);
	std::vector<VMAInfo> getVMAInfo(pid_t pid);

protected:
	typedef std::map<std::string, Instance*> TaskMap;
	TaskMap taskMap;

private:
	Instance initTask;

	Instance getMMStruct(Instance *task);
	Instance nextTask(Instance &task);
	std::string getPathFromDentry(Instance& dentry);
};

#endif //TASKMANAGER_H
