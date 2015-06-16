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

typedef int pid_t;

/* This class contains the extracted information of an address space's VMAs
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
		uint64_t start, end, ino, off;
		std::string name;

		VMAInfo(uint64_t start, uint64_t end, uint64_t ino, uint64_t off,
				std::string name);
		~VMAInfo();
};

/*
 * This class provides the interface for the kernel data structures 
 *    - task_struct
 *    - mm_struct
 *    - vm_area_struct
 *                      in the VMIInstance.
 *
 * The most important function is getVMAInfo(pid_t), which provides the caller
 * with all necessary information about current memory mapping of the task.
 */
class TaskManager{

	public:
		TaskManager(VMIInstance *vmi, std::string kernPath);
		~TaskManager();

		std::vector<VMAInfo*> getVMAInfo(pid_t pid);

	protected:
		typedef std::map<std::string, Instance*> TaskMap;
		TaskMap taskMap;

	private:
		Instance initTask;
		std::vector<Instance*> vma_vec;

//		Instance nextInstance(Instance *instance, std::string member, std::string type);
	
		Instance getInitTaskStruct();
		Instance getMMStruct(Instance *task);
		std::vector<Instance> getVMAs(Instance *mm);
		std::vector<Instance> getMappingForPID(pid_t pid);
		Instance getTaskForPID(pid_t pid);
		Instance nextTask(Instance &task);
	
		VMIInstance *vmi;
};
#endif //TASKMANAGER_H