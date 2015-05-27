#include "taskmanager.h"


VMAInfo::VMAInfo(uint64_t start, uint64_t end, uint64_t ino, uint64_t off,
				std::string name) :
		start(start), end(end), ino(ino), off(off), name(name){}

VMAInfo::~VMAInfo(){
	// TODO free contents? Call destructor manually?
}


/*
 * Initialize the TaskManager, parsing all necessary dwarf information from
 * vmlinux file.
 */
TaskManager::TaskManager(VMIInstance *vmi, std::string kernPath):taskMap(),
																initTask(),
																vma_vec(),
																vmi(vmi){


	std::cout << "Trying to parse kernel dwarf "
	<< " information from file " << kernPath << std::endl; 
	try{
		DwarfParser::parseDwarfFromFilename(kernPath);
	} catch (DwarfException &e) {
		std::cout << "Exception: " << e.what() << std::endl;
	}

	// retrieve task struct
	this->initTask = this->getInitTaskStruct();
#ifdef DEBUG
	std::cout << "debug:(TaskManager()) initTaskStruct: addr = " << std::hex
	<< (void*)this->initTask.getAddress() << ", length = "
	<< (void*)this->initTask.getLength()
	<< ", type = " 
	<< this->initTask.getType()->getNameForType(this->initTask.getType())
	<< std::endl;
#endif
}

TaskManager::~TaskManager(){}



/* Return an instance of the mm_struct member */
Instance TaskManager::getMMStruct(Instance *task){
	Instance mm = task->memberByName("mm", true);
	return mm;
}

/* Return a vector of all vma's in the given mm_struct */
std::vector<Instance> TaskManager::getVMAs(Instance *mm){
	//TODO optimize: declare vector with length map_count
	std::vector<Instance> vec;
	
	std::cout << "Trying to read the VMAs of " << std::hex << (void*) mm
	<< " ..." << std::endl;
	
	int map_count = 0;

	// get amount of VMAs in mm_struct
	Instance map_count_i = mm->memberByName("map_count");
	map_count = map_count_i.getValue<int32_t>();

	// get pointer to first VMA in mm_struct
	Instance mmap_i = mm->memberByName("mmap", true);

	// add all VMAs into the vector starting with the first vma
	Instance cur = mmap_i;
	Instance inodeNr;
	uint64_t i_ino = 0;
	Instance file;
	std::string name;
	for(int i = 0; i < map_count; i++){
		// TODO change to memberByName("", false).getRawValue<std::string>(true)
		inodeNr = cur.memberByName("vm_file", true);
		if(inodeNr != NULL){
			inodeNr = inodeNr.memberByName("f_mapping",true)
			.memberByName("host", true).memberByName("i_ino");
			i_ino = inodeNr.getValue<uint64_t>();
			file = cur.memberByName("vm_file", true)
			.memberByName("f_path", false)
			.memberByName("dentry", true)
			.memberByName("d_name", false)
			.memberByName("name", true);
			name = file.getRawValue<std::string>(false);
		}
		else {
			i_ino = 0;
			name.clear();
		}

#ifdef DEBUG
		std::cout << std::dec << "[" << i << "]\tAdding VMA from "
		<< (void*)cur.memberByName("vm_start").getValue<uint64_t>()
		<< "\t(" << i_ino <<  ")\t" << name << std::endl;
#endif


		vec.insert(std::end(vec), cur); 
		cur = cur.memberByName("vm_next", true);
	}
	(void)i_ino;
	return vec;
}


/* Return the vma vector of the task of the given pid */
std::vector<Instance> TaskManager::getMappingForPID(pid_t pid){

	std::cout << "Searching for task with pid " << std::dec << pid 
	<< " ..." << std::endl;
	Instance target = this->getTaskForPID(pid);

	// get vector for target task_struct
	Instance mm_i = this->getMMStruct(&target);
	return this->getVMAs(&mm_i);
}


/* Return a vector of VMAInfo*, containing all VMA mapping information
 * for the given pid. 
 *
 * IMPORTANT: The elements of the vector should be freed, if not needed anymore
 *            to save space!
 */
std::vector<VMAInfo*> TaskManager::getVMAInfo(pid_t pid){

	std::vector<Instance> input = this->getMappingForPID(pid);
	std::vector<VMAInfo*> ret;

	uint64_t curStart = 0;
	uint64_t curEnd = 0;
	uint64_t ino = 0;
	std::string name;
	uint64_t fileOff = 0;

	// sweep through all vma instances, read the needed values and append to vec
	for(auto it = std::begin(input); it != std::end(input); it++){
		curStart = (*it).memberByName("vm_start").getValue<uint64_t>();
		curEnd = (*it).memberByName("vm_end").getValue<uint64_t>();
		if((*it).memberByName("vm_file", true) != NULL){
			fileOff = (*it).memberByName("vm_pgoff").getValue<uint64_t>();
			ino = (*it).memberByName("vm_file", true)
					.memberByName("f_mapping",true)
					.memberByName("host", true).memberByName("i_ino")
					.getValue<uint64_t>();
			name = (*it).memberByName("vm_file", true)
					.memberByName("f_path", false)
					.memberByName("dentry", true)
					.memberByName("d_name", false)
					.memberByName("name", true).getRawValue<std::string>(false);
		}
		else{
			fileOff = 0;
			ino = 0;
			name.clear();
		}
		VMAInfo *vma_i = new VMAInfo(curStart, curEnd, ino, fileOff, name);
		ret.insert(std::end(ret), vma_i);
	}
	return ret;
}

/* Return an instance of the init task_struct of the vm */
Instance TaskManager::getInitTaskStruct(){

#ifdef DEBUG
	std::cout << "debug:(getInitTaskStruct) Now trying to get the first "
	<< "instance of task_struct..." << std::endl;
#endif
	// init_task actually refers to the swapper (pid 0)
	Instance init = Variable::findVariableByName("init_task")->getInstance();

	// get the real init task by looking at the next list_head in tasks
	init = init.memberByName("tasks").memberByName("next", true);
	init = init.changeBaseType("task_struct", "tasks");
	return init;
}


Instance TaskManager::getTaskForPID(pid_t pid){
	// set iterator to the first child of init
	Instance it = this->initTask.memberByName("tasks").memberByName("next",true);
	it = it.changeBaseType("task_struct", "tasks");
/*
	std::cout << "First iterator has pid : "
	<< it.memberByName("pid").getValue<int32_t>()
	<< std::endl;
*/
	// go through all the children of the init process, checking the pids
	pid_t curPid = -1;

	while(curPid != pid){
		it = this->nextTask(it);
		curPid = it.memberByName("pid").getValue<int32_t>();
//		std::cout << "Checked PID " << curPid << " ..." << std::endl;
	}

	if(curPid != -1){
		std::cout << "Found task_struct with PID " << std::dec << curPid
		<< std::endl;
		return it;
	}
	else {
		std::cout << "error(getTaskForPID): No corresponding task_struct found for PID "
		<< pid << ". Returning initTask. " << std::endl;
		return this->initTask;
	}
}

/* Return the next task from task list */
Instance TaskManager::nextTask(Instance &task){
	Instance next = task.memberByName("tasks").memberByName("next", true);
	next = next.changeBaseType("task_struct", "tasks");
	return next;
}

/* Retrieve the next Instance from a circular list given in member 
Instance TaskManager::nextInstance(Instance *instance, std::string member, std::string type){
	Instance next = instance->memberByName(member);
	// next is now an instance of type struct list_head with the needed value at
	// offset 0
	next = next.memberByName("next", true); 
	// next is now a list_head with type 62 (not list_head)
	next = next.changeBaseType(type);
	return next;
}
*/
