#include "taskmanager.h"

VMAInfo::VMAInfo(uint64_t start,
				 uint64_t end,
				 uint64_t ino,
				 uint64_t off,
				 uint64_t flags,
				 std::string name):
	start(start),
	end(end),
	ino(ino),
	off(off),
	flags(flags),
	name(name){}

VMAInfo::~VMAInfo(){}

void VMAInfo::print(){
	std::string _name;
	(name.empty()) ? _name = std::string("<anonymous>") : _name = name;
	std::cout << std::hex <<
		"0x" << start << " - 0x" << end << "   " << ino << "   " << name <<
		" " <<
		((flags & VM_READ) ? 'r' : '-') <<
		((flags & VM_WRITE) ? 'w' : '-') <<
		((flags & VM_EXEC) ? 'x' : '-') <<
		((flags & VM_MAYSHARE) ? 's' : 'p') <<
		std::endl;
	return;
}


/*
 * Initialize the TaskManager, parsing all necessary dwarf information from
 * vmlinux file.
 */
TaskManager::TaskManager():
	taskMap(), initTask(){

	auto var = Variable::findVariableByName("init_task");
	assert(var->getLocation());

	auto init = var->getInstance();
	// get the real init task by looking at the next list_head in tasks
	init = init.memberByName("tasks").memberByName("next", true);
	init = init.changeBaseType("task_struct", "tasks");
	this->initTask = init;
	
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

std::string TaskManager::getPathFromDentry(Instance& dentry){
	std::string path = "";
	std::string name = dentry
				.memberByName("d_name", false)
				.memberByName("name", true)
				.getRawValue<std::string>(false);
		
	while(name.compare("/") != 0){
		path.insert(0, name);
		path.insert(0, "/");
		dentry = dentry.memberByName("d_parent", true, true);
		name = dentry
					.memberByName("d_name", false)
					.memberByName("name", true)
					.getRawValue<std::string>(false);
	}

	return path;
}

/* Return a vector of VMAInfo*, containing all VMA mapping information
 * for the given pid. 
 *
 * IMPORTANT: The elements of the vector should be freed, if not needed anymore
 *            to save space!
 */
std::vector<VMAInfo> TaskManager::getVMAInfo(pid_t pid){

	Instance target = this->getTaskForPID(pid);

	// get vector for target task_struct
	Instance mm = this->getMMStruct(&target);

	int32_t map_count = 0;
	// get amount of VMAs in mm_struct
	map_count = mm.memberByName("map_count").getRawValue<int32_t>();

	// get pointer to first VMA in mm_struct
	Instance mmap_i = mm.memberByName("mmap", true);

	// add all VMAs into the vector starting with the first vma
	Instance cur = mmap_i;

	uint64_t curStart = 0;
	uint64_t curEnd = 0;
	uint64_t ino = 0;
	uint64_t flags = 0;
	std::string name;
	uint64_t fileOff = 0;

	std::vector<VMAInfo> vec;
	std::string prevName;

	// Get address of VDSO page
	VMIInstance *vmi = VMIInstance::getInstance();

	uint64_t vdsoPtr = mm.memberByName("context", true)
	                     .memberByName("vdso").getAddress();
	uint64_t vdsoPage = vmi->read64FromVA(vdsoPtr);


	for(int i = 0; i < map_count; i++){
		// TODO change to memberByName("", false).getRawValue<std::string>(true)
		curStart = cur.memberByName("vm_start").getValue<uint64_t>();
		curEnd   = cur.memberByName("vm_end").getValue<uint64_t>();
		flags    = cur.memberByName("vm_flags").getValue<uint64_t>();
		
		if(!cur.memberByName("vm_file", true, true).isNULL()){
			fileOff = cur.memberByName("vm_pgoff").getValue<uint64_t>();
			ino = cur.memberByName("vm_file", true)
					.memberByName("f_mapping",true)
					.memberByName("host", true).memberByName("i_ino")
					.getValue<uint64_t>();
			Instance dentry = cur.memberByName("vm_file", true)
					.memberByName("f_path", false)
					.memberByName("dentry", true);
			name = getPathFromDentry(dentry);
		}
		else {
			fileOff = 0;
			ino = 0;
			name.clear();
		}

		if(name.empty()){

			////////////////////////////////////////////////////
			// TODO XXX TODO XXX TODO                         //
			// This is a dirty hack!                          //
			// Find out where the kernel stores               //
			// the addresses of vvar                          //
			// I feel ashame for not fixing this right now!   //
			////////////////////////////////////////////////////
			
			Instance vm_mm = cur.memberByName("vm_mm", true, true);
			if (curStart == vdsoPage){
				name = "[vdso]";
			}
			else if(curStart <= 
				       vm_mm.memberByName("brk").getValue<uint64_t>() &&
				    curEnd >= 
				       vm_mm.memberByName("start_brk").getValue<uint64_t>())
			{
				name = "[heap]";
			}
			else if(curStart <= 
				       vm_mm.memberByName("start_stack").getValue<uint64_t>() &&
				    curEnd >= 
				       vm_mm.memberByName("start_stack").getValue<uint64_t>())
			{
				name = "[stack]";
			}
			else if (i == map_count - 1){
				name = "[vvar]";
			}else{
				(prevName.find(".heap") != std::string::npos)
					? name = prevName
					: name = prevName + ".heap";
			}
		}
		prevName = name;
		vec.push_back(VMAInfo(curStart, curEnd, ino, fileOff, flags, name));
		cur = cur.memberByName("vm_next", true, true);
	}
	return vec;
}

Instance TaskManager::getTaskForPID(pid_t pid){
	// set iterator to the first child of init
	Instance taskStruct =
		this->initTask.memberByName("tasks")
		              .memberByName("next",true)
		              .changeBaseType("task_struct", "tasks");
	Instance it = this->nextTask(taskStruct);
	
	// go through all the children of the init process, checking the pids
	pid_t curPid = -1;

	while(it != taskStruct){
		curPid = it.memberByName("pid").getValue<int64_t>();
		if (curPid == pid) return it;
		it = this->nextTask(it);
	}

	return this->initTask;
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
