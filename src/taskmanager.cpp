#include "taskmanager.h"

#include <elf.h>

#include "elfuserspaceloader.h"
#include "kernel.h"
#include "error.h"


namespace kernint {

VMAInfo::VMAInfo(uint64_t start, uint64_t end, uint64_t ino,
                 uint64_t off, uint64_t flags, std::string name)
	:
	start(start),
	end(end),
	ino(ino),
	off(off),
	flags(flags),
	name(name) {}

VMAInfo::~VMAInfo() {}

void VMAInfo::print() const {
	std::string _name;
	(this->name.empty()) ? _name = std::string("<anonymous>") : _name = this->name;
	std::cout << std::hex << "0x" << this->start << " - 0x" << this->end << "   "
	          << std::setw(5) << this->ino << "   " << ((flags & VM_READ) ? 'r' : '-')
	          << ((flags & VM_WRITE) ? 'w' : '-')
	          << ((flags & VM_EXEC) ? 'x' : '-')

	          << ((flags & VM_MAYSHARE) ? 's' : 'p') << "   " << this->name
	          << std::dec << std::endl;
	return;
}

/*
 * Initialize the TaskManager, parsing all necessary dwarf information from
 * vmlinux file.
 */
TaskManager::TaskManager(Kernel *kernel)
	:
	initTask{},
	kernel{kernel} {}

void TaskManager::init() {
	auto var = this->kernel->symbols.findVariableByName("init_task");
	assert(var);
	assert(var->getLocation());

	auto init = var->getInstance();
	// get the real init task by looking at the next list_head in tasks
	init           = init.memberByName("tasks");
	init           = init.memberByName("next", true);
	init           = init.changeBaseType("task_struct", "tasks");
	this->initTask = init;
}

TaskManager::~TaskManager() {}

std::string TaskManager::getPathFromDentry(Instance& dentry) const {
	std::string path;
	std::string name = dentry.memberByName("d_name", false)
	                         .memberByName("name", true)
	                         .getRawValue<std::string>(false);

	if(name.compare("dev/zero") == 0) {
		return "/dev/zero";
	}

	while (name.compare("/") != 0) {
		path.insert(0, name);
		path.insert(0, "/");
		dentry = dentry.memberByName("d_parent", true, true);
		name = dentry.memberByName("d_name", false)
		             .memberByName("name", true)
		             .getRawValue<std::string>(false);
	}

	return path;
}

/*
 * Return a vector of VMAInfo, containing all VMA mapping information
 * for the given pid.
 */
std::vector<VMAInfo> TaskManager::getVMAInfo(pid_t pid) {
	Instance target = this->getTaskForPID(pid);
	std::vector<VMAInfo> vec;

	/**
	 * Return an instance of the mm_struct member
	 * Take care, that this might not exist for kernel threads.
	 */
	Instance mm = target.memberByName("mm", true, true);

	// Kernel Threads do not own a memory map.
	if(!mm.getAddress()) {
		return vec;
	}

	int32_t map_count = 0;
	// get amount of VMAs in mm_struct
	map_count = mm.memberByName("map_count").getRawValue<int32_t>();

	// get pointer to first VMA in mm_struct
	Instance mmap_i = mm.memberByName("mmap", true);

	// add all VMAs into the vector starting with the first vma
	Instance cur = mmap_i;

	uint64_t curStart = 0;
	uint64_t curEnd   = 0;
	uint64_t ino      = 0;
	uint64_t flags    = 0;
	std::string name;
	uint64_t fileOff = 0;

	std::string prevName;

	// Get address of VDSO page
	uint64_t vdsoPtr = mm.memberByName("context", true).memberByName("vdso").getAddress();
	uint64_t vdsoPage = this->kernel->vmi->read64FromVA(vdsoPtr);

	for (int i = 0; i < map_count; i++) {
		// TODO change to memberByName("", false).getRawValue<std::string>(true)
		curStart = cur.memberByName("vm_start").getValue<uint64_t>();
		curEnd   = cur.memberByName("vm_end").getValue<uint64_t>();
		flags    = cur.memberByName("vm_flags").getValue<uint64_t>();

		if (!cur.memberByName("vm_file", true, true).isNULL()) {
			fileOff = cur.memberByName("vm_pgoff").getValue<uint64_t>();
			ino = cur.memberByName("vm_file", true)
			         .memberByName("f_mapping", true)
			         .memberByName("host", true)
			         .memberByName("i_ino")
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

		if (name.empty()) {
			////////////////////////////////////////////////////
			// TODO XXX TODO XXX TODO                         //
			// This is a dirty hack!                          //
			// Find out where the kernel stores               //
			// the addresses of vvar                          //
			// I feel ashame for not fixing this right now!   //
			////////////////////////////////////////////////////

			Instance vm_mm = cur.memberByName("vm_mm", true, true);
			if (curStart == vdsoPage) {
				name = "[vdso]";
			} else if (curStart <=
			           vm_mm.memberByName("brk").getValue<uint64_t>() &&
			           curEnd >= vm_mm.memberByName("start_brk")
			           .getValue<uint64_t>()) {
				name = "[heap]";
			} else if (curStart <= vm_mm.memberByName("start_stack")
			           .getValue<uint64_t>() &&
			           curEnd >= vm_mm.memberByName("start_stack")
			           .getValue<uint64_t>()) {
				name = "[stack]";
			} else if (i == map_count - 1) {
				name = "[vvar]";
			} else {
				if (prevName.find(".heap") != std::string::npos) {
					name = prevName;
				}
				else {
					name = prevName + ".heap";
				}
			}
		}

		prevName = name;
		vec.push_back(
			VMAInfo{
				curStart,
				curEnd,
				ino,
				fileOff,
				flags,
				name
			}
		);
		cur = cur.memberByName("vm_next", true, true);
	}
	// // Add vsyscall mapping.V
	// // This is already mapped in the kernel
	// // see arch/x86/include/uapi/asm/vsyscall.h
	// // TODO fix this
	// uint64_t vsyscall = -10UL << 20;
	// vec.push_back(VMAInfo(vsyscall, vsyscall + PAGESIZE, 0, 0, 0, "[vsyscall]"));
	return vec;
}

Instance TaskManager::getTaskForPID(pid_t pid) const {
	// set iterator to the first child of init
	Instance taskStruct = this->initTask.memberByName("tasks")
	                                    .memberByName("next", true)
	                                    .changeBaseType("task_struct", "tasks");
	Instance it = this->nextTask(taskStruct);

	// go through all the children of the init process, checking the pids
	pid_t curPid = -1;

	while (it != taskStruct) {
		curPid = it.memberByName("pid").getValue<int64_t>();
		if (curPid == pid)
			return it;
		it = this->nextTask(it);
	}

	return this->initTask;
}

std::vector<Instance> TaskManager::getTasks() const {
	std::vector<Instance> tasks;

	// set iterator to the first child of init
	Instance taskStruct = this->initTask.memberByName("tasks")
	                                    .changeBaseType("task_struct", "tasks");
	auto it = taskStruct;
	do {
		tasks.push_back(it);
		it = this->nextTask(it);
	} while(it != taskStruct);

	return tasks;
}


/* Return the next task from task list */
Instance TaskManager::nextTask(Instance &task) const {
	Instance next = task.memberByName("tasks").memberByName("next", true);
	next          = next.changeBaseType("task_struct", "tasks");
	return next;
}

std::string TaskManager::getTaskExeName(pid_t pid) const {
	//return this->getTaskForPID(pid).memberByName("comm").getRawValue<std::string>();
	Instance a = this->getTaskForPID(pid).memberByName("mm", true);
	a = a.memberByName("exe_file", true);
	a = a.memberByName("f_path");
	a = a.memberByName("dentry", true);
	return getPathFromDentry(a);
}

std::vector<std::string> TaskManager::getArgForTask(pid_t pid) const {
	Instance mm = this->getTaskForPID(pid).memberByName("active_mm", true);
	uint64_t start = mm.memberByName("arg_start").getValue<uint64_t>();
	uint64_t end   = mm.memberByName("arg_end").getValue<uint64_t>();

	std::vector<std::string> arguments;

	uint64_t i = start;
	while (i < end) {
		std::string str = this->kernel->vmi->readStrFromVA(i, pid);
		arguments.push_back(str);
		i += str.size() + 1;
	}

	return arguments;
}

std::unordered_map<std::string, std::string> TaskManager::getEnvForTask(pid_t pid) const {
	Instance mm = this->getTaskForPID(pid).memberByName("active_mm", true);
	uint64_t start = mm.memberByName("env_start").getValue<uint64_t>();
	uint64_t end   = mm.memberByName("env_end")  .getValue<uint64_t>();

	std::unordered_map<std::string, std::string> environment;

	uint64_t i = start;
	while (i < end) {
		std::string str = this->kernel->vmi->readStrFromVA(i, pid);
		size_t off = str.find("=");
		environment[str.substr(0, off)] = str.substr(off + 1);
		i += str.size() + 1;
	}

	return environment;
}

/* Retrieve the next Instance from a circular list given in member */
/*
Instance TaskManager::nextInstance(Instance *instance, std::string member, std::string type) {
	Instance next = instance->memberByName(member);
	// next is now an instance of type struct list_head with the needed value at
	// offset 0
	next = next.memberByName("next", true);
	// next is now a list_head with type 62 (not list_head)
	next = next.changeBaseType(type);
	return next;
}
*/

void TaskManager::setLibraryDir(const std::string &dirName) {
	const std::string delimiters   = ":";
	std::string::size_type lastPos = dirName.find_first_not_of(delimiters, 0);
	std::string::size_type pos     = dirName.find_first_of(delimiters, lastPos);

	while (std::string::npos != pos || std::string::npos != lastPos) {
		ldLibraryPaths.push_back(dirName.substr(lastPos, pos - lastPos));
		lastPos = dirName.find_first_not_of(delimiters, pos);
		pos     = dirName.find_first_of(delimiters, lastPos);
	}
}


void TaskManager::setRootDir(const std::string &dirName) {
	this->rootPath = dirName;
}


ElfLoader *TaskManager::loadLibrary(const std::string &libraryNameOrig,
                                    Process *process) {

	// locate the requested library name on the filesystem.
	// the elf doesn't request a full name, so we have to
	// walk through the searchpaths ourselves.
	std::string filename = this->findLibraryFile(libraryNameOrig);

	if (filename.empty()) {
		std::cout << libraryNameOrig
		          << ": library file not found on disk" << std::endl;
		return nullptr;
	}

	// this is the path on the hypervisor
	fs::path file = fs::canonical(filename);
	std::string file_on_disk = file.string();

	// make the path vm-absolute
	filename = "/" + file.lexically_relative(this->rootPath).string();

	auto library = this->findLibByName(filename);
	if (library) {
		return library;
	}

	std::cout << "to satisfy: " << libraryNameOrig
	          << " loading new library: " << filename << std::endl;

	// create ELF Object, returns nullptr if it's not an elf file.
	ElfFile *libraryFile = ElfFile::loadElfFile(file_on_disk);

	if (libraryFile == nullptr) {
		return nullptr;
	}

	library = libraryFile->parseUserspace(filename, this->kernel, process);

	// create the text segment copy
	library->initImage();

	// TODO: move somewhere where we can also do relocations in the
	//       process context. (to loaddependencies)
	//       this has to be done once per process.
	//       the design is fundamentally flawed so this task manager
	//       can only support one process to watch.
	library->getDependencies(process);

	this->libraryMap[filename] = library;

	return library;
}

ElfUserspaceLoader *TaskManager::findLibByName(const std::string &name) {
	auto it = this->libraryMap.find(name);
	if (it == this->libraryMap.end()) {
		return nullptr;
	}
	return dynamic_cast<ElfUserspaceLoader *>(it->second);
}

std::string TaskManager::findLibraryFile(const std::string &libName) {
	//escape special characters in filenames
	std::string replaced_libName = std::regex_replace(libName,
	std::regex("[\\[\\().*+^?|{}$[]"),"\\$&");
	std::regex regex = std::regex(replaced_libName);

	// try each search path
	for (auto &directory : this->ldLibraryPaths) {
		for (fs::recursive_directory_iterator end, dir(directory); dir != end; dir++) {
			if (std::regex_match((*dir).path().filename().string(), regex)) {
				return (*dir).path().native();
			}
		}
	}
	return "";
}

ElfUserspaceLoader *TaskManager::loadExec(Process *process) {
	// Create ELF Object

	// TODO XXX implement caching for binaries
	std::string binaryName = process->getName();
	std::string exe = this->getTaskExeName(process->getPID());

	std::cout << "loading exec: binary = " << binaryName
	          << ", exe name = " << exe << std::endl;

	fs::path file = fs::canonical(binaryName);
	std::string file_on_disk = file.string();

	std::string loader_name = "/" + file.lexically_relative(this->rootPath).string();


	ElfFile *execFile = ElfFile::loadElfFile(file_on_disk);

	ElfUserspaceLoader *execLoader = execFile->parseUserspace(
		loader_name, this->kernel, process);

	execLoader->initImage();

	// XXX: should we only store getNameFromPath(exe) (the basename)?
	this->libraryMap[exe] = execLoader;
	return execLoader;
}

ElfLoader *TaskManager::loadVDSO(Process *process) {
	// Symbols in Kernel that point to the vdso page
	// ... the size is currently unknown
	// TODO Find out the correct archirecture of the binary.
	// pass the arch as argument to this function.
	// store it as [vdso-64], [vdso-32_int80], etc.
	//
	// vdso_image_64
	// vdso_image_x32
	// vdso_image_32_int80
	// vdso_image_32_syscall
	// vdso_image_32_sysenter

	std::string vdsoString{"[vdso]"};
	auto *vdsoLoader = this->findLibByName(vdsoString);
	if (vdsoLoader) return vdsoLoader;

	if (this->vdsoData.size() > 0) {
		throw Error{"vdso vector has data but [vdso] not found as library"};
	}

	// if the vdso loader was not known, fetch the data from
	// the VM memory.

	auto vdsoVar = this->kernel->symbols.findVariableByName("vdso_image_64");
	assert(vdsoVar);

	auto vdsoImage = vdsoVar->getInstance();

	this->vdsoData = this->kernel->vmi->readVectorFromVA(
		vdsoImage.memberByName("data").getRawValue<uint64_t>(false),
		vdsoImage.memberByName("size").getValue<uint64_t>());

	// Load VDSO page
	ElfFile *vdsoFile = ElfFile::loadElfFileFromBuffer(
		vdsoString,
		this->vdsoData.data(), this->vdsoData.size()
	);

	vdsoLoader = vdsoFile->parseUserspace(vdsoString,
	                                      this->kernel, process);
	vdsoLoader->initImage();

	this->libraryMap[vdsoString] = vdsoLoader;
	return vdsoLoader;
}

} // namespace kernint
