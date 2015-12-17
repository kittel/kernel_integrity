#include "userspacemanager.h"

#include "elffile.h"
#include "elfloader.h"
#include "kernel.h"
#include "process.h"

UserspaceManager::UserspaceManager(Kernel *kernel) :
	kernel{kernel} {};

void UserspaceManager::setLibraryDir(const std::string &dirName) {
	const std::string delimiters   = ":";
	std::string::size_type lastPos = dirName.find_first_not_of(delimiters, 0);
	std::string::size_type pos     = dirName.find_first_of(delimiters, lastPos);

	while (std::string::npos != pos || std::string::npos != lastPos) {
		libDirName.push_back(dirName.substr(lastPos, pos - lastPos));
		lastPos = dirName.find_first_not_of(delimiters, pos);
		pos     = dirName.find_first_of(delimiters, lastPos);
	}
}

ElfLoader *UserspaceManager::loadLibrary(const std::string &libraryNameOrig) {
	std::string filename = this->findLibraryFile(libraryNameOrig);
	if (filename.empty()) {
		std::cout << libraryNameOrig
		          << ": Library File not found" << std::endl;
		return nullptr;
	}

	fs::path file = fs::canonical(filename);
	filename = file.string();
	std::string libraryName = file.filename().string();
	
	auto library = this->findLibByName(libraryName);
	if (library) return library;

	// create ELF Object
	ElfFile *libraryFile = ElfFile::loadElfFile(filename);

	library = libraryFile->parseProcess(libraryName, this->kernel);
	library->parse();
	
	this->libraryMap[libraryName] = library;

	return library;
}

ElfProcessLoader *UserspaceManager::findLibByName(const std::string &name) {
	if (this->libraryMap.find(name) == this->libraryMap.end()) {
		return nullptr;
	}
	return dynamic_cast<ElfProcessLoader *>(libraryMap[name]);
}

std::string UserspaceManager::findLibraryFile(const std::string &libName) {
	std::regex regex = std::regex(libName);
	for (auto &directory : this->libDirName) {
		for (fs::recursive_directory_iterator end, dir(directory); dir != end; dir++) {
			if (std::regex_match((*dir).path().filename().string(), regex)) {
				return (*dir).path().native();
			}
		}
	}
	return "";
}

ElfProcessLoader *UserspaceManager::loadExec(Process *process) {
	// Create ELF Object
	
	// TODO XXX implement caching for binaries
	std::string binaryName = process->getName();
	ElfFile *execFile = ElfFile::loadElfFile(binaryName);

	std::string name = binaryName.substr(
	    binaryName.rfind("/", std::string::npos) + 1, std::string::npos);

	ElfProcessLoader * execLoader =
	        execFile->parseProcess(name, this->kernel);
	execLoader->parse();
	return execLoader;
}

ElfLoader *UserspaceManager::loadVDSO() {
	// Symbols in Kernel that point to the vdso page
	// ... the size is currently unknown
	// TODO Find out the correct archirecture of the binary.
	//
	// vdso_image_64
	// vdso_image_x32
	// vdso_image_32_int80
	// vdso_image_32_syscall
	// vdso_image_32_sysenter

	std::string vdsoString{"[vdso]"};
	auto *vdsoLoader = this->findLibByName(vdsoString);
	if(vdsoLoader) return vdsoLoader;

	auto vdsoVar = this->kernel->symbols.findVariableByName("vdso_image_64");
	assert(vdsoVar);

	auto vdsoImage = vdsoVar->getInstance();

	auto vdso = this->kernel->vmi->readVectorFromVA(
		vdsoImage.memberByName("data").getRawValue<uint64_t>(false),
		vdsoImage.memberByName("size").getValue<uint64_t>());

	// Load VDSO page
	ElfFile *vdsoFile = ElfFile::loadElfFileFromBuffer(vdso.data(), vdso.size());

	vdsoLoader = vdsoFile->parseProcess("[vdso]", this->kernel);
	vdsoLoader->parse();

	this->libraryMap[vdsoString] = vdsoLoader;
	return vdsoLoader;
}



