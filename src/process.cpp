#include "process.h"

#include <regex>

#include "elffile.h"
#include "elfprocessloader.h"
#include "kernel.h"
#include "libdwarfparser/instance.h"
#include "processvalidator.h"

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
//The following should replace boost filesystem once it is available in gcc
//#include <filesystem>
//namespace fs = std::filesystem;

Process::Process(const std::string &binaryName, Kernel *kernel)
	:
	kernel{kernel},
	execLoader{0},
	binaryName{binaryName} {}


const std::string &Process::getName() {
	return this->binaryName;
}

void Process::setLibraryDir(const std::string &dirName) {
	const std::string delimiters   = ":";
	std::string::size_type lastPos = dirName.find_first_not_of(delimiters, 0);
	std::string::size_type pos     = dirName.find_first_of(delimiters, lastPos);

	while (std::string::npos != pos || std::string::npos != lastPos) {
		libDirName.push_back(dirName.substr(lastPos, pos - lastPos));
		lastPos = dirName.find_first_not_of(delimiters, pos);
		pos     = dirName.find_first_of(delimiters, lastPos);
	}
}

ElfLoader *Process::loadLibrary(const std::string &libraryNameOrig) {
	std::string filename = this->findLibraryFile(libraryNameOrig);
	if (filename.empty()) {
		std::cout << libraryNameOrig
		          << ": Library File not found" << std::endl;
		return nullptr;
	}

	fs::path file = fs::canonical(filename);
	filename = file.string();
	std::string libraryName = file.filename().string();

	if (this->libraryMap.find(libraryName) != this->libraryMap.end()) {
		return this->libraryMap[libraryName];
	}

	// create ELF Object
	ElfFile *libraryFile = ElfFile::loadElfFile(filename);

	auto library = dynamic_cast<ElfProcessLoader64 *>(
		libraryFile->parseProcess(libraryName, this, this->kernel));

	library->parse();
	this->libraryMap[libraryName] = library;

	return library;
}

ElfProcessLoader *Process::findLibByName(const std::string &name) {
	if (this->libraryMap.find(name) == this->libraryMap.end()) {
		return nullptr;
	}
	return dynamic_cast<ElfProcessLoader *>(libraryMap[name]);
}

std::string Process::findLibraryFile(const std::string &libName) {
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

ElfProcessLoader *Process::getExecLoader() {
	if (!this->execLoader) {
		this->loadExec();
	}
	assert(this->execLoader);
	return this->execLoader;
}

void Process::loadExec() {
	// Create ELF Object
	ElfFile *execFile = ElfFile::loadElfFile(this->binaryName);

	std::string name = this->binaryName.substr(this->binaryName.rfind("/", std::string::npos) + 1, std::string::npos);

	this->execLoader = execFile->parseProcess(name, this, this->kernel);
	execLoader->parse();
	return;
}


ElfLoader *Process::loadVDSO() {
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
	if (this->libraryMap.find(vdsoString) != this->libraryMap.end()) {
		return this->libraryMap[vdsoString];
	}

	auto vdsoVar = this->symbols.findVariableByName("vdso_image_64");
	assert(vdsoVar);

	auto vdsoImage = vdsoVar->getInstance();

	auto vdso = this->kernel->vmi->readVectorFromVA(
		vdsoImage.memberByName("data").getRawValue<uint64_t>(false),
		vdsoImage.memberByName("size").getValue<uint64_t>());

	// Load VDSO page
	ElfFile *vdsoFile = ElfFile::loadElfFileFromBuffer(vdso.data(), vdso.size());

	auto vdsoLoader = dynamic_cast<ElfProcessLoader64 *>(vdsoFile->parseProcess("[vdso]", this, this->kernel));
	vdsoLoader->parse();

	this->libraryMap[vdsoString] = vdsoLoader;
	return vdsoLoader;
}

Kernel *Process::getKernel() const {
	return this->kernel;
}
