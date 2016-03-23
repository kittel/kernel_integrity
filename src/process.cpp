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

Process::Process(const std::string &binaryName, Kernel *kernel, pid_t pid)
	:
	kernel{kernel},
	pid{pid},
	execLoader{0},
	binaryName{binaryName},
	libraryMap{},
	dataSegmentMap{},
	dataSegmentInfoMap{} {

	std::cout << COLOR_GREEN << "Loading process " << binaryName
	    << COLOR_NORM << std::endl;
	this->mappedVMAs = kernel->getTaskManager()->getVMAInfo(pid);
	this->execLoader = this->kernel->getTaskManager()->loadExec(this);
}


const std::string &Process::getName() const {
	return this->binaryName;
}

ElfProcessLoader *Process::getExecLoader() {
	assert(this->execLoader);
	return this->execLoader;
}

Kernel *Process::getKernel() const {
	return this->kernel;
}

pid_t Process::getPID() const {
	return this->pid;
}

ElfLoader *Process::loadLibrary(const std::string &libraryName) {
	// TODO create a local mapping here.
	// Also relocate the data section according to this process.
	ElfLoader *library = this->findLibByName(libraryName);
	if(library) return library;

	library = this->kernel->getTaskManager()->loadLibrary(libraryName);
	this->libraryMap[libraryName] = library;
	return library;
}

ElfProcessLoader *Process::findLibByName(const std::string &name) {
	if (this->libraryMap.find(name) == this->libraryMap.end()) {
		return nullptr;
	}
	return dynamic_cast<ElfProcessLoader *>(libraryMap[name]);
}

std::vector<uint8_t> *Process::getDataSegmentForLib(const std::string &name) {
	return &this->dataSegmentMap[name];
}

SectionInfo *Process::getSectionInfoForLib(const std::string &name) {
	auto sectionInfoIt = this->dataSectionInfoMap.find(name);
	if(sectionInfoIt != this->dataSectionInfoMap.end()) {
		return &sectionInfoIt->second;
	}

	assert(false);
	return nullptr;
}

SegmentInfo *Process::getSegmentInfoForLib(const std::string &name) {
	auto segmentInfoIt = this->dataSegmentInfoMap.find(name);
	if(segmentInfoIt != this->dataSegmentInfoMap.end()) {
		return &segmentInfoIt->second;
	}

	assert(false);
	return nullptr;
	//auto segmentInfo = this->findLibByName(name)->elffile->findDataSegment();
	//this->dataSegmentInfoMap[name] = segmentInfo;
	//return &this->dataSegmentInfoMap[name];
}

const std::vector<VMAInfo> &Process::getMappedVMAs() const {
	return this->mappedVMAs;
}

/* Print the information for all mapped VMAs */
void Process::printVMAs() const {
	std::cout << "Currently mapped VMAs:" << std::endl;

	for (auto &it : this->mappedVMAs) {
		it.print();
	}
	return;
}

const VMAInfo *Process::findVMAByName(const std::string &name) const {
	for (auto &vma : this->mappedVMAs) {
		if (vma.name.compare(name) == 0) {
			return &vma;
		}
	}
	return nullptr;
}

const VMAInfo *Process::findVMAByAddress(const uint64_t address) const {
	for (auto &vma : this->mappedVMAs) {
		if (address >= vma.start && address < vma.end) {
			return &vma;
		}
	}
	return nullptr;
}
