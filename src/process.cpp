#include "process.h"

#include <regex>

#include "elffile.h"
#include "elfuserspaceloader.h"
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
	this->mappedVMAs = this->kernel->getTaskManager()->getVMAInfo(pid);
	this->execLoader = this->kernel->getTaskManager()->loadExec(this);
}


const std::string &Process::getName() const {
	return this->binaryName;
}

ElfUserspaceLoader *Process::getExecLoader() {
	assert(this->execLoader);
	return this->execLoader;
}

Kernel *Process::getKernel() const {
	return this->kernel;
}

pid_t Process::getPID() const {
	return this->pid;
}

ElfUserspaceLoader *Process::findLibByName(const std::string &name) {
	auto it = this->libraryMap.find(name);
	if (it == this->libraryMap.end()) {
		return nullptr;
	}
	return it->second;
}

std::vector<uint8_t> *Process::getDataSegmentForLib(const std::string &name) {
	return &this->dataSegmentMap[name];
}

SectionInfo *Process::getSectionInfoForLib(const std::string &name) {
	auto sectionInfoIt = this->dataSectionInfoMap.find(name);
	if (sectionInfoIt != this->dataSectionInfoMap.end()) {
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

	// TODO segment info
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

/* Gather all libraries which are mapped into the current Address-Space
 *
 * The dynamic linker has already done the ordering work.
 * The libraries lie in this->mappedVMAs, lowest address first.
 * => Reverse iterate through the mappedVMAs and find the corresponding loader,
 *    gives the loaders in the correct processing order.
 */
const std::unordered_set<ElfUserspaceLoader *> Process::getMappedLibs() const {
	std::unordered_set<ElfUserspaceLoader *> ret;
	ElfUserspaceLoader *loader = nullptr;

	for (auto &vma : this->getMappedVMAs()) {
		loader = this->findLoaderByFileName(vma.name);
		if (loader) {
			ret.insert(loader);
		}
	}
	return ret;
}

/*
 * Find a corresponding ElfUserspaceLoader for the given vaddr
 */
ElfUserspaceLoader *Process::findLoaderByAddress(const uint64_t addr) const {
	const VMAInfo *vma = this->findVMAByAddress(addr);
	if (!vma) {
		return nullptr;
	}
	return this->findLoaderByFileName(vma->name);
}

/*
 * find loader by searching for a library name
 */
ElfUserspaceLoader *Process::findLoaderByFileName(const std::string &name) const {
	std::string libname = fs::path(name).filename().string();
	return this->getKernel()
	           ->getTaskManager()
	           ->findLibByName(libname);
}


/* Find a corresponding SectionInfo for the given vaddr */
SectionInfo *Process::getSegmentForAddress(uint64_t vaddr) {
	// find a corresponding loader for the given vaddr
	ElfUserspaceLoader *loader = this->findLoaderByAddress(vaddr);

	SectionInfo *ret = loader->getSegmentForAddress(vaddr);
	return ret;
}

/* Process load-time relocations of all libraries, which are mapped to the
 * virtual address space of our main process. The following steps have to be
 * taken:
 *
 *  - check which libraries are mapped to the VAS
 *  - generate processing order based on cross-dependencies
 *  - based on the order do for every library:
 *      - retrieve all exported symbols from the respective library
 *      - process relocation of the respective library
 */
void Process::processLoadRel() {
	const std::unordered_set<ElfUserspaceLoader *> mappedLibs = this->getMappedLibs();


	// TODO symbol registration by dependency graph


	for (auto &lib : mappedLibs) {
		// announce provided symbols
		std::cout << " - adding syms of " << lib->getName() << std::endl;
		this->registerSyms(lib);
	}

	for (auto &lib : mappedLibs) {
		// TODO: perform relocations on this->image
		// TODO: the process segments were already inited,
		//       this will now update the sections and
		//       won't affect the segment! -> cyclic dependency.
		lib->elffile->applyRelocations(lib, this->kernel, this);
	}


	// TODO ================
	// for each elf component: component->initData()
	// to get process-local data segments

	// else:
	// TODO use this->elffile->getDependencies as source for
	// the relocation processing graph

	// last, apply the relocations on the executable image.
	ElfUserspaceLoader *execLoader = this->getExecLoader();
	execLoader->elffile->applyRelocations(execLoader, this->kernel, this);
	this->registerSyms(execLoader);

	return;
}

/* Add the symbols, announced by lib, to the nameRelSymMap
 *
 *  - sweep through all provided symbols of the lib
 *  if symbol not in map or (symbol in map(WEAK) and exported symbol(GLOBAL))
 *      add to relSymMap
 */
void Process::registerSyms(ElfUserspaceLoader *elf) {
	std::vector<RelSym> syms = elf->getSymbols();

	for (auto &it : syms) {
		const std::string &name = it.name;
		uint64_t location = it.value;

		this->symbols.addSymbolAddress(name, location);

		/**
		TODO if mapped symbol is WEAK and cur symbol is GLOBAL . overwrite
		if (ELF64_ST_BIND(sym.info) == STB_WEAK &&
			ELF64_ST_BIND(it.info) == STB_GLOBAL) {
			this->relSymMap[it.name] = it;
		}
		*/
	}
	return;
}
