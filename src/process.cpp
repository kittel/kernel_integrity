#include "process.h"

#include <regex>

#include "elffile.h"
#include "elfuserspaceloader.h"
#include "error.h"
#include "kernel.h"
#include "libdwarfparser/instance.h"
#include "processvalidator.h"

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
//The following should replace boost filesystem once it is available in gcc
//#include <filesystem>
//namespace fs = std::filesystem;

namespace kernint {

Process::Process(const std::string &binaryName, Kernel *kernel, pid_t pid)
	:
	kernel{kernel},
	pid{pid},
	execLoader{0},
	binaryName{binaryName} {

	std::cout << COLOR_GREEN << "Loading process " << binaryName
	          << COLOR_NORM << std::endl;
	this->mappedVMAs = this->kernel->getTaskManager()->getVMAInfo(pid);
	this->execLoader = this->kernel->getTaskManager()->loadExec(this);

	// process load-time relocations
	std::cout << "Processing load-time relocations..." << std::endl;
	this->processLoadRel();

	this->symbols.updateRevMaps();
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

/*
 * Gather all libraries which are mapped into the current Address-Space
 *
 * The dynamic linker has already done the ordering work.
 * The libraries lie in this->mappedVMAs, lowest address first.
 * => Reverse iterate through the mappedVMAs and find the corresponding loader,
 *    gives the loaders in the correct processing order.
 */
const std::vector<UserspaceMapping> Process::getMappings() const {
	std::vector<UserspaceMapping> ret;

	std::cout << "Process VMAs: " << std::endl;

	// return a list of mappings
	for (auto &vma : this->getMappedVMAs()) {
		vma.print();

		ElfUserspaceLoader *loader = this->findLoaderByFileName(vma.name);
		UserspaceMapping mapping{
			loader,
			vma.start,
			vma.end,
			vma.flags
		};

		if (loader) {
			ret.push_back(mapping);
		} else {
			std::cout << "ignoring VMA '"
			          << vma.name << "' because no loader found."
			          << std::endl;
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
	std::cout << "Loading vdso" << std::endl;
	this->kernel->getTaskManager()->loadVDSO();

	const std::vector<UserspaceMapping> mappings = this->getMappings();

	// TODO symbol registration by dependency graph
	// use this->elffile->getDependencies as source for
	// the relocation processing graph

	std::unordered_set<ElfUserspaceLoader *> loaders;

	for (auto &mapping : mappings) {
		loaders.insert(mapping.loader);
	}

	// for each loader
	// goal: add symbols by symbol manager with their virtual address
	// given: mappings, loaders
	// for each loader:
	//     for each symbol:
	//         figure out what segment the symbol is in
	//         figure out what mapping that segment is (by flags (ugh))
	//         get virtual base address from the mapping
	for (auto &loader : loaders) {
		this->registerSyms(loader, mappings);
	}

	for (auto &loader : loaders) {
		// TODO: perform relocations on this->image,
		//       NOT on the global elffile.
		loader->elffile->applyRelocations(loader, this->kernel, this);
	}

	for (auto &loader : loaders) {
		// for each elf component: component->initData()
		// to get process-local data segments
		// we have to re-calculate the data segment to apply
		// the relocation stuff.
		loader->initData();
	}


	// last, apply the relocations on the executable image.
	//ElfUserspaceLoader *execLoader = this->getExecLoader();
	//this->registerSyms(execLoader);
	//execLoader->elffile->applyRelocations(execLoader, this->kernel, this);
	//execLoader->initData();

	return;
}

/*
 * Register the symbols at the symbol manager
 *
 *  - sweep through all provided symbols of the given lib (the loader)
 *  if symbol not in map or (symbol in map(WEAK) and exported symbol(GLOBAL))
 *      add to relSymMap
 *
 * add symbols of the given mapping to the symbol manager of this process.
 * a mapping is some elfloader and has an address range.
 */
void Process::registerSyms(ElfUserspaceLoader *loader,
                           const std::vector<UserspaceMapping> &mappings) {


	// loader: some loader where we get symbols from.
	// mappings: all the mappings of this process

	// in here:
	// for each symbol:
	//     determine what segment a symbol is in
	//     find the mapping of that segment by loader name and flags
	//     symbol address += mapping virtual base address
	//     add symbol -> symbol address to symbol manager

	std::cout << " - adding syms of " << loader->getName() << std::endl;

	// TODO: only get symbols for that mapping!
	std::vector<ElfSymbol> syms = loader->getSymbols();

	for (auto &sym : syms) {
		const std::string &name     = sym.name;
		uint64_t           location = sym.value;
		const SegmentInfo *segment  = sym.segment;

		// test if the symbol actually has target location 0,
		// weak symbols have this.
		if (location == 0) {
			std::cout << "NULL-symbol: " << name << std::endl;
			//throw InternalError{"symbol with location 0 registered"};
		}

		std::cout << " * symbol: " << name
		          << std::hex << ", location: 0x" << location
		          << std::dec << std::endl;


		// TODO: check the last mapping?
		const UserspaceMapping *sym_proc_mapping = nullptr;

		for (auto &mapping : mappings) {
			// test if the flags of the mapping match the flags of the
			// found segment and if the loader is the same
			if (mapping.loader == loader) {
				// in-vm mapping flags from the VMAinfo
				bool mflag_r, mflag_w, mflag_x;
				mflag_r = mapping.flags & VMAInfo::VM_READ;
				mflag_w = mapping.flags & VMAInfo::VM_WRITE;
				mflag_x = mapping.flags & VMAInfo::VM_EXEC;

				// segment flags from program header table
				bool sflag_r, sflag_w, sflag_x;
				sflag_r = segment->flags & PF_R;
				sflag_w = segment->flags & PF_W;
				sflag_x = segment->flags & PF_X;

				if (mflag_r == sflag_r and
				    mflag_w == sflag_w and
				    mflag_x == sflag_x) {

					if (sym_proc_mapping == nullptr) {
						sym_proc_mapping = &mapping;
					}
					else {
						throw Error{"found another mapping for the symbol!"};
					}
				}
			}
		}

		if (sym_proc_mapping == nullptr) {
			throw Error{"could not find any mapping for the symbol!"};
		}

		// add the virtual base address to the location!
		location += sym_proc_mapping->virtual_base;

		// actually register it!
		bool replaced = this->symbols.addSymbolAddress(name, location, true);
		if (replaced) {
			std::cout << " * reregistered symbol: " << name << std::endl;
			//throw Error{"symbol overwritten!"};
		}

		std::cout << " * registered symbol: " << name << std::endl;

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

} // namespace kernint
