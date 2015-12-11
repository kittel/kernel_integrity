#include <iostream>
#include <iomanip>

#include <cassert>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <unordered_map>
#include <algorithm>

#include <processvalidator.h>

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

// TODO: retrieve paths from command line parameters
ProcessValidator::ProcessValidator(ElfKernelLoader *kl,
                                   Process *process,
                                   VMIInstance *vmi,
                                   int32_t pid)
    :
	vmi{vmi},
	kl{kl},
	pid{pid},
	process{process},
	tm{process->getKernel()} {

	std::cout << "ProcessValidator got: " << this->process->getName() << std::endl;

	this->mappedVMAs = tm.getVMAInfo(pid);

	// process load-time relocations
	std::cout << "Processing load-time relocations..." << std::endl;
	this->processLoadRel();
}

ProcessValidator::~ProcessValidator() {}

int ProcessValidator::validateProcess() {
	// check if all mapped pages are known
	std::cout << COLOR_GREEN
	    << "Starting page validation ..."
	    COLOR_RESET << std::endl;

	PageMap executablePageMap = vmi->getPages(pid);
	for (auto &page : executablePageMap) {
		// check if page is contained in VMAs
		if (!(page.second->vaddr & 0xffff800000000000) &&
		    !this->findVMAByAddress(page.second->vaddr)) {
			std::cout << COLOR_RED << COLOR_BOLD
			          << "Found page that has no corresponding VMA: "
			          << std::hex << page.second->vaddr << std::dec
			          << COLOR_RESET << std::endl;
		}
	}
	vmi->destroyMap(executablePageMap);

	// Check if all mapped VMAs are valid
	for (auto &section : this->mappedVMAs) {
		if (section.name[0] == '[') {
			continue;
		} else if ((section.flags & VMAInfo::VM_EXEC)) {
			validateCodePage(&section);
		} else if ((section.flags & VMAInfo::VM_WRITE)) {
			//validateDataPage(&section);
		}
		// No need to validate pages that are only readable
	}

	// TODO count errors or change return value
	return 0;
}

void ProcessValidator::validateCodePage(VMAInfo *vma) {
	std::vector<uint8_t> codevma;
	ElfProcessLoader *binary = nullptr;

	if (this->process->getName().length() >= vma->name.length() &&
	    this->process->getName().compare(
	        this->process->getName().length() - vma->name.length(),
	        vma->name.length(), vma->name) == 0) {
		binary = this->process->getExecLoader();
	} else {
		ElfProcessLoader *lib = this->findLoaderByName(vma->name);
		if (!lib) {
			// TODO find out why libnss* is always mapped to the process space
			// std::cout << COLOR_RED <<
			//    "Warning: Found library in process that was not a dependency "
			//    <<
			//    vma->name << COLOR_RESET << std::endl;
			return;
		}
		binary = lib;
	}

	assert(binary);

	const uint8_t *fileContent = 0;
	const uint8_t *memContent  = 0;
	size_t textsize            = 0;
	size_t bytesChecked        = 0;

	fileContent = binary->textSegmentContent.data();
	textsize    = binary->textSegmentContent.size();

	while (bytesChecked < textsize) {
		// read vma from memory
		codevma = vmi->readVectorFromVA(vma->start + bytesChecked,
		                                vma->end - vma->start - bytesChecked,
		                                pid);
		memContent = codevma.data();

		for (size_t j = 0;
		     j < std::min(textsize - bytesChecked, codevma.size());
		     j++) {
			if (memContent[j] != fileContent[bytesChecked + j]) {
				std::cout << COLOR_RED << COLOR_BOLD
				          << "MISMATCH in code segment!" << COLOR_RESET
				          << std::endl;
				return;
			}
		}
		bytesChecked += codevma.size();

		// An unmapped page can not be modified
		if (bytesChecked < textsize) {
			// std::cout << COLOR_RED << COLOR_BOLD <<
			//	"Some part of the text segment is not mapped in the VM" <<
			//	std::endl << "\t" << "Offset: " << vma->start + bytesChecked <<
			//	COLOR_RESET << std::endl;
			bytesChecked += PAGESIZE;
		}
	}
}

void ProcessValidator::validateDataPage(VMAInfo *vma) {
	std::vector<VMAInfo> range;
	for (auto &section : this->mappedVMAs) {
		if (CHECKFLAGS(section.flags, VMAInfo::VM_EXEC)) {
			range.push_back(section);
		}
	}

	uint64_t counter = 0;
	auto content =
	    vmi->readVectorFromVA(vma->start, vma->end - vma->start, pid);
	uint8_t *data = content.data();
	for (uint32_t i = 0; i < content.size() - 7; i++) {
		uint64_t *value = (uint64_t *)(data + i);
		// if((*value & 0x00007f00000000UL) != 0x00007f0000000000UL){
		//	continue;
		//}
		for (auto &section : range) {
			if ((CHECKFLAGS(section.flags, VMAInfo::VM_EXEC))) {
				if (contained(*value, section.start, section.end)) {
					counter++;
					// std::cout << "Found ptr to: " << section->name <<
					// std::endl;
				}
			}
		}
	}

	std::cout << "Found " << COLOR_RED << COLOR_BOLD << counter << COLOR_RESET
	          << " pointers in section:" << std::endl;
	vma->print();
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
void ProcessValidator::processLoadRel() {
	const std::set<ElfProcessLoader *> mappedLibs = this->getMappedLibs();

	for (auto &lib : mappedLibs) {
		// announce provided symbols
		this->announceSyms(lib);
	}

	for (auto &lib : mappedLibs) {
		// process own relocations
		lib->applyLoadRel(this);
	}
	return;
}

/* Gather all libraries which are mapped into the current Address-Space
 *
 * The dynamic linker has already done the ordering work.
 * The libraries lay in this->mappedVMAs, lowest address first.
 * => Reverse iterate through the mappedVMAs and find the corresponding loader,
 *    gives the loaders in the correct processing order.
 */
const std::set<ElfProcessLoader*> ProcessValidator::getMappedLibs() const {
	std::set<ElfProcessLoader *> ret;
	ElfProcessLoader *loader = nullptr;
	for (auto &vma : this->mappedVMAs) {
		loader = this->findLoaderByName(vma.name);
		if (loader) {
			ret.insert(loader);
		}
	}
	return ret;
}

/* Add the symbols, announced by lib, to the nameRelSymMap
 *
 *  - sweep through all provided symbols of the lib
 *  - if( symbol not yet in map || symbol in map(WEAK) and exported
 * symbol(GLOBAL)
 *      - add to map
 */
void ProcessValidator::announceSyms(ElfProcessLoader *lib) {
	std::vector<RelSym> syms = lib->getProvidedSyms();

	for (auto &it : syms) {
		if (this->relSymMap.find(it.name) == this->relSymMap.end()) {
			this->relSymMap[it.name] = it;
			continue;
		} else {
			RelSym sym = this->relSymMap[it.name];
			// if mapped symbol is WEAK and cur symbol is GLOBAL . overwrite
			if (ELF64_ST_BIND(sym.info) == STB_WEAK &&
			    ELF64_ST_BIND(it.info) == STB_GLOBAL) {
				this->relSymMap[it.name] = it;
			}
		}
	}
	return;
}

/* Print the information for all mapped VMAs */
void ProcessValidator::printVMAs() {
	std::cout << "Currently mapped VMAs:" << std::endl;

	for (auto &it : this->mappedVMAs) {
		it.print();
	}
	return;
}

std::vector<uint8_t> ProcessValidator::getStackContent(
    size_t readAmount) const {
	const VMAInfo *stack = this->findVMAByName("[stack]");
	// get stack content from VM
	// return vmi->readVectorFromVA(stack->start, readAmount, pid);

	return vmi->readVectorFromVA(
	    stack->end - readAmount, readAmount, pid, true);
}

int ProcessValidator::checkEnvironment(const std::map<std::string, std::string> &inputMap) {
	int errors  = 0;
	auto envMap = tm.getEnvForTask(pid);

	// check all input settings
	for (auto &inputPair : inputMap) {
		if (envMap.find(inputPair.first) != envMap.end()) {
			if (envMap[inputPair.first].compare(inputPair.second) == 0) {
				// setting is right
				continue;
			} else {
				// setting is wrong
				errors++;
				std::cout << COLOR_RED
				          << "Found mismatch in environment variables on entry "
				          << inputPair.first << ". Expected: '"
				          << inputPair.second << "', found: '"
				          << envMap[inputPair.first] << "'." << COLOR_NORM
				          << std::endl;
			}
		}
	}
	return errors;
}

/*
 * Find a corresponding ElfProcessLoader for the given vaddr
 */
ElfProcessLoader *ProcessValidator::findLoaderByAddress(const uint64_t addr) const {
	const VMAInfo *vma = findVMAByAddress(addr);
	if (!vma)
		return nullptr;
	return this->findLoaderByName(vma->name);
}

ElfProcessLoader *ProcessValidator::findLoaderByName(const std::string &name) const {
	std::string libname = fs::path(name).filename().string();
	return this->process->findLibByName(libname);
}

const VMAInfo *ProcessValidator::findVMAByName(const std::string &name) const {
	for (auto &vma : this->mappedVMAs) {
		if (vma.name.compare(name) == 0) {
			return &vma;
		}
	}
	return nullptr;
}

const VMAInfo *ProcessValidator::findVMAByAddress(
    const uint64_t address) const {
	for (auto &vma : this->mappedVMAs) {
		if (address >= vma.start && address < vma.end) {
			return &vma;
		}
	}
	return nullptr;
}

/* Find a corresponding SectionInfo for the given vaddr */
SectionInfo *ProcessValidator::getSegmentForAddress(uint64_t vaddr) {
	SectionInfo *ret;

	// find a corresponding loader for the given vaddr
	ElfProcessLoader *loader = this->findLoaderByAddress(vaddr);
	this->lastLoader = loader;
	ret = loader->getSegmentForAddress(vaddr);
	return ret;
}

/* Lazy evaluation of the given address addr
 *
 *   - get corresponding loader/segment for addr
 *   - if ( addr subject to LazyBinding )
 *       - relocate the address
 *       - return 0
 *   - else
 *       - return 1
 */
int ProcessValidator::evalLazy(uint64_t start, uint64_t addr) {
	ElfProcessLoader *loader = 0;

	try {
		// TODO: will be empty, is filled nowhere currently.
		loader = this->addrToLoaderMap.at(start);
	} catch (const std::out_of_range &oor) {
#ifdef DEBUG
		std::cout << "debug:(evalLazy) Couldn't find a corresponding loader "
		          << "for address " << (void *)addr << std::endl;
#endif
		return 1;
	}

	return loader->evalLazy(addr, &this->relSymMap);
}

int ProcessValidator::_validatePage(page_info_t *page) {
	assert(page);

	// TODO optimize this output, such that we don't have to check for stack
	// address here everytime
	if (page->vaddr >= this->stdStackTop && page->vaddr <= this->stdStackBot) {
		std::cout << "Located in stack of "
		          << getNameFromPath(this->process->getExecLoader()->getName()) << std::endl;
		return 0;
	}

	SectionInfo *targetSegment = this->getSegmentForAddress(page->vaddr);

	if (targetSegment == nullptr) {
		std::cout << "Located in heap." << std::endl;
		return 0;
	}

	// check if the targetSegment is a heapSegment (might check name cont. heap)
	// if(targetSegment->index == 0 && targetSegment->segID == 0){
	if (targetSegment->segName.find("<heap>") != std::string::npos) {
		std::cout << "Located in heap of " << targetSegment->segName
		          << ". Skipping..." << std::endl;
		return 0;
	} else {
		std::cout << "Located in "
		          << getNameFromPath(this->lastLoader->getName()) << std::endl;
	}

#ifdef DEBUG
	std::cout << "debug: checking page 0x" << std::hex << page->vaddr
	          << std::dec << std::endl;
#endif

	// TODO: Check what happens, if offset is negative (maybe replace by int64_t
	uint64_t pageOffset = 0;  // offset of page to actual aligned memindex of
	                          // the containing segment
	uint64_t pageIndex = 0;   // offset above in amount of pages (index)
	uint32_t changeCount =
	    0;  // Number of differing bytes in validation process

#ifdef DEBUG
	printf("debug: page->vaddr:0x%lx, memindex=0x%lx\n",
	       page->vaddr,
	       (uint64_t)targetSegment->memindex);
#endif

	pageOffset = (page->vaddr - ((uint64_t)targetSegment->memindex));
	pageIndex =
	    (page->vaddr - ((uint64_t)targetSegment->memindex)) / page->size;

#ifdef DEBUG
	std::cout << "debug: Initialized pageOffset=0x" << pageOffset
	          << ", pageIndex=0x" << pageIndex << std::endl;
#endif

	std::cout << "pageOffset: " << (void *)pageOffset
	          << ", pageIndex: " << (void *)pageIndex << std::endl;

	// get Page from exec
	// check if the loaded procimage already contains the page we just retrieved
	if (targetSegment->size < pageOffset) {
		// This section is not completely loaded
		assert(false);
	}

	// the corresponding page out of our procimage
	uint8_t *loadedPage = targetSegment->index + pageOffset;
	// uint8_t* loadedPage = (execLoader->getImageForAddress(page->vaddr,
	//                                                       pageOffset));
	// execLoader->textSegmentContent.data() + pageOffset;
	if (loadedPage == nullptr)
		return 1;

	// get Page _content_ from VM
	std::vector<uint8_t> pageInMem =
	    vmi->readVectorFromVA(page->vaddr, page->size, pid);

#ifdef DEBUG
	std::cout << "Content of the whitelisted page:" << std::endl;
	std::vector<uint8_t> dummy;
	dummy.insert(std::begin(dummy), loadedPage, (loadedPage + 0x1000));
	printHexDump(&dummy);

	std::cout << "Content of the page in memory:" << std::endl;
	printHexDump(&pageInMem);
/*
for(auto &it : pageInMem) {
    printf("%c", *it);
}
*/
#endif

	// lazy evaluation lock
	// TODO maybe optimize, only search for lazyBinding entry every 8 bytes?
	uint8_t remain = 0;

	// check byte for byte
	for (int32_t i = 0; i < page->size; i++) {
		if (loadedPage[i] == pageInMem[i]) {
#ifdef DEBUG
#ifndef DUMP
			std::cout << COLOR_GREEN << "Address " << COLOR_BOLD << std::hex
			          << (void *)(page->vaddr + i) << COLOR_BOLD_OFF
			          << " is fine." << std::dec << std::endl
			          << COLOR_NORM;
#endif
#ifdef DUMP
			std::cout << "Address 0x" << std::hex << (int)(page->vaddr + i)
			          << " is fine." << std::dec << std::endl;
#endif
#endif
			if (remain > 0)
				remain--;
			continue;
		} else {
			// if we have _not_ written recently due to lazyEval we may write
			if (remain == 0) {
				// Lazy Evaluation TODO this can be optimized by giving the
				// targetSegment->index directly
				if (!this->evalLazy(
				        (uint64_t)targetSegment->memindex,
				        ((uint64_t)targetSegment->memindex) + i + pageOffset)) {
					// Lazy evaluation has been applied. Block the next 8 Bytes
					// from writing!
					remain = 7;
#ifdef DEBUG
					std::cout << "Found change. remain: " << std::hex
					          << (int)remain << std::dec << std::endl;
#endif
					if (loadedPage[i] == pageInMem[i]) {
#ifdef DEBUG
#ifndef DUMP
						std::cout << COLOR_GREEN << "Address " << COLOR_BOLD
						          << std::hex << (void *)(page->vaddr + i)
						          << COLOR_BOLD_OFF << " is fine."
						          << " [Evaluated Lazy]" << std::endl
						          << COLOR_NORM;
#endif
#ifdef DUMP
						std::cout << "Address 0x" << std::hex
						          << (int)(page->vaddr + i)
						          << " is fine. [Evaluated Lazy]" << std::endl;
#endif
#endif
						continue;
					}
				}
			}

			// if we have written recently, the error should be resolved or
			// malicious
			else {
				remain--;
			}

			changeCount++;
#ifndef DUMP
			std::cout << COLOR_RED << "Found mutation at " << COLOR_BOLD
			          << std::hex << (void *)(i + page->vaddr) << COLOR_BOLD_OFF
			          << ". Expected:'" << COLOR_BOLD << "0x"
			          << std::setfill('0') << std::setw(2)
			          << (int)(loadedPage[i]) << COLOR_BOLD_OFF << "', found:'"
			          << COLOR_BOLD << "0x" << std::setw(2)
			          << (int)(pageInMem[i]) << COLOR_BOLD_OFF
			          << "'. Errors = " << std::dec << changeCount << COLOR_NORM
			          << std::endl;
#endif
#ifdef DUMP
			std::cout << "Found mutation at " << std::hex
			          << (void *)(i + page->vaddr) << ". Expected:'"
			          << "0x" << std::setfill('0') << std::setw(2)
			          << (int)(loadedPage[i]) << "', found:'"
			          << "0x" << std::setw(2) << (int)(pageInMem[i])
			          << "'. Change count = " << std::dec << changeCount
			          << std::endl;
#endif
		}
	}

	if (changeCount == 0)
		std::cout << "Page fine." << std::endl;

	return changeCount;
}

int ProcessValidator::validatePage(page_info_t *page) {
	return this->_validatePage(page);
}

std::unordered_map<std::string, RelSym> *ProcessValidator::getSymMap() {
	return &this->relSymMap;
}

RelSym *ProcessValidator::findSymbolByName(const std::string &name) {
	if (this->relSymMap.find(name) != this->relSymMap.end()) {
		return &this->relSymMap[name];
	}
	return nullptr;
}
