#include "processvalidator.h"

#include <algorithm>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unordered_map>

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include "elffile.h"
#include "elfkernelloader.h"
#include "elfuserspaceloader.h"
#include "taskmanager.h"


namespace kernint {

// TODO: retrieve paths from command line parameters
ProcessValidator::ProcessValidator(ElfKernelLoader *kl,
                                   Process *process,
                                   VMIInstance *vmi)
    :
	vmi{vmi},
	kl{kl},
	process{process} {

	std::cout << "ProcessValidator got: " << this->process->getName() << std::endl;

	this->pid = process->getPID();
	std::cout << "[PID] " << this->pid << std::endl;

	// process load-time relocations
	std::cout << "Processing load-time relocations..." << std::endl;
	this->process->processLoadRel();
}

ProcessValidator::~ProcessValidator() {}

int ProcessValidator::validateProcess() {
	// check if all mapped pages are known
	std::cout << COLOR_GREEN
	          << "Starting page validation ..."
	          << COLOR_RESET << std::endl;

	PageMap executablePageMap = this->vmi->getPages(this->pid);
	for (auto &page : executablePageMap) {
		// check if page is contained in VMAs
		if (!(page.second->vaddr & 0xffff800000000000) &&
		    !this->process->findVMAByAddress(page.second->vaddr)) {
			std::cout << COLOR_RED << COLOR_BOLD
			          << "Found page that has no corresponding VMA: "
			          << std::hex << page.second->vaddr << std::dec
			          << COLOR_RESET << std::endl;
		}
	}
	this->vmi->destroyMap(executablePageMap);

	// Check if all mapped VMAs are valid
	for (auto &section : this->process->getMappedVMAs()) {
		if (section.name[0] == '[') {
			continue;
		} else if ((section.flags & VMAInfo::VM_EXEC)) {
			this->validateCodePage(&section);
		} else if ((section.flags & VMAInfo::VM_WRITE)) {
			this->validateDataPage(&section);
		}
		// No need to validate pages that are only readable,
		// we trust the kernel.
	}

	// TODO count errors or change return value
	return 0;
}

void ProcessValidator::validateCodePage(const VMAInfo *vma) const {
	std::vector<uint8_t> codevma;
	ElfUserspaceLoader *binary = nullptr;

	if (this->process->getName().length() >= vma->name.length() &&
	    this->process->getName().compare(this->process->getName().length()
	                                     - vma->name.length(),
	                                     vma->name.length(),
	                                     vma->name) == 0) {
		binary = this->process->getExecLoader();
	} else {
		ElfUserspaceLoader *lib = this->process->findLoaderByFileName(vma->name);
		if (!lib) {
			// occurs when it's library is mapped but is not a dependency
			// TODO find out why libnss* is always mapped to the process space
			std::cout << COLOR_RED << "Warning: Found library in process "
			                          "that was not a dependency "
			          << vma->name << COLOR_RESET << std::endl;
			return;
		}
		binary = lib;
	}

	assert(binary);

	const uint8_t *fileContent = nullptr;
	const uint8_t *memContent  = nullptr;
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
				          << "MISMATCH in code segment! " << vma->name
				          << COLOR_RESET
				          << std::endl;

				displayChange(memContent, fileContent + bytesChecked, j, textsize);
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

void ProcessValidator::validateDataPage(const VMAInfo *vma) const {
	// TODO: see if the start address of the mapping
	// is the address of GOT, then validate if symbols and
	// references are correct. elffile64 does the patching.

	std::vector<VMAInfo> range;
	for (auto &section : this->process->getMappedVMAs()) {
		if (CHECKFLAGS(section.flags, VMAInfo::VM_EXEC)) {
			range.push_back(section);
		}
	}

	uint64_t counter = 0;
	auto content = vmi->readVectorFromVA(vma->start, vma->end - vma->start, this->pid, true);
	if (content.size() <= sizeof(uint64_t)) {
		// This page is currently not mapped
		return;
	}

	uint8_t *data = content.data();

	for (uint32_t i = 0; i < content.size() - sizeof(uint64_t); i++) {
		// create pointer to current sec
		uint64_t *value = reinterpret_cast<uint64_t *>(data + i);

		// the pointer is never invalid as we're walking
		// over memory to verify.
		if (*value == 0) {
			continue;
		}

		for (auto &section : range) {
			if ((CHECKFLAGS(section.flags, VMAInfo::VM_EXEC))) {
				if (IN_RANGE(*value, section.start, section.end)) {
					counter++;
					std::cout << "Found ptr to: " << section.name << std::endl;
				}
			}
		}
	}

	// resolve-trampoline:
	// sysdeps/x86_64/dl-trampoline.S:64
	// LD_BIND_NOW forces load-time relocations.

	std::cout << "Found " << COLOR_RED << COLOR_BOLD
	          << counter << COLOR_RESET
	          << " pointers in section:" << std::endl;
	vma->print();
}


std::vector<uint8_t> ProcessValidator::getStackContent(
    size_t readAmount) const {
	const VMAInfo *stack = process->findVMAByName("[stack]");
	// get stack content from VM
	// return vmi->readVectorFromVA(stack->start, readAmount, this->pid);

	return vmi->readVectorFromVA(stack->end - readAmount, readAmount, this->pid, true);
}

int ProcessValidator::checkEnvironment(const std::map<std::string, std::string> &inputMap) {
	int errors  = 0;
	auto envMap = this->kl->getTaskManager()->getEnvForTask(this->pid);

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



// TODO: obsolete?
[[ deprecated ]]
int ProcessValidator::validatePage(page_info_t *page) {
	assert(page);

	// TODO optimize this output, such that we don't have to check for stack
	// address here everytime
	if (page->vaddr >= this->stdStackTop && page->vaddr <= this->stdStackBot) {
		std::cout << "Located in stack of "
		          << getNameFromPath(this->process->getExecLoader()->getName()) << std::endl;
		return 0;
	}

	SectionInfo *targetSection = this->process->getSegmentForAddress(page->vaddr);

	if (targetSection == nullptr) {
		std::cout << "Located in heap." << std::endl;
		return 0;
	}

	// check if the targetSection is a heapSegment (might check name cont. heap)
	// if(targetSection->index == 0 && targetSection->segID == 0){
	if (targetSection->name.find("<heap>") != std::string::npos) {
		std::cout << "Located in heap of " << targetSection->name
		          << ". Skipping..." << std::endl;
		return 0;
	} else {
		std::cout << "Located somewhere else (last loader?)" << std::endl;
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
	       (uint64_t)targetSection->memindex);
#endif

	pageOffset = (page->vaddr - ((uint64_t)targetSection->memindex));
	pageIndex =
	    (page->vaddr - ((uint64_t)targetSection->memindex)) / page->size;

#ifdef DEBUG
	std::cout << "debug: Initialized pageOffset=0x" << pageOffset
	          << ", pageIndex=0x" << pageIndex << std::endl;
#endif

	std::cout << "pageOffset: " << (void *)pageOffset
	          << ", pageIndex: " << (void *)pageIndex << std::endl;

	// get Page from exec
	// check if the loaded procimage already contains the page we just retrieved
	if (targetSection->size < pageOffset) {
		// This section is not completely loaded
		assert(false);
	}

	// the corresponding page out of our procimage
	uint8_t *loadedPage = targetSection->index + pageOffset;
	// uint8_t* loadedPage = (execLoader->getImageForAddress(page->vaddr,
	//                                                       pageOffset));
	// execLoader->textSegmentContent.data() + pageOffset;
	if (loadedPage == nullptr)
		return 1;

	// get Page _content_ from VM
	std::vector<uint8_t> pageInMem = vmi->readVectorFromVA(page->vaddr, page->size, this->pid);

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
				// targetSection->index directly
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

} // namespace kernint
