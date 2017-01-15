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
}

ProcessValidator::~ProcessValidator() {}

int ProcessValidator::validateProcess() {
	static uint64_t execSize = 0;
	static uint64_t execPageCount = 0;
	static uint64_t dataSize = 0;
	static uint64_t dataPageCount = 0;

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

	std::vector<size_t> summary_counter(20, 0);

	// Check if all mapped VMAs are valid
	for (auto &section : this->process->getMappedVMAs()) {
		if(section.name == "[stack]" || section.name == "[heap]") {
			dataSize += section.end - section.start;
			dataPageCount++;
			summary_counter = summary_counter + this->validateDataPage(&section);
		} else if (section.name[0] == '[') {
			continue;
		} else if ((section.flags & VMAInfo::VM_EXEC)) {
			execSize += section.end - section.start;
			execPageCount++;
			this->validateCodePage(&section);
		} else if ((section.flags & VMAInfo::VM_WRITE)) {
			dataSize += section.end - section.start;
			dataPageCount++;
			summary_counter = summary_counter + this->validateDataPage(&section);
		}
		// No need to validate pages that are only readable,
		// we trust the kernel.
	}

	if(summary_counter[0]) {
		std::cout << "Prozess summary" << ";"
		          << ";" << this->process->getPID()
		          << ";" << this->process->getName()
		          << ";" << summary_counter[ 0]
		          << ";" << summary_counter[ 1]
		          << ";" << summary_counter[ 2]
		          << ";" << summary_counter[ 3]
		          << ";" << summary_counter[ 4]
		          << ";" << summary_counter[ 5]
		          << ";" << summary_counter[ 6]
		          << ";" << summary_counter[ 7]
		          << ";" << summary_counter[ 8]
		          << ";" << summary_counter[ 9]
		          << ";" << summary_counter[10]
		          << ";" << summary_counter[11]
		          << ";" << summary_counter[12]
		          << std::endl;
	}

	// TODO count errors or change return value
	std::cout << "Validated " << execPageCount << " executable sections"
	          << " (" << (execSize / 0x1000) << " pages)"<< std::endl;
	std::cout << "Checked " << dataPageCount << " data sections"
	          << " (" << (dataSize / 0x1000) << " pages)"<< std::endl;
	return 0;
}

void ProcessValidator::validateCodePage(const VMAInfo *vma) const {
	std::vector<uint8_t> codevma;
	ElfUserspaceLoader *binary = nullptr;

	// check if the process name equals the vma name
	// -> use the exec loader and not some library loader
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


class PagePtrInfo {
public:

PagePtrInfo(Process* process, const VMAInfo *fromVMA, const VMAInfo &toVMA)
	:
	count{0},
	counter(20, 0),
	ptrs{},
	process{process},
	data{nullptr},
	fromVMA{fromVMA},
	toVMA{toVMA} {

	if (fromVMA->name[0] != '[') {
		this->fromLoader = this->process->findLoaderByFileName(fromVMA->name);
	} else {
		this->fromLoader = this->process->getExecLoader();
	}
	this->toLoader = this->process->findLoaderByFileName(toVMA.name);

	if (this->toLoader != nullptr) {
		this->data = this->toLoader->getTextSegment().data();
	}
}

~PagePtrInfo() = default;

uint32_t getCount() {
	return count;
}

void addPtr(uint64_t where, uint64_t addr) {
	this->count += 1;
	this->ptrs[addr].insert(where);
}

void printSummary() {
	if(counter[0]) {
		std::cout << "Mapping summary" << ";"
		          << ";" << this->process->getPID()
		          << ";" << this->process->getName()
		          << ";" << this->fromVMA->name
		          << ";" << this->toVMA.name
		          << ";" << counter[ 0]
		          << ";" << counter[ 1]
		          << ";" << counter[ 2]
		          << ";" << counter[ 3]
		          << ";" << counter[ 4]
		          << ";" << counter[ 5]
		          << ";" << counter[ 6]
		          << ";" << counter[ 7]
		          << ";" << counter[ 8]
		          << ";" << counter[ 9]
		          << ";" << counter[10]
		          << ";" << counter[11]
		          << ";" << counter[12]
		          << std::endl;
	}
}

std::vector<size_t> showPtrs(VMIInstance *vmi, uint32_t pid) {
	//std::cout << "Found " << count << " pointers:" << std::endl;
	uint64_t callAddr = 0;
	bool printKnown = false;
	for (auto &ptr : ptrs) {
		this->counter[0]++;
		this->counter[1] += ptr.second.size();
		bool valid = false;

		auto toSec = this->toLoader->elffile->findSectionByOffset(ptr.first - toVMA.start);
		auto symname = this->process->symbols.getElfSymbolName(ptr.first);


		if (symname != "") {
			this->counter[2]++;
			if (printKnown) {
				std::cout << COLOR_GREEN << "Pointer to Symbol:"
				          << "\t" << symname << std::endl << COLOR_NORM;
			}
			continue;
		}

		if(!this->toLoader && !toVMA.name.empty()){
			this->counter[3]++;
			if (printKnown) {
				std::cout << COLOR_GREEN << "Pointer to Plain File:"
				          << "\t" << toVMA.name << std::endl << COLOR_NORM;
			}
			continue;
		}

		if(!toSec) {
			this->counter[4]++;
			if (printKnown) {
				std::cout << COLOR_MARGENTA << "Pointer to no section"
				          << std::endl << COLOR_NORM;
			}
			continue;
		}

		if ((ptr.first - toVMA.start - toSec->offset) == 0) {
			this->counter[5]++;
			if (printKnown) {
				std::cout << COLOR_GREEN << "Pointer to start of Section:"
				          << "\t" << toSec->name << std::endl << COLOR_NORM;
			}
			continue;
		}

		if (printKnown) {
			if (toSec->name == ".dynstr"){
				std::string str = std::string((char*) toSec->index + (ptr.first - toVMA.start) - toSec->memindex);
				std::cout << COLOR_GREEN << "Pointer to String:"
				          << "\t" << str << std::endl << COLOR_NORM;
				continue;
			}

			if(toSec->name == ".dynsym"){
				std::string str = this->toLoader->elffile->dynSymbolName(ptr.first - toVMA.start - toSec->offset);
				std::cout << COLOR_GREEN << "Pointer to Symbol:"
				          << "\t" << str << std::endl << COLOR_NORM;
				continue;
			}
		}

		std::unordered_set<std::string> allowedSections = {
			".data.rel.ro",
			".data.rel.ro.local",
			".dynamic",
			".dynstr",
			".dynsym",
			".eh_frame",
			".eh_frame_hdr",
			".gcc_except_table",
			".gnu.hash",
			".gnu.version",
			".gnu.version_d",
			".gnu.version_r",
			".got",
			".got.plt",
			".hash",
			".interp",
			".note.ABI-tag",
			".note.gnu.build-id",
			".plt",
			".plt.got",
			".rela.dyn",
			".rela.plt",
			".rodata",
			"__libc_IO_vtables",
			"__libc_thread_freeres_fn"
		};

		if(allowedSections.find(toSec->name) != allowedSections.end()) {
			this->counter[6]++;
			if (printKnown) {
				std::cout << COLOR_MARGENTA << "Pointer to Section:"
				          << "\t" << toSec->name << std::endl << COLOR_NORM;
			}
			continue;
		}

		if (toSec->name == ".text") {
			if (toLoader->elffile->entryPoint() == (ptr.first - toVMA.start)){
				this->counter[7]++;
				if (printKnown) {
					std::cout << COLOR_GREEN << "Pointer to Entry Point:"
					          << std::endl << COLOR_NORM;
				}
				continue;
			}
			if (this->data) {
				if(!isValidInstruction(this->data,
				                       ptr.first - toVMA.start,
				                       toVMA.start)) {
					this->counter[8]++;
					std::cout << COLOR_RED << COLOR_BOLD
					          << "Pointer to invalid instruction!"
					          << COLOR_RESET << std::endl;
				}else{
					valid = true;
				}
				if(valid &&
				   (callAddr = isReturnAddress(this->data,
				                               ptr.first - toVMA.start,
				                               toVMA.start, vmi, pid))) {
					this->counter[9]++;
					if (printKnown) {
						uint64_t retFunc = this->process->symbols.getContainingSymbol(ptr.first);
						std::string retFuncName = this->process->symbols.getElfSymbolName(retFunc);

						std::cout << COLOR_GREEN << "Return Address to: "
						          << "\t" << retFuncName << std::endl << COLOR_NORM;
						if((callAddr) > 1) {
							std::string callFuncName = this->process->symbols.getElfSymbolName(callAddr);
							std::cout << COLOR_GREEN << "\tPreceeding call: "
							          << "\t" << callFuncName << std::endl << COLOR_NORM;
						}
					}
					continue;
				}
			}

			uint64_t func = this->process->symbols.getContainingSymbol(ptr.first);
			std::string funcName = this->process->symbols.getElfSymbolName(func);

			this->counter[10]++;
			std::cout << COLOR_MARGENTA << "Unknown Pointer:"
			          << "\t" << funcName << std::hex
			          << " (" << "offset: " << ptr.first - func << ")"
			          << std::dec << std::endl << COLOR_NORM;

			if(this->data && valid){
				uint64_t start = func - toVMA.start;
				if(!isIntendedInstruction(this->data + start,
				                          ptr.first - func,
				                          toVMA.start + start)) {
					this->counter[11]++;
					std::cout << COLOR_RED << COLOR_BOLD
					          << "\tPointer to unintended instruction!"
					          << COLOR_RESET << std::endl;
				}
				start = ptr.first - toVMA.start;
				uint64_t len = this->toLoader->getTextSegment().size() - start;
				auto ret = printInstructions(this->data + start, len, toVMA.start + start);
				size_t nr_instr = std::get<0>(ret);
				bool end_valid = std::get<1>(ret);
				std::string instr = std::get<2>(ret);
				std::cout << COLOR_RED << COLOR_BOLD
				          << "\tPointing to gadget of " << nr_instr
				          << " instructions" << std::endl;
				if(end_valid) {
					std:: cout << "\tEnding in an invalid instruction!" << std::endl;
				}
				for(auto && str : split(instr, '\n')){
					std::cout << "\t\t" << str << std::endl;
				}
				std::cout << COLOR_RESET;
			}


		}

		std::cout << COLOR_RED
		          << "Pointer to 0x" << std::setfill('0') << std::setw(8)
		          << std::hex << ptr.first - toVMA.start << " ( 0x"
		          << ptr.first << " ) " << std::dec;
		if (toSec) {
			std::cout << "\tSection: " << toSec->name;
		}
		std::cout << std::endl;

		for (auto &where : ptr.second) {
			std::cout << "\tFrom: 0x" << std::setfill('0') << std::setw(8)
			          << std::hex << where << " ( 0x"
			          << fromVMA->start + ptr.first << " ) " << std::dec;
			const SectionInfo* fromSec = 0;
			if(this->fromLoader && fromVMA->ino != 0) {
				fromSec = this->fromLoader->elffile->findSectionByOffset(fromVMA->off * 0x1000 + where);
			}
			if(fromSec) {
				std::cout << "\tSection: " << fromSec->name;
			}else if (fromVMA->ino == 0) {
				std::cout << "\tSection: .bss (dynamic)";
			} else {
				std::cout << "\tPlain File: " << fromVMA->name << " : ";
				fromVMA->print();
			}
			std::cout << std::endl;
		}
		std::cout << COLOR_NORM;
		this->counter[12]++;
	}
	return this->counter;
}


protected:
	uint32_t count;
	std::vector<size_t> counter;
	std::map<uint64_t, std::set<uint64_t>> ptrs;
	Process *process;
	ElfLoader *fromLoader;
	ElfLoader *toLoader;
	const uint8_t *data;
	const VMAInfo *fromVMA;
	const VMAInfo toVMA;
};

std::vector<size_t> ProcessValidator::validateDataPage(const VMAInfo *vma) const {
	// TODO: see if the start address of the mapping
	// is the address of GOT, then validate if symbols and
	// references are correct. elffile64 does the patching.

	std::vector<std::pair<VMAInfo, PagePtrInfo>> range;

	for (auto &toVMA : this->process->getMappedVMAs()) {
		if (CHECKFLAGS(toVMA.flags, VMAInfo::VM_EXEC)) {
			range.push_back(
				std::make_pair(
					toVMA,
					PagePtrInfo(process, vma, toVMA)
				)
			);
		}
	}

	auto content = vmi->readVectorFromVA(vma->start,
	                                     vma->end - vma->start,
	                                     this->pid, true);
	if (content.size() <= sizeof(uint64_t)) {
		// This page is currently not mapped
		return std::vector<size_t>(20, 0);
	}

	uint8_t *data = content.data();

	for (uint64_t i = 0; i < content.size() - sizeof(uint64_t); i++) {
		// create pointer to current sec
		uint64_t *value = reinterpret_cast<uint64_t *>(data + i);

		// the pointer is never invalid as we're walking
		// over memory to verify.
		if (*value == 0) {
			continue;
		}

		for (auto &mapping : range) {
			if (CHECKFLAGS(mapping.first.flags, VMAInfo::VM_EXEC)) {
				if (vma->name == mapping.first.name) {
					// points to the same mapping
					break;
				}

				if (IN_RANGE(*value, mapping.first.start + 1, mapping.first.end)) {
					if (*value == mapping.first.start + 0x40) {
						// Pointer to PHDR
						break;
					}

					mapping.second.addPtr(i, *value);
				}
			}
		}
	}

	// resolve-trampoline:
	// sysdeps/x86_64/dl-trampoline.S:64
	// LD_BIND_NOW forces load-time relocations.

	std::vector<size_t> summary_counter(20, 0);

	for (auto &mapping : range) {
		std::vector<size_t> counter = mapping.second.showPtrs(this->vmi, this->pid);

		summary_counter = summary_counter + counter;
		if(counter[12]) {
			std::cout << "Pointers from " << ((vma->name[0] == '[') ? process->getName() + " " + vma->name :vma->name)
			          << " to " << mapping.first.name << std::endl;
		}
		mapping.second.printSummary();
	}
	if(summary_counter[1]) {
		std::cout << "Found " << COLOR_RED << COLOR_BOLD
		      << std::setfill(' ') << std::setw(5)
		      << summary_counter[12] << COLOR_RESET << " unknown ("
		      << COLOR_GREEN << std::setw(5) << summary_counter[1] << COLOR_RESET << ")"
		      << " pointers: ";
		vma->print();
	}

	if(summary_counter[0]) {
		std::cout << "Section summary" << ";"
		          << ";" << this->process->getPID()
		          << ";" << this->process->getName()
		          << ";" << vma->name
		          << ";" << summary_counter[ 0]
		          << ";" << summary_counter[ 1]
		          << ";" << summary_counter[ 2]
		          << ";" << summary_counter[ 3]
		          << ";" << summary_counter[ 4]
		          << ";" << summary_counter[ 5]
		          << ";" << summary_counter[ 6]
		          << ";" << summary_counter[ 7]
		          << ";" << summary_counter[ 8]
		          << ";" << summary_counter[ 9]
		          << ";" << summary_counter[10]
		          << ";" << summary_counter[11]
		          << ";" << summary_counter[12]
		          << std::endl;
	}

	return summary_counter;

}


std::vector<uint8_t> ProcessValidator::getStackContent(
    size_t readAmount) const {
	const VMAInfo *stack = process->findVMAByName("[stack]");

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

} // namespace kernint
