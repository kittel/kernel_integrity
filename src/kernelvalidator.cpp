#include "kernelvalidator.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <memory>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <unordered_map>

#include "elfkernelspaceloader.h"
#include "elfkernelloader.h"
#include "elfmoduleloader.h"
#include "helpers.h"
#include "kernel_headers.h"


KernelValidator::KernelValidator(ElfKernelLoader *kernelLoader,
                                 const std::string &targetsFile)
	:
	kernelLoader(kernelLoader),
	stackAddresses() {

	this->kernelLoader->loadAllModules();
	this->kernelLoader->symbols.updateRevMaps();

	if (targetsFile.length() > 0) {
		// Read targets of calls
		std::ifstream infile;
		infile.open(targetsFile, std::ios::in|std::ios::binary);
		uint64_t callAddr;
		uint64_t callDest;

		while (!infile.eof()) {
			infile.read((char*)&callAddr, sizeof(callAddr));
			if (infile.eof()) break;
			infile.read((char*)&callDest, sizeof(callDest));

			this->callTargets.insert(
				std::pair<uint64_t,uint64_t>(callAddr, callDest));
		}
		infile.close();
	}

	this->setOptions();
}

KernelValidator::~KernelValidator() {}

void KernelValidator::setOptions(bool lm, bool cv, bool pe){
	this->options.loopMode = lm;
	this->options.codeValidation = cv;
	this->options.pointerExamination = pe;
}

ElfKernelLoader *KernelValidator::loadKernel(const std::string &dirName) {
	std::string kernelName = dirName;
	kernelName.append("/vmlinux");

	ElfFile *kernelFile = ElfFile::loadElfFile(kernelName);

	ElfKernelLoader *kernelLoader = kernelFile->parseKernel();

	kernelLoader->setKernelDir(dirName);
	kernelLoader->parseSystemMap();
	kernelLoader->initImage();

	return kernelLoader;
}

uint64_t KernelValidator::validatePages() {
	uint64_t iterations = 0;

	do {
		iterations++;

		globalCodePtrs = 0;
		if (this->options.pointerExamination) {
			//Validate all Stacks
			this->updateStackAddresses();
			for (auto &stack : this->stackAddresses) {
				std::vector<uint8_t> pageInMem = this->kernelLoader->vmi->readVectorFromVA(stack.first, 0x2000);
				this->validateStackPage(pageInMem.data(),
				                        stack.first,
				                        stack.second);
			}
		}

		PageMap executablePageMap = this->kernelLoader->vmi->getPages(0);

		for (auto &page : executablePageMap) {
			if ((page.second->vaddr & 0xff0000000000) == 0x8800000000000){
				continue;
			}
			this->validatePage(page.second);
		}

		std::cout << COLOR_GREEN << COLOR_BOLD
		          << "Done validating pages"
		          << COLOR_BOLD_OFF << COLOR_NORM << std::endl;

		this->kernelLoader->vmi->destroyMap(executablePageMap);
	} while (this->options.loopMode);

	return iterations;
}


void KernelValidator::validatePage(page_info_t * page) {
	//std::cout << "Try to verify page: " << std::hex <<
	//             page->vaddr << std::dec << std::endl;

	if ((page->vaddr & 0xff0000000000) == 0xc900000000000){
		// TODO investigate, what are these c9 addresses
		return;
	}

	ElfKernelspaceLoader *module = kernelLoader->getModuleForAddress(page->vaddr);
	//assert(module);
	if (!module) {
		if(this->kernelLoader->vmi->isPageExecutable(page)){
			std::cout << COLOR_MARGENTA << COLOR_BOLD <<
			"No Module found for address: " << std::hex <<
			page->vaddr << std::dec << COLOR_RESET << std::endl;
		}
	} else if (this->options.codeValidation &&
	           module->isCodeAddress(page->vaddr)) {
		this->validateCodePage(page, module);
	}
	else if (this->options.pointerExamination &&
	         module->isDataAddress(page->vaddr)) {
		if (this->kernelLoader->vmi->isPageExecutable(page)) {
			static bool execData = false;
			if (!execData) {
				std::cout << COLOR_RED << COLOR_BOLD <<
				"Warning: Executable Data Page" <<
				COLOR_NORM << COLOR_BOLD_OFF << std::endl;
				execData = true;
			}
		}

		this->validateDataPage(page, module);
	}
}

void KernelValidator::validateStackPage(uint8_t* memory,
                                        uint64_t stackBottom,
                                        uint64_t stackEnd) {
	std::stringstream ss;
	bool stackInteresting = false;

	ss << std::endl
	   << COLOR_BOLD << COLOR_GREEN << "Checking stack at: " << std::hex
	   << stackBottom << std::dec << COLOR_NORM << COLOR_BOLD_OFF << std::endl;

	std::map<uint64_t, uint64_t> returnAddresses;

	// Reset unused part of Stack to Zero
	// TODO

	// Go through every byte and check if it contains a kernel pointer
	for (int32_t i = stackEnd % 0x2000; i < 0x2000 - 4; i++) {
		uint32_t* intPtr = (uint32_t*)(memory + i);

		// Check if this could be a valid kernel address.
		if (*intPtr != (uint32_t)0xffffffff)
			continue;

		// The first 4 byte could belong to a kernel address.
		uint64_t* longPtr = (uint64_t*)(intPtr - 1);
		if (*longPtr == (uint64_t)0xffffffffffffffffL) {
			i += 8;
			continue;
		}

		ElfKernelspaceLoader *elfloader = kernelLoader->getModuleForAddress(*longPtr);
		if (!elfloader || !elfloader->isCodeAddress(*longPtr)) {
			continue;
		}

		if (kernelLoader->symbols.isFunction(*longPtr))
			continue;

		if (kernelLoader->symbols.isSymbol(*longPtr))
			continue;

		uint64_t offset = *longPtr - elfloader->textSegment.memindex;

		if (offset > elfloader->getTextSegment().size()) {
			stackInteresting = true;
			ss << std::hex << COLOR_RED << COLOR_BOLD
			   << "Found possible malicious pointer: 0x" << *longPtr
			   << " ( @ 0x" << i - 4 + stackBottom << " )"
			   << " Pointing to code after initialized content" << COLOR_NORM
			   << COLOR_BOLD_OFF << std::dec << std::endl;
			continue;
		}

		returnAddresses[i - 4 + stackBottom] = *longPtr;
	}

	uint64_t oldRetFunc = 0;
	std::string oldRetFuncName;

	for (auto& retAddr : returnAddresses) {
		ElfKernelspaceLoader* elfloader = kernelLoader->getModuleForAddress(retAddr.second);

		// Return Address (Stack)
		uint64_t offset = retAddr.second - elfloader->textSegment.memindex;

		std::vector<uint8_t> pageInMem = this->kernelLoader->vmi->readVectorFromVA(
			elfloader->textSegment.memindex, offset + 0x40);

		uint64_t callAddr = isReturnAddress(elfloader->textSegmentContent.data(), offset, elfloader->textSegment.memindex);

		if (!callAddr) {
			stackInteresting = true;
			ss << std::hex << COLOR_RED << COLOR_BOLD
			   << "Found possible malicious pointer: 0x" << retAddr.second
			   << " ( @ 0x" << retAddr.first << " )" << std::endl
			   << " Pointing to module: " << elfloader->getName() << COLOR_NORM
			   << COLOR_BOLD_OFF << std::dec << std::endl;
		}

		uint64_t retFunc = kernelLoader->symbols.getContainingSymbol(retAddr.second);

		std::string retFuncName = kernelLoader->symbols.getModuleSymbolName(retFunc);

		ss << std::hex << COLOR_GREEN << COLOR_BOLD << "return address: 0x"
		   << retAddr.second << " ( @ 0x" << retAddr.first << " )" << std::endl
		   << "\t-> " << retFuncName << " ( " << retFunc << " ) " << COLOR_NORM
		   << COLOR_BOLD_OFF << std::dec << std::endl;

		// The first return address is always allowed
		if (oldRetFunc == 0) {
			oldRetFunc     = retFunc;
			oldRetFuncName = retFuncName;
			continue;
		}

		// The return Address points to the function that
		// was previously called
		if (oldRetFunc == callAddr) {
			oldRetFunc     = retFunc;
			oldRetFuncName = retFuncName;
			continue;
		}

		if ((oldRetFuncName == "__schedule_kernel" &&
		     retFuncName == "kthread_kernel") ||
		    (oldRetFuncName == "kthread_kernel" && retFuncName == "do_exit") ||
		    (oldRetFuncName == "do_exit" && retFuncName == "ret_from_fork")) {

			oldRetFunc     = retFunc;
			oldRetFuncName = retFuncName;
			continue;
		}

		// Check common stack frames for 3.8
		// Make this nicer...
		// if ((i - 4 == 0x1f50 && *longPtr == 0xffffffff816d48ac) ||
		//	(i - 4 == 0x1ed0 && *longPtr == 0xffffffff8107d360) ||
		//	*longPtr == 0xffffffff816cb199){
		//	oldRetFunc = retFunc;
		//	continue;
		//}

		if (this->callTargets.size() > 0) {
			auto call = (this->callTargets.upper_bound(retAddr.second)--);

			while (call->first > retAddr.second) {
				call--;
			}
			uint64_t addressOfCall = call->first;
			auto boundaries        = this->callTargets.equal_range(addressOfCall);
			bool found             = false;

			for (auto& element = boundaries.first; element != boundaries.second;
			     element++) {
				if (element->second == oldRetFunc) {
					oldRetFunc     = retFunc;
					oldRetFuncName = retFuncName;
					found          = true;
					break;
				}
			}
			if (found)
				continue;
		}

		stackInteresting = true;
		ss << std::hex << "callAddr:      " << callAddr << " "
		   << kernelLoader->symbols.getModuleSymbolName(callAddr) << std::endl
		   << "retFunc:       " << retFunc << " " << retFuncName << std::endl
		   << "oldRetFunc:    " << oldRetFunc << " " << oldRetFuncName
		   << std::endl
		   << std::dec << std::endl;

		ss << std::hex << COLOR_BLUE << COLOR_BOLD
		   << "Unvalidated return address: 0x" << retAddr.second << " ( @ 0x"
		   << retAddr.first << " )" << std::endl
		   << "\t-> " << retFuncName << " ( " << retFunc << " ) " << COLOR_NORM
		   << COLOR_BOLD_OFF << std::dec << std::endl
		   << std::endl;

		oldRetFunc     = retFunc;
		oldRetFuncName = retFuncName;
	}
	if (stackInteresting) {
		// TODO Output disabled as currently unneccessary
		//std::cout << ss.rdbuf();
	}
}

bool KernelValidator::isValidJmpLabel(uint8_t* pageInMem,
                                      uint64_t codeAddress,
                                      int32_t i,
                                      ElfKernelspaceLoader* elf) {
	auto entry = elf->jumpEntries.find(codeAddress);

	if (entry != elf->jumpEntries.end()) {
		// Check if the entry is currently disabled
		if ((memcmp(pageInMem + i, this->kernelLoader->pvpatcher.pvstate->ideal_nops[5], 5) == 0 ||
		     memcmp(pageInMem + i, this->kernelLoader->pvpatcher.pvstate->ideal_nops[9], 5) == 0)) {
			return true;
		}
		// Otherwise check if the destination matches
		int32_t jmpDestInt = 0;
		memcpy(&jmpDestInt, pageInMem + i + 1, 4);

		if (pageInMem[i] == (uint8_t)0xe9 && entry->second == jmpDestInt) {
			return true;
		}
	}
	return false;
}

void KernelValidator::validateCodePage(page_info_t *page,
                                       ElfKernelspaceLoader *elf) {
	assert(page);
	assert(elf);

	uint32_t pageOffset = 0;
	uint32_t pageIndex = 0;
	pageOffset = (page->vaddr - ((uint64_t)elf->textSegment.memindex & 0xffffffffffff));
	pageIndex = (page->vaddr - ((uint64_t)elf->textSegment.memindex & 0xffffffffffff)) /
	page->size;

	// std::cout << "Validating: " << elf->getName() <<
	//             " Page: " << std::hex << pageIndex
	//                       << std::dec << std::endl;

	// const auto time2_start = std::chrono::system_clock::now();

	// get Page from module
	if (elf->textSegmentContent.size() < pageOffset) {
		// This section is not completely loaded
		assert(false);
	}
	uint8_t* loadedPage = elf->textSegmentContent.data() + pageOffset;
	// get Page from memdump
	std::vector<uint8_t> pageInMem = this->kernelLoader->vmi->readVectorFromVA(page->vaddr, page->size);

	uint32_t changeCount = 0;

	for (int32_t i = 0; i < page->size; i++) {
		if (loadedPage[i] == pageInMem[i]) {
			continue;
		}

		// Show first changed byte only thus continue
		// if last byte also is different
		if (i > 0 && loadedPage[i - 1] != pageInMem[i - 1]) {
			continue;
		}

		uint64_t unkCodeAddress = (uint64_t)elf->textSegment.memindex + pageOffset + i;
		// Ignore hypercall_page for now
		if ((unkCodeAddress & 0xfffffffffffff000) == 0xffffffff81001000) {
			continue;
		}

		// Check for ATOMIC_NOP
		if (i > 1 && memcmp(loadedPage + i - 2,
		                    this->kernelLoader->pvpatcher.pvstate->ideal_nops[5], 5) == 0 &&
		    memcmp(pageInMem.data() + i - 2,
		           this->kernelLoader->pvpatcher.pvstate->ideal_nops[9], 5) == 0) {
			i += 5;
			continue;
		}

		if (i <= 1 && (((loadedPage[i] == (uint8_t)0x66 &&
		                 pageInMem[i] == (uint8_t)0x90) ||
		                (loadedPage[i] == (uint8_t)0x90 &&
		                 pageInMem[i] == (uint8_t)0x66)))) {
			continue;
		}

		if (memcmp(loadedPage + i, "\x0f\x1f\x44\x00\x00", 5) == 0 &&
		    memcmp(pageInMem.data() + i, "\x66\x66\x66\x66\x90", 5) == 0) {
			i += 5;
			continue;
		}

		if (isValidJmpLabel(pageInMem.data(), unkCodeAddress, i, elf)) {
			i += 5;
			continue;
		}

		if (i > 0 && loadedPage[i - 1] == (uint8_t)0xe8) {
			uint32_t jmpDestElfInt = 0;
			memcpy(&jmpDestElfInt, loadedPage + i + 1, 4);

			uint64_t elfDestAddress = (uint64_t)elf->textSegment.memindex +
			                          pageOffset + i + jmpDestElfInt + 5;

			auto kernelLoader = dynamic_cast<ElfKernelLoader*>(elf);
			if (kernelLoader) {
				if (kernelLoader->genericUnrolledAddress == elfDestAddress) {
					i += 4;
					continue;
				}
			} else if (dynamic_cast<ElfModuleLoader*>(elf)) {
				uint32_t jmpDestMemInt = 0;
				memcpy(&jmpDestMemInt, pageInMem.data() + i + 1, 4);

				// TODO Why is this commented out?
				// uint64_t memDestAddress = (uint64_t)
				// elf->textSegment.memindex + pageOffset + i + jmpDestMemInt + 5;
				// std::cout << "Error: " << std::endl;
				// std::cout << "Jump in mem to: " << std::hex
				//           << memDestAddress << std::dec << std::endl;
				// std::cout << "Offset: " << std::hex
				//           << jmpDestMemInt << std::dec << std::endl;
				// std::cout << "Jump in elf to: " << std::hex
				//           << elfDestAddress << std::dec << std::endl;
				// std::cout << "Offset: " << std::hex
				//           << jmpDestElfInt << std::dec << std::endl;
				// std::cout << "Difference: " << std::hex
				//           << elfDestAddress - memDestAddress
				//           << std::dec << std::endl;
			}
		}

		// Handle smp locks
		if ((loadedPage[i] == (uint8_t)0x3e && pageInMem[i] == (uint8_t)0xf0) ||
		    (loadedPage[i] == (uint8_t)0xf0 && pageInMem[i] == (uint8_t)0x3e)) {
			// TODO get smpOffsets
			if (elf->smpOffsets.find(i + pageOffset) != elf->smpOffsets.end()) {
				continue;
			}
		}

		// TODO investigate
		if (memcmp(loadedPage + i, "\xe9\x00\x00\x00\x00", 5) == 0 &&
		    memcmp(pageInMem.data() + i, this->kernelLoader->pvpatcher.pvstate->ideal_nops[9], 5) == 0) {
			i += 5;
			continue;
		}

		// check for uninitialized content after initialized
		// part of kernels text segment
		if (dynamic_cast<ElfKernelLoader *>(elf) &&
		    i >= (int32_t) (elf->textSegmentContent.size() - pageOffset)) {
			std::cout << COLOR_RED <<
			             "Validating: " << elf->getName() <<
			             " Page: " << std::hex << pageIndex
			                       << std::dec << std::endl;
			std::cout << "Unknown code @ " << std::hex << unkCodeAddress <<
			             std::dec << COLOR_NORM << std::endl;
			if (changeCount == 0) {
				std::cout << "The Code Segment is fully intact but " <<
				             "the rest of the page is uninitialized" <<
				             std::dec << std::endl << std::endl;
			}

			break;
		}

		std::cout << COLOR_RED << "Validating: " << elf->getName()
		          << " Page: " << std::hex << pageIndex << std::dec
		          << " Address: " << std::hex << unkCodeAddress << std::dec
		          << COLOR_NORM << std::endl;
		displayChange(pageInMem.data(), loadedPage, i, page->size);
		// exit(0);
		changeCount++;
		return;
	}

	if (changeCount > 0) {
		std::cout << elf->getName() << " Section: " << pageIndex
		          << " mismatch! " << changeCount << " inconsistent changes."
		          << std::endl;
		// exit(0);
	}
	// const auto time2_stop = std::chrono::system_clock::now();

	// const auto time1 = std::chrono::duration_cast<std::chrono::milliseconds>(time1_stop - time1_start).count();
	// const auto time2 = std::chrono::duration_cast<std::chrono::milliseconds>(time2_stop - time2_start).count();

	// std::cout << "Needed " << time1 << " / " << time2 << " ms " << std::endl;
	return;
	// return changeCount;
}

void KernelValidator::validateDataPage(page_info_t* page, ElfKernelspaceLoader* elf) {
	assert(page);
	assert(elf);

	// get Page from memdump
	std::vector<uint8_t> pageInMem = this->kernelLoader->vmi->readVectorFromVA(page->vaddr, page->size);

	if (page->vaddr == (kernelLoader->idt_tableAddress & 0xffffffffffff) ||
	    page->vaddr == (kernelLoader->nmi_idt_tableAddress & 0xffffffffffff)) {
		// Verify IDT Table
		// Verify nmi IDT Table
		//

		uint64_t idtPtr    = 0;
		uint8_t* idtPtrPtr = (uint8_t*)&idtPtr;
		for (uint32_t i = 0; i < page->size; i += 0x10) {
			uint8_t* pagePtr = pageInMem.data() + i;

			idtPtr       = *((uint64_t*)(pagePtr + 4));
			idtPtrPtr[0] = pagePtr[0];
			idtPtrPtr[1] = pagePtr[1];

			// TODO also verify flags
			if ((kernelLoader->symbols.isFunction(idtPtr) ||
			     kernelLoader->symbols.isSymbol(idtPtr) || idtPtr == 0) &&
			    *((uint32_t*)(pagePtr + 12)) == 0) {
				// IDT Entry points to function
				continue;
			} else if ((i >= 0x140 && i < 0x210) &&
			           idtPtr ==
			           (kernelLoader->sinittextAddress + (i / 0x10) * 9)) {
				// Some uninitialized IDT Entries might point to .init_text and
				// onwards
				continue;
			} else if ((i >= 0x210) &&
			           idtPtr == (kernelLoader->irq_entries_startAddress +
			                      (((i / 0x10 - 0x20) % 7) * 4 +
			                       ((i / 0x10 - 0x20) / 7) * 0x20))) {
				// irq_entries
				continue;
			}

			std::cout << COLOR_RED << COLOR_BOLD << "Could not verify idt ptr "
			          << std::hex << idtPtr << " @ " << page->vaddr + i
			          << " Padding is: " << *((uint32_t*)(pagePtr + 12))
			          << COLOR_BOLD_OFF << COLOR_NORM << std::dec << std::endl;

			// stats.unknownPtrs++;
		}
		return;
	}

	uint8_t *loadedPage;

	uint64_t roDataOffset =
	((uint64_t)elf->roDataSection.memindex & 0xffffffffffff);

	if (page->vaddr >= roDataOffset &&
	    page->vaddr < roDataOffset + elf->roDataSection.size) {

		loadedPage = elf->roData.data() + (page->vaddr - ((uint64_t)kernelLoader->roDataSection.memindex & 0xffffffffffff));

		if (memcmp(pageInMem.data(), loadedPage, page->size) != 0) {
			std::cout << COLOR_RED << "RoData Hash does not match @ "
			          << std::hex << page->vaddr << std::dec << COLOR_NORM
			          << std::endl;
			for (int32_t count = 0; count <= page->size; count++) {
				if (loadedPage[count] != pageInMem[count]) {
					uint64_t currentPtr =
					(uint64_t)((uint64_t*)(pageInMem.data() + count))[0];
					// TODO this is not clean!
					// kvm_guest_apic_eoi_write vs native_apic_mem_write
					// KVM init code overwrites apci->eoi_write with
					//     kvm_guest_apic_eoi_write
					if (kernelLoader->symbols.getFunctionAddress(
						    "kvm_guest_apic_eoi_write") == currentPtr) {
						std::cout << "Found pointer to kvm_guest_apic_eoi_write"
						          << " ... skipping" << std::endl;
						count += 7;
						continue;
					} else if (count + page->vaddr ==
					           0xffff81aef000 /* 3. 8 */ ||
					           count + page->vaddr ==
					           0xffff817c6000 /* 3.16 */) {
						std::cout << COLOR_RED << "Found pages that should be "
						                          "zero @ ffffffff81aef000"
						          << COLOR_NORM << std::endl;
						return;
					} else {
						std::cout << COLOR_RED << "Could not find function @ "
						          << std::hex << currentPtr << " ( "
						          << count + page->vaddr << " ) " << std::dec
						          << COLOR_NORM << std::endl;
					}
					displayChange(pageInMem.data(), loadedPage, count, page->size);
				}
			}
		}
		return;
	}

	uint64_t codePtrs = this->findCodePtrs(page, pageInMem.data());
	if (!codePtrs) {
		return;
	} else {
		globalCodePtrs += codePtrs;
		std::cout << COLOR_RED << COLOR_BOLD << "FOUND " << codePtrs
		          << " undecidable ptrs to executable memory"
		          << " in module " << elf->getName() << std::dec << COLOR_NORM
		          << COLOR_BOLD_OFF << std::endl;
	}

	std::cout << COLOR_GREEN << "Still " << globalCodePtrs
	          << " unidentified changes" << COLOR_NORM << std::endl;

	std::cout << COLOR_RED << "Still unprocessed data page @ " << std::hex
	          << page->vaddr << " with size: " << page->size << std::dec
	          << COLOR_NORM << std::endl;
}

uint64_t KernelValidator::isReturnAddress(uint8_t* ptr,
                                          uint32_t offset,
                                          uint64_t index) {
	int32_t callOffset = 0;
	if (offset > 5 && ptr[offset - 5] == (uint8_t)0xe8) {
		// call qword 0x5
		memcpy(&callOffset, ptr + offset - 4, 4);
		return index + offset + callOffset;
	}
	if (offset > 5 && ptr[offset - 5] == (uint8_t)0xe9) {
		// jmp qword
		// This is a jmp instruction!
		return 0;
	}
	if (offset > 6 && ptr[offset - 6] == (uint8_t)0xff &&
	    ptr[offset - 5] == (uint8_t)0x90) {
		// call qword [rax+0x0]
		// return 1 as we do not know rax
		return 1;
	}
	if (offset > 6 && ptr[offset - 6] == (uint8_t)0xff &&
	    ptr[offset - 5] == (uint8_t)0x15) {
		// call qword [rel 0x6]
		memcpy(&callOffset, ptr + offset - 4, 4);
		uint64_t callAddr = index + offset + callOffset;
		return this->kernelLoader->vmi->read64FromVA(callAddr);
	}
	if (offset > 7 && ptr[offset - 7] == (uint8_t)0xff &&
	    ptr[offset - 6] == (uint8_t)0x14 && ptr[offset - 5] == (uint8_t)0x25) {
		// call qword [0x0]
		memcpy(&callOffset, ptr + offset - 4, 4);
		std::cout << "INVESTIGATE!" << std::endl;
		return 1;
	}
	if (offset > 7 && ptr[offset - 7] == (uint8_t)0xff &&
	    ptr[offset - 6] == (uint8_t)0x14 && ptr[offset - 5] == (uint8_t)0xc5) {
		// call   QWORD PTR [rax*8-0x0]
		memcpy(&callOffset, ptr + offset - 4, 4);
		return 1;
	}
	if (offset > 2 && ptr[offset - 2] == (uint8_t)0xff) {
		return 1;
	}
	if (offset > 3 && ptr[offset - 3] == (uint8_t)0xff) {
		// call qword [rbx+0x0]
		return 1;
	}

	return 0;
}

uint64_t KernelValidator::findCodePtrs(page_info_t* page, uint8_t* pageInMem) {
	uint64_t codePtrs = 0;

	SectionInfo exTable = kernelLoader->elffile->findSectionWithName("__ex_table");

	if (this->stackAddresses.find(page->vaddr & 0xffffffffe000) !=
	    this->stackAddresses.end()) {
		// This is a stack that will be evaluated separately
		return 0;
	}

	// Go through every byte and check if it contains a kernel pointer
	for (int32_t i = 4; i < page->size - 4; i++) {
		uint32_t *intPtr = (uint32_t*)(pageInMem + i);

		// Check if this could be a valid kernel address.
		if (*intPtr == (uint32_t)0xffffffff) {
			// The first 4 byte could belong to a kernel address.
			uint64_t* longPtr = (uint64_t*)(intPtr - 1);
			if (*longPtr == (uint64_t)0xffffffffffffffffL) {
				i += 8;
				continue;
			}

			if (*longPtr == (uint64_t)0xffffffff815237b0L) {
				std::cout << "Found @ " << std::hex << " ( @ 0x"
				          << i - 4 + page->vaddr << " )" << std::dec
				          << std::endl;
				exit(0);
			}

			if (kernelLoader->symbols.isFunction(*longPtr)) {
				continue;
			}

			if (kernelLoader->symbols.isSymbol(*longPtr)) {
				// stats.symPtrs++;
				continue;
			}

			ElfKernelspaceLoader* elfloader = kernelLoader->getModuleForAddress(*longPtr);
			if (!elfloader || !elfloader->isCodeAddress(*longPtr)) {
				continue;
			}

			uint64_t offset = *longPtr - elfloader->textSegment.memindex;

			if (offset > elfloader->textSegmentContent.size()) {
				std::cout << std::hex << COLOR_RED << COLOR_BOLD
				          << "Found possible malicious pointer: 0x" << *longPtr
				          << " ( @ 0x" << i - 4 + page->vaddr << " )"
				          << " Pointing to code after initialized content"
				          << COLOR_NORM << COLOR_BOLD_OFF << std::dec
				          << std::endl;
				continue;
			}

			if (elfloader->smpOffsets.find(offset) !=
			    elfloader->smpOffsets.end()) {
				continue;
			}

			// Jump Instruction
			if (elfloader->jumpEntries.find(*longPtr) !=
			    elfloader->jumpEntries.end() ||
			    elfloader->jumpDestinations.find(*longPtr) !=
			    elfloader->jumpDestinations.end()) {
				//stats.jumpEntry++;
				continue;
			}

			// Exception Table
			if (*longPtr > (uint64_t)exTable.memindex) {
				//stats.exPtr++;
				continue;
			}

			// Return Address (Stack)
			uint64_t callAddr =
			isReturnAddress(elfloader->textSegmentContent.data(),
			                offset, elfloader->textSegment.memindex);
			if (callAddr) {
				std::cout << std::hex << COLOR_BLUE << COLOR_BOLD
				          << "return address: 0x" << *longPtr << " ( @ 0x"
				          << i - 4 + page->vaddr << " )" << COLOR_NORM
				          << COLOR_BOLD_OFF << std::dec << std::endl;
				continue;
			}

			//if (*longPtr == 0xffffffff81412843) {
			//	continue;
			//}

			// Handle bp_int3_addr and bp_int3_handler
			static uint64_t bp_int3_addr =
			kernelLoader->symbols.getSymbolAddress("bp_int3_addr");
			if ((page->vaddr + i - 4) == (bp_int3_addr & 0xffffffffffff)) {
				i += 16;
				continue;
			}

			std::cout << std::hex << COLOR_RED << COLOR_BOLD
			          << "Found possible malicious pointer: 0x" << *longPtr
			          << " ( @ 0x" << i - 4 + page->vaddr << " )" << std::endl
			          << " Pointing to module: " << elfloader->getName()
			          << COLOR_NORM << COLOR_BOLD_OFF << std::dec << std::endl;
			// stats.unknownPtrs++;
			codePtrs++;
		}
	}

	return codePtrs;
}

#define IDENTITYADDR 0xffff880000000000

void KernelValidator::updateStackAddresses() {
	this->stackAddresses.clear();

	Instance init_task = this->kernelLoader->symbols.findVariableByName("init_task")->getInstance();

	Instance task = init_task;
	do {
		Instance thread    = task.memberByName("thread");
		uint64_t stackAddr = thread.memberByName("sp0").getValue<uint64_t>();
		uint64_t rsp       = thread.memberByName("sp").getValue<uint64_t>();
		// This is the top of the stack
		uint64_t stackBottom = stackAddr - 0x2000;

		//if (((stackBottom ^ IDENTITYADDR) & 0xff0000000000) == 0) {
		//	stackBottom ^= IDENTITYADDR;
		//} else {
		stackBottom ^= 0xffff000000000000;
		//}

		this->stackAddresses[stackBottom] = rsp;

		//Instance ti = ti_bt->getInstance(stackAddr - 0x2000);
		//Instance ti_task = ti.memberByName("task", true);
		//if (ti_task.getAddress() != task.getAddress()) {
		//	assert(false);
		//}
		Instance tasks = task.memberByName("tasks");
		task = tasks.memberByName("next", true);
		task = task.changeBaseType("task_struct", "tasks");
	} while (task != init_task);
}
