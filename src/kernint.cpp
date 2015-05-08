#include <iostream>
#include <iomanip>

#include "elffile.h"
#include "elfloader.h"

#include <cassert>
#include <iostream>
#include <typeinfo>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"
#include "helpers.h"
#include "kernel_headers.h"

#include <list>
#include <algorithm>


#include <iostream>


class KernelValidator {
	public:
		KernelValidator(std::string dirName, VMIInstance* vmi);
		virtual ~KernelValidator();


		void validatePage(page_info_t *page);

	protected:

	private:

		VMIInstance* vmi;
		ElfKernelLoader* kernelLoader;
		
		void validateCodePage(page_info_t *page, ElfLoader* elf);
		void validateDataPage(page_info_t *page, ElfLoader* elf);

		void displayChange(uint8_t* memory, uint8_t* reference, 
		                   int32_t offset, int32_t size);

		void loadKernel(std::string dirName);

		uint64_t findCodePtrs(page_info_t* page, uint8_t* pageInMem);
		bool isReturnAddress(uint8_t* ptr, uint32_t offset);

};

KernelValidator::KernelValidator(std::string dirName, VMIInstance* vmi):
	vmi(vmi), kernelLoader(){
	this->loadKernel(dirName);
	this->kernelLoader->loadAllModules();
	this->kernelLoader->updateRevMaps();

}

KernelValidator::~KernelValidator(){

}

void KernelValidator::loadKernel(std::string dirName){
	std::string kernelName = dirName;
	kernelName.append("/vmlinux");
    ElfFile *kernelFile = ElfFile::loadElfFile(kernelName);
    kernelLoader = dynamic_cast<ElfKernelLoader *>(
			kernelFile->parseElf(ElfFile::ELFPROGRAMTYPEKERNEL));
	kernelLoader->setKernelDir(dirName);
	kernelLoader->parseSystemMap();
	kernelLoader->parseElfFile();
}

void KernelValidator::validatePage(page_info_t * page){
	//std::cout << "Try to verify page: " << std::hex << 
	//             page->vaddr << std::dec << std::endl;
	if ((page->vaddr & 0xff0000000000) == 0xc900000000000){
		// TODO investigate, what are these c9 addresses
		return;
	}
	ElfLoader* elfloader = kernelLoader->getModuleForAddress(page->vaddr);
	//assert(elfloader);
	if(!elfloader){
		//std::cout << COLOR_MARGENTA << COLOR_BOLD << 
		//	"No Module found for address: " << std::hex <<
		//	page->vaddr << std::dec << COLOR_RESET << std::endl;
	}else if (elfloader->isCodeAddress(page->vaddr)){
		this->validateCodePage(page, elfloader);
	}else if (elfloader->isDataAddress(page->vaddr)){
		if(this->vmi->isPageExecutable(page)){
			static bool execData = false;
		    if(!execData){
				std::cout << COLOR_RED << COLOR_BOLD << 
		    		     "Warning: Executable Data Page" << 
                         COLOR_NORM << COLOR_BOLD_OFF << std::endl;
				execData = true;
			}
		}

		this->validateDataPage(page, elfloader);
	}
}

void KernelValidator::validateCodePage(page_info_t * page, ElfLoader* elf){
	assert(page);
	assert(elf);

	uint32_t pageOffset = 0;
	uint32_t pageIndex = 0;
	pageOffset = (page->vaddr - 
			     ((uint64_t) elf->textSegment.memindex & 0xffffffffffff ));
	pageIndex = (page->vaddr - 
			     ((uint64_t) elf->textSegment.memindex & 0xffffffffffff )
				) / page->size;
	//std::cout << "Validating: " << elf->getName() << 
	//             " Page: " << std::hex << pageIndex
	//                       << std::dec << std::endl;

	// get Page from module
	if(elf->textSegmentContent.size() < pageOffset){
		//This section is not completely loaded
		assert(false);
	}
	uint8_t* loadedPage = elf->textSegmentContent.data() + pageOffset;
	// get Page from memdump
	std::vector<uint8_t> pageInMem = 
	                     vmi->readVectorFromVA(page->vaddr, page->size);

    uint32_t changeCount = 0;

	for(int32_t i = 0 ; i < page->size ; i++)
	{
		if (loadedPage[i] == pageInMem[i]){
			continue;
		}

		// Show first changed byte only thus continue
		// if last byte also is different
		if(i>0 && loadedPage[i-1] != pageInMem[i-1]){
			continue;
		}

		// Check for ATOMIC_NOP
		if(i > 1 &&
				memcmp(loadedPage + i - 2, elf->ideal_nops[5], 5) == 0 &&
				memcmp(pageInMem.data() + i - 2, elf->ideal_nops[9], 5) == 0)
		{
			i = i+5;
			continue;
		}
		
		if (i <= 1 && 
				(((loadedPage[i] == (uint8_t) 0x66 && 
				   pageInMem[i] == (uint8_t) 0x90) ||
				 (loadedPage[i] == (uint8_t) 0x90 && 
				  pageInMem[i] == (uint8_t) 0x66)))){
			continue;
		}

		//Check if this is a jumpEntry that should be disabled
		if(loadedPage[i] == (uint8_t) 0xe9 &&
				(memcmp(pageInMem.data() + i, elf->ideal_nops[5], 5) == 0 ||
				 memcmp(pageInMem.data() + i, elf->ideal_nops[9], 5) == 0) &&
				// currentPage.data.at(i) == (char) 0xf &&
				// currentPage.data.at(i+1) == (char) 0x1f &&
				// currentPage.data.at(i+2) == (char) 0x44 &&
				// currentPage.data.at(i+3) == (char) 0x0 &&
				// currentPage.data.at(i+4) == (char) 0x0 &&
				dynamic_cast<ElfKernelLoader*>(elf))
		{
			//Get destination from memory
			int32_t jmpDestInt = 0;
			memcpy(&jmpDestInt, loadedPage + i + 1, 4);
			
			uint64_t labelOffset = page->vaddr + i + 0xffff000000000000;
			
			if(elf->jumpEntries.find(labelOffset) != 
			        elf->jumpEntries.end() &&
			   elf->jumpEntries[labelOffset] == jmpDestInt){
				//std::cout << "Jump Entry not disabled (inconsistency)" << std::endl;
				i += 5;
				continue;
			}
		}

		if(i > 0 && loadedPage[i-1] == (uint8_t) 0xe8){
			uint32_t jmpDestElfInt = 0;
			memcpy(&jmpDestElfInt, loadedPage + i + 1, 4);

			uint64_t elfDestAddress = (uint64_t) elf->textSegment.memindex + 
									  pageOffset + i + 
									  jmpDestElfInt + 5;

			if (dynamic_cast<ElfKernelLoader*>(elf)){
				if ( dynamic_cast<ElfKernelLoader*>(elf)->
					   genericUnrolledAddress == elfDestAddress){
					i += 4;
					continue;
				}
			}
			else if (dynamic_cast<ElfModuleLoader*>(elf)){
				uint32_t jmpDestMemInt = 0;
				memcpy(&jmpDestMemInt, pageInMem.data() + i + 1, 4);

				uint64_t memDestAddress = (uint64_t) elf->textSegment.memindex + 
										  pageOffset + i + 
										  jmpDestMemInt + 5;
				std::cout << "Error: " << std::endl;
				std::cout << "Jump in mem to: " << std::hex <<
							 memDestAddress << std::dec << std::endl;	
				std::cout << "Offset: " << std::hex <<
							 jmpDestMemInt << std::dec << std::endl;	
				std::cout << "Jump in elf to: " << std::hex <<
							 elfDestAddress << std::dec << std::endl;	
				std::cout << "Offset: " << std::hex <<
							 jmpDestElfInt << std::dec << std::endl;	
				std::cout << "Difference: " << std::hex <<
							 elfDestAddress - memDestAddress << 
							 std::dec << std::endl;	
			}
		}

		// Handle smp locks
		if((loadedPage[i] == (uint8_t) 0x3e && 
			pageInMem[i] == (uint8_t) 0xf0) ||
		   (loadedPage[i] == (uint8_t) 0xf0 && 
			pageInMem[i] == (uint8_t) 0x3e))
		{
			//TODO get es.ismpOffsets
			if (elf->smpOffsets.find(i + pageOffset) !=
					elf->smpOffsets.end()){
				continue;
			}
		}

        // TODO investigate
		if (memcmp(loadedPage + i, "\xe9\x00\x00\x00\x00", 5) == 0 && 
		    memcmp(pageInMem.data() + i, elf->ideal_nops[9], 5) == 0){
		    i += 5;
		    continue;
		}

		// check for uninitialized content after initialized 
		// part of kernels text segment
		if ( dynamic_cast<ElfKernelLoader*>(elf) && 
			 i >= (int32_t) (elf->textSegmentLength - pageOffset))
		{
			uint64_t unkCodeAddress = (uint64_t) elf->textSegment.memindex + 
			                                     pageOffset + i;
			std::cout << COLOR_RED << 
			             "Validating: " << elf->getName() << 
			             " Page: " << std::hex << pageIndex
			                       << std::dec << std::endl;
			std::cout << "Unknown code @ " << std::hex << unkCodeAddress <<
			             std::dec << COLOR_NORM << std::endl;
			if(changeCount == 0)
			{
				std::cout << "The Code Segment is fully intact but " << 
					"the rest of the page is uninitialized" << 
					std::dec << std::endl << std::endl;
			}

			break;
		}


	//	if(changeCount == 0){
			uint64_t unkCodeAddress = (uint64_t) elf->textSegment.memindex + 
			                                     pageOffset + i;
			std::cout << COLOR_RED << 
			             "Validating: " << elf->getName() << 
			             " Page: " << std::hex << pageIndex
			                       << std::dec << 
						 " Address: " << std::hex << unkCodeAddress <<
						                 std::dec << COLOR_NORM << std::endl;
			displayChange(pageInMem.data(), loadedPage, i, page->size);
	//	}
		changeCount++;
	}
	if (changeCount > 0)
	{
		std::cout << elf->getName() << 
		             " Section: " << pageIndex << 
					 " mismatch! " << changeCount << 
					 " inconsistent changes." << std::endl;
		exit(0);
	}
	return;
	//return changeCount;
}

void KernelValidator::validateDataPage(page_info_t * page, ElfLoader* elf){
	assert(page);
	assert(elf);
	// get Page from memdump
	std::vector<uint8_t> pageInMem = 
	                     vmi->readVectorFromVA(page->vaddr, page->size);

    if (page->vaddr == (kernelLoader->idt_tableAddress & 0xffffffffffff) ||
        page->vaddr == (kernelLoader->nmi_idt_tableAddress & 0xffffffffffff)){
        // Verify IDT Table
        // Verify nmi IDT Table
		//

        uint64_t idtPtr = 0;
        uint8_t* idtPtrPtr = (uint8_t*) &idtPtr;
        for( uint32_t i = 0 ; i < page->size ; i += 0x10){
            uint8_t* pagePtr = pageInMem.data() + i;

            idtPtr = *((uint64_t*) (pagePtr + 4));
            idtPtrPtr[0] = pagePtr[0];
            idtPtrPtr[1] = pagePtr[1];

            //TODO also verify flags
            if ((kernelLoader->isFunction(idtPtr) || 
			      kernelLoader->isSymbol(idtPtr) || 
				  idtPtr == 0) && 
				*((uint32_t*) (pagePtr + 12)) == 0){
                //IDT Entry points to function
                continue;
            }else if( (i >= 0x140 && i < 0x210) && 
			           idtPtr == (kernelLoader->sinittextAddress + 
						   (i / 0x10) * 9)){
                //Some uninitialized IDT Entries might point to .init_text and onwards
                continue;
            }else if( (i >= 0x210)  && 
					   idtPtr == (kernelLoader->irq_entries_startAddress + 
						   (((i / 0x10 - 0x20) % 7) * 4 + 
							((i / 0x10 - 0x20) / 7) * 0x20))){
                //irq_entries
                continue;
            }

			std::cout << COLOR_RED << COLOR_BOLD << 
				"Could not verify idt ptr " << std::hex << 
				idtPtr << " @ " << page->vaddr + i << 
				" Padding is: " << *((uint32_t*) (pagePtr + 12)) << 
				COLOR_BOLD_OFF << COLOR_NORM << 
				std::dec << std::endl;

            //stats.unknownPtrs++;
        }
        return;
    }
	
	uint8_t* loadedPage;

	uint64_t roDataOffset = ((uint64_t) elf->roDataSegment.memindex & 0xffffffffffff);

	if (page->vaddr >= roDataOffset &&
		page->vaddr < roDataOffset + elf->roDataSegment.size){

		loadedPage = elf->roData.data() + (page->vaddr - 
				((uint64_t) kernelLoader->roDataSegment.memindex & 
				     0xffffffffffff));

		if(memcmp(pageInMem.data(), loadedPage, page->size) != 0){
			std::cout << COLOR_RED << 
				"RoData Hash does not match @ " << std::hex << 
				page->vaddr << std::dec << COLOR_NORM << std::endl;
            for(int32_t count = 0 ; count <= page->size; count++) {
                if(loadedPage[count] != pageInMem[count]){
                    uint64_t currentPtr = (uint64_t) ((uint64_t *)(pageInMem.data() + count))[0];
                    // TODO this is not clean!
                    // kvm_guest_apic_eoi_write vs native_apic_mem_write
                    // KVM init code overwrites apci->eoi_write with 
					//     kvm_guest_apic_eoi_write
                    if (kernelLoader->
						getFunctionAddress("kvm_guest_apic_eoi_write") ==
					    currentPtr){
						
						std::cout << "Found pointer to kvm_guest_apic_eoi_write" << 
					           " ... skipping" << std::endl;
                        count+=7;
                        continue;
                    }else if(count + page->vaddr == 0xffff81aef000){
						std::cout << COLOR_RED << 
							"Found pages that should be zero @ ffffffff81aef000" << 
							COLOR_NORM << std::endl;
                        return;
                    }
                    else{
						std::cout << COLOR_RED << 
                            "Could not find function @ " << 
							std::hex << currentPtr << 
							" ( " << count + page->vaddr << " ) " <<
							std::dec <<
							COLOR_NORM << std::endl;
                    }
					displayChange(pageInMem.data(), loadedPage, count, page->size);
				}
            }
        }
        return;
    }
	static uint64_t globalCodePtrs = 0;
	uint64_t codePtrs = this->findCodePtrs(page, pageInMem.data());
	if(!codePtrs){
		return;
	}else{
		globalCodePtrs += codePtrs;
		std::cout << COLOR_RED << COLOR_BOLD <<  
			"FOUND " << codePtrs << " undecidable ptrs to executable memory" <<
			" in module " << elf->getName() << 
			std::dec << COLOR_NORM << COLOR_BOLD_OFF << std::endl;
	}

	std::cout << COLOR_GREEN << 
		"Still " << globalCodePtrs << " unidentified changes" <<
		COLOR_NORM << std::endl;
	
	std::cout << COLOR_RED << 
		"Still unprocessed data page @ " << 
		std::hex << page->vaddr <<
		" with size: " << page->size << std::dec << 
		COLOR_NORM << std::endl;

}

bool KernelValidator::isReturnAddress(uint8_t* ptr, uint32_t offset){
    if ( offset > 5 && ptr[offset-5] == (uint8_t) 0xe8 ){
		return true;
	}
	if ( offset > 5 && ptr[offset-5] == (uint8_t) 0xe9 ){
	    return true;
	}
	if ( offset > 6 && ptr[offset-6] == (uint8_t) 0xff &&
                       ptr[offset-5] == (uint8_t) 0x90 ){
	    return true;
	}
	if  (offset > 6 && ptr[offset-6] == (uint8_t) 0xff &&
                       ptr[offset-5] == (uint8_t) 0x15 ){
	    return true;
	}
	if ( offset > 7 && ptr[offset-7] == (uint8_t) 0xff &&
                       ptr[offset-6] == (uint8_t) 0x14 &&
                       ptr[offset-6] == (uint8_t) 0x25 ){
		return true;
	}
	if ( offset > 2 && ptr[offset-2] == (uint8_t) 0xff ){
	    return true;
	}
	if ( offset > 3 && ptr[offset-3] == (uint8_t) 0xff){
		return true;
	}

	return false;
}

uint64_t KernelValidator::findCodePtrs(page_info_t* page, 
		                           uint8_t* pageInMem){
	uint64_t codePtrs = 0;
	
	SegmentInfo exTable = 
		kernelLoader->elffile->findSegmentWithName("__ex_table");
	
    //Go through every byte and check if it contains a kernel pointer
    for(int32_t i = 4 ; i < page->size - 4; i++){
        uint32_t* intPtr = (uint32_t*) (pageInMem + i);
        
		//Check if this could be a valid kernel address.
        if(*intPtr == (uint32_t) 0xffffffff){
            //The first 4 byte could belong to a kernel address.
            uint64_t* longPtr = (uint64_t*) (intPtr -1);
            if (*longPtr == (uint64_t) 0xffffffffffffffffL){
                i += 8;
                continue;
            }

            if (kernelLoader->isFunction(*longPtr)){
                 continue;
            }
            
			if(kernelLoader->isSymbol(*longPtr)){
                //stats.symPtrs++;
                continue;
            }

			ElfLoader* elfloader = kernelLoader->getModuleForAddress(*longPtr);
			if (elfloader && elfloader->isCodeAddress(*longPtr)){
                // Check if ptr points to the instruction after a call 
				// (return address on the stack)
                // TODO: This could segfault...!
                uint64_t offset = *longPtr - 
					(uint64_t) elfloader->textSegment.memindex;
				if(offset > elfloader->textSegmentContent.size()){
					std::cout << std::hex << COLOR_RED << COLOR_BOLD <<
					   	"Found possible malicious pointer: 0x" << *longPtr << 
						" ( @ 0x" << i - 4 + page->vaddr << " )" << 
						" Pointing to code after initialized content" <<
						COLOR_NORM << COLOR_BOLD_OFF << std::dec << std::endl;
					continue;
				}
				if(elfloader->smpOffsets.find(offset) != 
						elfloader->smpOffsets.end()){
					continue;
				}
				//Jump Instruction
				if(elfloader->jumpEntries.find(*longPtr) != 
						elfloader->jumpEntries.end() || 
				   elfloader->jumpDestinations.find(*longPtr) != 
						elfloader->jumpDestinations.end()){
                //    stats.jumpEntry++;
					continue;
                }
                //Exception Table
                if (*longPtr > (uint64_t) exTable.memindex){
                //    stats.exPtr++;
					continue;
                }
                //Return Address (Stack)
				if ( isReturnAddress(elfloader->textSegmentContent.data(), 
				                          offset)){
                //    stats.returnPtrs++;
					continue;
                }

				//if(*longPtr == 0xffffffff81412843){
				//	continue;
				//}

				std::cout << std::hex << COLOR_RED << COLOR_BOLD <<
				   	"Found possible malicious pointer: 0x" << *longPtr << 
					" ( @ 0x" << i - 4 + page->vaddr << " )" << std::endl << 
					" Pointing to module: " << elfloader->getName() <<
					COLOR_NORM << COLOR_BOLD_OFF << std::dec << std::endl;
                //stats.unknownPtrs++;
				codePtrs++;
            }
            //At this point the pointer seems to point to arbitrary kernel data
            //Maybe we could check if it was initialized
            //stats.dataPtrs++;
        }
    }
	return codePtrs;
}

void KernelValidator::displayChange(uint8_t* memory, uint8_t* reference, 
                   int32_t offset, int32_t size){

	std::cout << "First change" << 
				 " in byte 0x" << std::hex << offset << 
				 " is 0x" << (uint32_t) reference[offset] <<
				 " should be 0x" << (uint32_t) memory[offset] << 
				 std::dec << std::endl;
	//Print 40 Bytes from should be

	std::cout << "The loaded block is: " << std::hex << std::endl;
	for (int32_t k = offset-15 ; (k < offset + 15) && (k < size); k++)
	{
		if (k < 0 || k >= size) continue;
		if (k == offset) std::cout << " # ";
		std::cout << std::setfill('0') << std::setw(2) <<
			(uint32_t) reference[k] << " ";
	}

	std::cout << std::endl << 
	    "The block in mem is: " << std::hex << std::endl;
	for (int32_t k = offset-15 ; (k < offset + 15) && (k < size); k++)
	{
		if (k < 0 || k >= size) continue;
		if (k == offset) std::cout << " # ";
		std::cout << std::setfill('0') << std::setw(2) << 
			(uint32_t) memory[k] << " ";
	}

	std::cout << std::dec << std::endl << std::endl;
}




int main (int argc, char **argv)
{	
	std::cout << COLOR_RESET;
    VMIInstance *vmi;

    //Parse options from cmdline
	const char* guestvm = NULL;
	const char* kerndir = NULL;
	int hypflag = 0;
	int index;
	int c;

	opterr = 0;

	while ((c = getopt (argc, argv, ":kxf")) != -1)
		switch (c)
		{
			case 'k':
				if(hypflag != 0){
					std::cout << "Could not set multiple hypervisors." <<
					   " Exiting..." << std::endl;
					return 0;
				}
				hypflag = VMI_KVM;
				break;
			case 'x':
				if(hypflag != 0){
					std::cout << "Could not set multiple hypervisors." <<
					   " Exiting..." << std::endl;
					return 0;
				}
				hypflag = VMI_XEN;
				break;
			case 'f':
				if(hypflag != 0){
					std::cout << "Could not set multiple hypervisors." <<
					   " Exiting..." << std::endl;
					return 0;
				}
				hypflag = VMI_FILE;
				break;
			case '?':
				if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,
							"Unknown option character `\\x%x'.\n",
							optopt);
			default:
				printf("Usage: %s [-x|-k|-f] <kerneldir> [ramdump]\n", argv[0]);
				return 1;
		}
	
	if (hypflag == 0){
		hypflag = VMI_AUTO;
	}

	index = optind;

	kerndir = argv[index++];
	if(index < argc){
		guestvm = argv[index];
	} else {
		guestvm = "insight";
		hypflag = VMI_AUTO;
	}

	vmi = new VMIInstance(guestvm, hypflag | VMI_INIT_COMPLETE);

	KernelValidator *val = new KernelValidator(kerndir, vmi);

	PageMap executablePageMap = vmi->getKernelPages();

	for ( auto page : executablePageMap){
		val->validatePage(page.second);
	}

	std::cout << COLOR_GREEN << COLOR_BOLD << 
		"Done validating pages" << 
		COLOR_BOLD_OFF << COLOR_NORM << std::endl;

	vmi->destroyMap(executablePageMap);
}

