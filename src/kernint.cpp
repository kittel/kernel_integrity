#include <iostream>
#include <iomanip>

#include "elffile.h"
#include "elfloader.h"

#include <cassert>
#include <iostream>
#include <typeinfo>

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
		void validateDataPage(page_info_t *page/*, EflLoader* elf*/);

		void loadKernel(std::string dirName);



};

KernelValidator::KernelValidator(std::string dirName, VMIInstance* vmi):
	vmi(vmi), kernelLoader(){
	this->loadKernel(dirName);
	this->kernelLoader->loadAllModules();

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
}

void KernelValidator::validateCodePage(page_info_t * page, ElfLoader* elf){
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
							 elfDestAddress - memDestAddress << std::dec << std::endl;	
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


		if(changeCount == 0){
			std::cout << COLOR_RED << 
			             "Validating: " << elf->getName() << 
			             " Page: " << std::hex << pageIndex
			                       << std::dec << COLOR_NORM << std::endl;
			std::cout << "First change on section " << 
			                 pageIndex <<
						 " in byte 0x" << std::hex << i << 
						 " ( " << i + pageOffset << 
						 " ) is 0x" << (uint32_t) loadedPage[i] <<
						 " should be 0x" << (uint32_t) pageInMem[i] << 
						 std::dec << std::endl;
			//Print 40 Bytes from should be

			std::cout << "The loaded block is: " << std::hex << std::endl;
			for (int32_t k = i-15 ; (k < i + 15) && (k < page->size); k++)
			{
				if (k < 0 || k >= page->size) continue;
				if (k == i) std::cout << " # ";
				std::cout << std::setfill('0') << std::setw(2) <<
					(uint32_t) loadedPage[k] << " ";
			}

			std::cout << std::endl << 
			    "The block in mem is: " << std::hex << std::endl;
			for (int32_t k = i-15 ; (k < i + 15) && (k < page->size); k++)
			{
				if (k < 0 || k >= page->size) continue;
				if (k == i) std::cout << " # ";
				std::cout << std::setfill('0') << std::setw(2) << 
					(uint32_t) pageInMem[k] << " ";
			}

			std::cout << std::dec << std::endl << std::endl;
			exit(0);
		}
		changeCount++;
	}
	if (changeCount > 0)
	{
		std::cout << elf->getName() << 
		             " Section: " << pageOffset / page->size << 
					 " hash mismatch! " << changeCount << 
					 " inconsistent changes." << std::endl;
	}
	return;
	//return changeCount;
}

void KernelValidator::validatePage(page_info_t * page){
	//std::cout << "Try to verify page: " << std::hex << 
	//             page->vaddr << std::dec << std::endl;
	ElfLoader* elfloader = kernelLoader->getModuleForAddress(page->vaddr);
	if (elfloader){
		this->validateCodePage(page, elfloader);
	}else{
		// std::cout << "Warning: Executable Data Page" << std::endl;
	}
}

int main (int argc, char **argv)
{	
    VMIInstance *vmi;
    /* this is the VM or file that we are looking at */
    if (argc < 2) {
        printf("Usage: %s <kerneldir> [ramdump]\n", argv[0]);
        return 1;
    }
	if(argc == 3){
		vmi = new VMIInstance(argv[2], VMI_FILE | VMI_INIT_COMPLETE);
	}else{   
		vmi = new VMIInstance("insight", VMI_KVM | VMI_INIT_COMPLETE);
	}
	KernelValidator *val = new KernelValidator(argv[1], vmi);
	
	PageMap executablePageMap = vmi->getExecutableKernelPages();

	for ( auto page : executablePageMap){
		val->validatePage(page.second);
	}

	vmi->destroyMap(executablePageMap);
}

