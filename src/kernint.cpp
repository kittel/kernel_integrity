#include <iostream>

#include "elffile.h"
#include "elfloader.h"

#include <cassert>
#include <iostream>
#include <typeinfo>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"
#include "helpers.h"

#include <list>
#include <algorithm>


#include <iostream>


class KernelValidator {
	public:
		KernelValidator(std::string dirName);
		virtual ~KernelValidator();


		void validatePage(page_info_t *page);

	protected:

	private:
		ElfKernelLoader* kernelLoader;
		
		void validateCodePage(page_info_t *page/*, ElfLoader* elf*/);
		void validateDataPage(page_info_t *page/*, EflLoader* elf*/);

		void loadKernel(std::string dirName);



};

KernelValidator::KernelValidator(std::string dirName):
	kernelLoader(){
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

void KernelValidator::validateCodePage(page_info_t * page/*, ElfLoader* elf*/){
	assert(elf);
	std::cout << "Try to verify code page: " << std::hex << page->vaddr << std::dec << std::endl;

	ElfLoader* elfloader = kernelLoader->getModuleForAddress(page->vaddr);
	if (!elfloader){
		std::cout << "Warning: Executable Data Page" << std::endl;
		return;
	}
	
	std::cout << "ModuleName: " << elfloader->getName() << std::endl;
}

void KernelValidator::validatePage(page_info_t * page){
	std::cout << "Try to verify page: " << std::hex << page->vaddr << std::dec << std::endl;
	ElfLoader* elfloader = kernelLoader->getModuleForAddress(page->vaddr);
	if (elfloader){
		std::cout << "ModuleName: " << elfloader->getName() << std::endl;
	}else{
		std::cout << "Warning: Executable Data Page" << std::endl;
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
	KernelValidator *val = new KernelValidator(argv[1]);
	
	PageMap executablePageMap = vmi->getExecutableKernelPages();

	for ( auto page : executablePageMap){
		val->validatePage(page.second);
	}

	vmi->destroyMap(executablePageMap);
}

