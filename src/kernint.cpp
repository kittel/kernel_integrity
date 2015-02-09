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




	protected:

	private:
		ElfKernelLoader* kernelLoader;

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
	//
	//vmi->getKernelPages();
    //uint64_t modules = vmi->read64FromVA(file64->findAddressOfVariable("modules"));


	DELETE(val);
	DELETE(vmi);
    
}
