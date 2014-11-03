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

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
#include <iostream>


class KernelValidator {
	public:
		KernelValidator(std::string dirName);
		virtual ~KernelValidator();

		std::list<std::string> getKernelModules();

		Instance nextModule(Instance &instance);
		std::string findModuleFile(std::string modName);



	protected:

	private:
		std::string dirName;
		ElfLoader* kernelLoader;

		typedef std::map<std::string, ElfLoader*> modules;

		void loadKernel();
		void loadModules();



};

KernelValidator::KernelValidator(std::string dirName):
	dirName(dirName),kernelLoader(){
	this->loadKernel();
	//this->loadModules();

}

KernelValidator::~KernelValidator(){

}

void KernelValidator::loadKernel(){
	std::string kernelName = dirName;
	kernelName.append("/vmlinux");
    ElfFile *kernelFile = ElfFile::loadElfFile(kernelName);
    kernelLoader = kernelFile->parseElf(ElfFile::ELFPROGRAMTYPEKERNEL);
}

void KernelValidator::loadModules(){
	std::list<std::string> moduleNames = this->getKernelModules();

	for (auto curStr : moduleNames ){
		std::string filename = findModuleFile(curStr);
		std::cout << filename << std::endl;
		ElfFile *file = ElfFile::loadElfFile(filename);
		UNUSED(file);
		//
		//Load ELF File
		//
		//Create Loader
	
	}



}

Instance KernelValidator::nextModule(Instance &instance){
	Instance next = instance.memberByName("list").memberByName("next", true);
	next.changeBaseType("module");
	return next;
}

std::string KernelValidator::findModuleFile(std::string modName){
	for( fs::recursive_directory_iterator end, dir(this->dirName);
			dir != end; dir++){
		if(fs::extension(*dir) == ".ko"){
			if((*dir).path().stem() == modName){
				return (*dir).path().native();
			}
			std::replace(modName.begin(), modName.end(), '_', '-');
			if((*dir).path().stem() == modName){
				return (*dir).path().native();
			}
			std::replace(modName.begin(), modName.end(), '-', '_');
			if((*dir).path().stem() == modName){
				return (*dir).path().native();
			}
		}
	}
	return "";

}

std::list<std::string> KernelValidator::getKernelModules(){
	std::list<std::string> strList;
	Instance modules = Variable::findVariableByName("modules")->getInstance();
	Instance module = modules.memberByName("next", true);
	modules.changeBaseType("module");
	module.changeBaseType("module");
	
	while(module != modules){
		strList.push_back(module.memberByName("name").getRawValue<std::string>());
		module = this->nextModule(module);
	}
	return strList;
}

int main (int argc, char **argv)
{
    VMIInstance *vmi;
    /* this is the VM or file that we are looking at */
    if (argc < 2) {
        printf("Usage: %s <kerneldir> [vmimage]\n", argv[0]);
        return 1;
    }
	if(argc == 3){
		vmi = new VMIInstance(argv[2], VMI_FILE | VMI_INIT_COMPLETE);
	}else{   
		vmi = new VMIInstance("insight", VMI_KVM | VMI_INIT_COMPLETE);
	}
	//KernelValidator *val = new KernelValidator(argv[1]);
	//val->getKernelModules();
	//
	vmi->getKernelPages();
    //uint64_t modules = vmi->read64FromVA(file64->findAddressOfVariable("modules"));

    //std::cout << "Value at modules: " << modules << std::endl;


	//DELETE(val);
	DELETE(vmi);
    
}
