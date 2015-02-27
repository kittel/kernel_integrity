#include "elfmoduleloader32.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

ElfModuleLoader32::ElfModuleLoader32(ElfFile32* elffile, 
		                             std::string name,
                                     KernelManager* parent):
	ElfModuleLoader(elffile, name, parent){
	//this->ParseElfFile();
}

ElfModuleLoader32::~ElfModuleLoader32(){}