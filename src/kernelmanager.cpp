#include "kernelmanager.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

#include <algorithm>
#include <fstream>
#include <cctype>

#include "elffile.h"

#include "libdwarfparser/variable.h"

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
//The following should replace boost filesystem once it is available in gcc
//#include <filesystem>
//namespace fs = std::filesystem;

KernelManager::KernelManager():
	moduleMap(), dirName(), moduleInstanceMap(), symbolMap(),
	moduleSymbolMap(), functionSymbolMap()
	{
}

void KernelManager::setKernelDir(std::string dirName){
	this->dirName = dirName;
}

ElfLoader *KernelManager::loadModule(std::string moduleName){
	std::replace(moduleName.begin(), moduleName.end(), '-', '_');
	if(moduleMap.find(moduleName) != moduleMap.end()){
		return moduleMap[moduleName];
	}
	std::string filename = findModuleFile(moduleName);
	if(filename.empty()){
		std::cout << moduleName << ": Module File not found" << std::endl;
		return NULL;
	}else{
		//std::cout << filename << std::endl;
	}
	ElfFile *file = ElfFile::loadElfFile(filename);
	auto module = file->parseElf(ElfFile::ELFPROGRAMTYPEMODULE, moduleName, this);
	moduleMap[moduleName] = module;

	return module;
}


void KernelManager::loadAllModules(){
	std::list<std::string> moduleNames = this->getKernelModules();

	for (auto curStr : moduleNames ){
		this->loadModule(curStr);
	}
}

Instance KernelManager::nextModule(Instance &instance){
	Instance next = instance.memberByName("list").memberByName("next", true);
	next = next.changeBaseType("module");
	return next;
}

std::string KernelManager::findModuleFile(std::string modName){
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

std::list<std::string> KernelManager::getKernelModules(){
	if(this->moduleInstanceMap.size() == 0){
		this->loadKernelModules();
	}
	std::list<std::string> strList;
	for(auto mod: this->moduleInstanceMap){
	    strList.push_back(mod.first);
	}
	return strList;
}

Instance KernelManager::getKernelModuleInstance(std::string modName){
	std::replace(modName.begin(), modName.end(), '-', '_');
	if(this->moduleInstanceMap.find(modName) != this->moduleInstanceMap.end()){
		return this->moduleInstanceMap[modName];
	}
	assert(false);
	return Instance();
}

void KernelManager::loadKernelModules(){
	moduleInstanceMap.clear();
	Instance modules = Variable::findVariableByName("modules")->getInstance();
	Instance module = modules.memberByName("next", true);
	modules = modules.changeBaseType("module");
	module = module.changeBaseType("module");
	
	while(module != modules){
		std::string moduleName = module.memberByName("name").getRawValue<std::string>();
		//std::cout << "Module " << moduleName << std::endl;
		moduleInstanceMap[moduleName] = module;
		module = this->nextModule(module);
	}
}

uint64_t KernelManager::getSystemMapAddress(std::string name){
	if(this->symbolMap.find(name) != this->symbolMap.end()){
		return this->symbolMap[name];
	}
	return 0;
}
void KernelManager::addSymbolAddress(std::string name, uint64_t address){
	while(this->moduleSymbolMap.find(name) != this->moduleSymbolMap.end()){
		name = name.append("_");
	}
	this->moduleSymbolMap[name] = address;
}

uint64_t KernelManager::getSymbolAddress(std::string name){
	if(this->moduleSymbolMap.find(name) != this->moduleSymbolMap.end()){
		return this->moduleSymbolMap[name];
	}
	return 0;
}

std::string KernelManager::getSymbolName(uint64_t address){
	if(this->moduleSymbolRevMap.find(address) != this->moduleSymbolRevMap.end()){
		return this->moduleSymbolRevMap[address];
	}
	return "";
}

bool KernelManager::isSymbol(uint64_t address){
	
	if(this->moduleSymbolRevMap.find(address) != this->moduleSymbolRevMap.end()){
		return true;
	}
	return false;
}


void KernelManager::addFunctionAddress(std::string name, uint64_t address){
	while(this->functionSymbolMap.find(name) != this->functionSymbolMap.end()){
		name = name.append("_");
	}
	this->functionSymbolMap[name] = address;
}

uint64_t KernelManager::getFunctionAddress(std::string name){
	if(this->functionSymbolMap.find(name) != this->functionSymbolMap.end()){
		return this->functionSymbolMap[name];
	}
	return 0;
}

std::string KernelManager::getFunctionName(uint64_t address){
	if(this->functionSymbolRevMap.find(address) != this->functionSymbolRevMap.end()){
		return this->functionSymbolRevMap[address];
	}
	return "";
}

bool KernelManager::isFunction(uint64_t address){
	if(this->functionSymbolRevMap.find(address) != this->functionSymbolRevMap.end()){
		return true;
	}
	return false;
}

void KernelManager::updateRevMaps(){
	this->moduleSymbolRevMap.clear();
	this->functionSymbolRevMap.clear();

	for( auto i : this->moduleSymbolMap){
		this->moduleSymbolRevMap[i.second] = i.first;
	}
	for( auto i : this->functionSymbolMap){
		this->functionSymbolRevMap[i.second] = i.first;
	}
}

void KernelManager::parseSystemMap(){
	std::string sysMapFileName = this->dirName;
	sysMapFileName.append("/System.map");
	std::string line;
	std::ifstream sysMapFile (sysMapFileName);
	if (sysMapFile.is_open()){
		while ( sysMapFile.good() ){
			uint64_t address;
			char mode = '\0';
			std::string varname;
			std::getline (sysMapFile,line);
			std::stringstream iss(line); 
			iss >> std::hex >>address >> mode >> varname;

			if(std::isupper(mode)){
				symbolMap[varname] = address;
			}
		}
		sysMapFile.close();
    }else{  
		std::cout << "Unable to open file" << std::endl;
		return;
    }
}
