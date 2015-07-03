#include "kernelmanager.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <cctype>

#include <regex>
#include <thread>

#include "elffile.h"

#include "libdwarfparser/variable.h"
#include "libdwarfparser/function.h"
#include "libdwarfparser/array.h"

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
//The following should replace boost filesystem once it is available in gcc
//#include <filesystem>
//namespace fs = std::filesystem;

KernelManager::KernelManager():
	moduleMapMutex(), moduleMap(), 
	dirName(), moduleInstanceMap(), symbolMap(),
	privSymbolMap(), moduleSymbolMap(), functionSymbolMap()
	{
}

void KernelManager::setKernelDir(std::string dirName){
	this->dirName = dirName;
}

ElfLoader *KernelManager::loadModule(std::string moduleName){
	std::replace(moduleName.begin(), moduleName.end(), '-', '_');
	
	moduleMapMutex.lock();
	// Check if module is already loaded
	if (moduleMap.find(moduleName) != moduleMap.end()){
		// This might be NULL! Think about
		moduleMapMutex.unlock();
		while (moduleMap[moduleName] == NULL){
			std::this_thread::yield();
		}
		return moduleMap[moduleName];
	}
	moduleMap[moduleName] = NULL;
	moduleMapMutex.unlock();
	
	std::string filename = findModuleFile(moduleName);
	if(filename.empty()){
		std::cout << moduleName << ": Module File not found" << std::endl;
		return NULL;
	}
	ElfFile *file = ElfFile::loadElfFile(filename);
	auto module = file->parseElf(ElfFile::ELFPROGRAMTYPEMODULE, 
			                     moduleName, 
								 this);
	
	moduleMapMutex.lock();
	moduleMap[moduleName] = module;
	moduleMapMutex.unlock();
	
	return moduleMap[moduleName];
}

void KernelManager::loadAllModules(){
	std::list<std::string> moduleNames = this->getKernelModules();

	std::vector<std::thread*> threads;

	for (auto curStr : moduleNames ){
		std::thread* t;
	   	t = new std::thread(&KernelManager::loadModule, this, curStr);
		threads.push_back(t);
	}

	for (auto &&thread : threads){
		thread->join();
		delete(thread);
	}
	Array::cleanArrays();
	Function::cleanFunctions();
}

Instance KernelManager::nextModule(Instance &instance){
	Instance next = instance.memberByName("list").memberByName("next", true);
	next = next.changeBaseType("module");
	return next;
}

std::string KernelManager::findModuleFile(std::string modName){
	std::replace(modName.begin(), modName.end(), '-', '_');
    size_t start_pos = 0;
	while((start_pos = modName.find("_", start_pos)) != std::string::npos) {
	    modName.replace(start_pos, 1, "[_|-]");
	    start_pos += 5;
	}
	std::regex regex = std::regex(modName);
	for( fs::recursive_directory_iterator end, dir(this->dirName);
			dir != end; dir++){
		if(fs::extension(*dir) == ".ko"){
			if (std::string((*dir).path().string()).find("debian") != 
					std::string::npos){
			   	continue;
			}
			if (std::regex_match((*dir).path().stem().string(), regex)){
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
	auto moduleInstance = this->moduleInstanceMap.find(modName);
	if(moduleInstance != this->moduleInstanceMap.end()){
		return moduleInstance->second;
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

uint64_t KernelManager::getSystemMapAddress(std::string name, bool priv){
	auto symbol = this->symbolMap.find(name);
	if(symbol != this->symbolMap.end()){
		return symbol->second;
	}
	if (!priv) return 0;

	symbol = this->privSymbolMap.find(name);
	if(symbol != this->privSymbolMap.end()){
		return symbol->second;
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
	auto symbol = this->moduleSymbolMap.find(name);
	if(symbol != this->moduleSymbolMap.end()){
		return symbol->second;
	}
	return 0;
}

std::string KernelManager::getSymbolName(uint64_t address){
	auto symbol = this->moduleSymbolRevMap.find(address);
	if(symbol != this->moduleSymbolRevMap.end()){
		return symbol->second;
	}
	return "";
}

bool KernelManager::isSymbol(uint64_t address){
	if(this->moduleSymbolRevMap.find(address) != this->moduleSymbolRevMap.end()){
		return true;
	}
	return false;
}

uint64_t KernelManager::getContainingSymbol(uint64_t address){
	auto iter = this->moduleSymbolRevMap.upper_bound(address);
	if(iter != this->moduleSymbolRevMap.end() && 
			iter-- != this->moduleSymbolRevMap.begin()){
		return iter->first;
	}
	return 0;
}

void KernelManager::dumpSymbols(){
	//std::ofstream outfile ("/home/kittel/linux-symbols-3.16.txt",std::ofstream::binary);
	//for(auto symbol : this->moduleSymbolRevMap ){
	//	outfile << std::hex << symbol.first << std::dec << 
	//		" " << symbol.second << std::endl;
	//}
	//outfile.close();
}


void KernelManager::addFunctionAddress(std::string name, uint64_t address){
	while(this->functionSymbolMap.find(name) != this->functionSymbolMap.end()){
		name = name.append("_");
	}
	this->functionSymbolMap[name] = address;
}

uint64_t KernelManager::getFunctionAddress(std::string name){
	auto function = this->functionSymbolMap.find(name);
	if(function != this->functionSymbolMap.end()){
		return function->second;
	}
	return 0;
}

std::string KernelManager::getFunctionName(uint64_t address){
	auto function = this->functionSymbolRevMap.find(address);
	if(function != this->functionSymbolRevMap.end()){
		return function->second;
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
			} else {
				privSymbolMap[varname] = address;
			}
		}
		sysMapFile.close();
    }else{  
		std::cout << "Unable to open file" << std::endl;
		return;
    }
}
