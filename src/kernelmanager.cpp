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

#include "elfprocessloader.h"

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
	kernelDirName(), moduleInstanceMap(), symbolMap(),
	privSymbolMap(), moduleSymbolMap(), functionSymbolMap()
	{
}

void KernelManager::setVMIInstance(VMIInstance *vmi){
	this->vmi = vmi;
}

void KernelManager::setKernelDir(const std::string &dirName){
	this->kernelDirName = dirName;
}

void KernelManager::setLibraryDir(const std::string &dirName){
	this->libDirName = dirName;
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

void KernelManager::loadModuleThread(std::list<std::string> &modList,
		std::mutex &modMutex){

	while(true){
		modMutex.lock();
		if(modList.empty()){
			modMutex.unlock();
			return;
		}
		std::string mod = modList.front();
		modList.pop_front();
		modMutex.unlock();
		this->loadModule(mod);
	}

}

void KernelManager::loadAllModules(){

	uint32_t concurentThreadsSupported = std::thread::hardware_concurrency();

	std::list<std::string> moduleNames = this->getKernelModules();
	std::mutex modMutex;
	std::vector<std::thread*> threads;

	for (uint32_t i = 0 ; i < concurentThreadsSupported ; i++ ) {
		std::thread* t = 
			new std::thread(&KernelManager::loadModuleThread,
					this,
					std::ref(moduleNames),
					std::ref(modMutex));
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
	for( fs::recursive_directory_iterator end, dir(this->kernelDirName);
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
	for(auto& mod: this->moduleInstanceMap){
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

uint64_t KernelManager::getSystemMapAddress(const std::string &name, bool priv){
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
void KernelManager::addSymbolAddress(const std::string &name, uint64_t address){
	std::string newName = name;
	while(this->moduleSymbolMap.find(newName) != this->moduleSymbolMap.end()){
		newName = newName.append("_");
	}
	this->moduleSymbolMap[newName] = address;
}

uint64_t KernelManager::getSymbolAddress(const std::string &name){
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
	//for(auto& symbol : this->moduleSymbolRevMap ){
	//	outfile << std::hex << symbol.first << std::dec << 
	//		" " << symbol.second << std::endl;
	//}
	//outfile.close();
}


void KernelManager::addFunctionAddress(const std::string &name, uint64_t address){
	std::string newName = name;
	while(this->functionSymbolMap.find(newName) != this->functionSymbolMap.end()){
		newName = newName.append("_");
	}
	this->functionSymbolMap[newName] = address;
}

uint64_t KernelManager::getFunctionAddress(const std::string &name){
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

	for( auto& i : this->moduleSymbolMap){
		this->moduleSymbolRevMap[i.second] = i.first;
	}
	for( auto& i : this->functionSymbolMap){
		this->functionSymbolRevMap[i.second] = i.first;
	}
}

void KernelManager::parseSystemMap(){
	std::string sysMapFileName = this->kernelDirName;
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

ElfLoader *KernelManager::loadLibrary(std::string libraryName){
	
//	moduleMapMutex.lock();
//	// Check if module is already loaded
	if (this->libraryMap.find(libraryName) != this->libraryMap.end()){
		// This might be NULL! Think about
//		moduleMapMutex.unlock();
//		while (moduleMap[moduleName] == NULL){
//			std::this_thread::yield();
//		}
		return this->libraryMap[libraryName];
	}
//	moduleMap[moduleName] = NULL;
//	moduleMapMutex.unlock();
	
	std::string filename = findLibraryFile(libraryName);
	if(filename.empty()){
		std::cout << libraryName << ": Library File not found" << std::endl;
		return NULL;
	}
	//Create ELF Object
	ElfFile *libraryFile = ElfFile::loadElfFile(filename);
	auto library = dynamic_cast<ElfProcessLoader64 *>
               (libraryFile->parseElf(ElfFile::ELFPROGRAMTYPEEXEC,
	                               libraryName, this));
	//this->execLoader->supplyVDSO(dynamic_cast<ElfProcessLoader64*>(this->vdsoLoader));
	library->parseElfFile();
	
//	moduleMapMutex.lock();
	std::cout << "library loaded: " << libraryName << std::endl;
	this->libraryMap[libraryName] = library;
//	moduleMapMutex.unlock();
//	
	return library;
}

ElfProcessLoader* KernelManager::findLibByName(std::string name){ 
	if(this->libraryMap.find(name) == this->libraryMap.end()){
		return NULL;
	}
	return dynamic_cast<ElfProcessLoader*>(libraryMap[name]);
}

std::string KernelManager::findLibraryFile(std::string libName){
	std::regex regex = std::regex(libName);
	for( fs::recursive_directory_iterator end, dir(this->libDirName);
		dir != end; dir++){
		if (std::regex_match((*dir).path().filename().string(), regex)){
			return (*dir).path().native();
		}
	}
	return "";
}

ElfLoader* KernelManager::loadVDSO(){
	// Symbols in Kernel that point to the vdso page
	// ... the size is currently unknown
	// TODO Find out the correct archirecture of the binary.
	//
	// vdso_image_64
	// vdso_image_x32
	// vdso_image_32_int80
	// vdso_image_32_syscall
	// vdso_image_32_sysenter
	
	std::string vdsoString = std::string("[vdso]");
	if (this->libraryMap.find(vdsoString) != this->libraryMap.end()){
		return this->libraryMap[vdsoString];
	}

	auto vdsoVar = Variable::findVariableByName("vdso_image_64");
	assert(vdsoVar);

	auto vdsoImage = vdsoVar->getInstance();
	
	assert(vmi);
	auto vdso = vmi->readVectorFromVA(
	             vdsoImage.memberByName("data").getRawValue<uint64_t>(false),
	             vdsoImage.memberByName("size").getValue<uint64_t>());

	// Load VDSO page
	ElfFile* vdsoFile = ElfFile::loadElfFileFromBuffer(vdso.data(), vdso.size());

	auto vdsoLoader = dynamic_cast<ElfProcessLoader64*>
	           (vdsoFile->parseElf(ElfFile::ELFPROGRAMTYPEEXEC,
	           "[vdso]", this));
	vdsoLoader->parseElfFile();

	this->libraryMap[vdsoString] = vdsoLoader;
	return vdsoLoader;
}
