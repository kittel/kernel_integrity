#include "kernel.h"

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

Kernel::Kernel()
	:
	paravirt{this} {}

void Kernel::setVMIInstance(VMIInstance *vmi) {
	this->vmi = vmi;
}

void Kernel::setKernelDir(const std::string &dirName) {
	this->kernelDirName = dirName;
}

ElfLoader *Kernel::loadModule(const std::string &moduleNameOrig) {
	std::string moduleName{moduleNameOrig};
	std::replace(moduleName.begin(), moduleName.end(), '-', '_');

	moduleMapMutex.lock();
	// Check if module is already loaded
	if (moduleMap.find(moduleName) != moduleMap.end()) {
		// This might be nullptr! Think about
		moduleMapMutex.unlock();
		while (moduleMap[moduleName] == nullptr) {
			std::this_thread::yield();
		}
		return moduleMap[moduleName];
	}
	moduleMap[moduleName] = nullptr;
	moduleMapMutex.unlock();

	std::string filename = findModuleFile(moduleName);
	if (filename.empty()) {
		std::cout << moduleName << ": Module File not found" << std::endl;
		return nullptr;
	}
	ElfFile *file = ElfFile::loadElfFile(filename);

	auto module = file->parseKernelModule(moduleName, this);

	moduleMapMutex.lock();
	moduleMap[moduleName] = module;
	moduleMapMutex.unlock();

	return moduleMap[moduleName];
}

void Kernel::loadModuleThread(std::list<std::string> &modList,
                                     std::mutex &modMutex) {
	while (true) {
		modMutex.lock();
		if (modList.empty()) {
			modMutex.unlock();
			return;
		}
		std::string mod = modList.front();
		modList.pop_front();
		modMutex.unlock();
		this->loadModule(mod);
	}
}

void Kernel::loadAllModules() {
	uint32_t concurentThreadsSupported = std::thread::hardware_concurrency();

	std::list<std::string> moduleNames = this->getKernelModules();
	std::mutex modMutex;
	std::vector<std::thread *> threads;

	for (uint32_t i = 0; i < concurentThreadsSupported; i++) {
		std::thread *t = new std::thread(&Kernel::loadModuleThread,
		                                 this,
		                                 std::ref(moduleNames),
		                                 std::ref(modMutex));
		threads.push_back(t);
	}

	for (auto &&thread : threads) {
		thread->join();
		delete (thread);
	}

	this->symbols.cleanArrays();
	this->symbols.cleanFunctions();
}

Instance Kernel::nextModule(Instance &instance) {
	Instance next = instance.memberByName("list").memberByName("next", true);
	next          = next.changeBaseType("module");
	return next;
}

std::string Kernel::findModuleFile(std::string modName) const {
	std::replace(modName.begin(), modName.end(), '-', '_');
	size_t start_pos = 0;
	while ((start_pos = modName.find("_", start_pos)) != std::string::npos) {
		modName.replace(start_pos, 1, "[_|-]");
		start_pos += 5;
	}
	std::vector<std::string> exclude;
	exclude.push_back(std::string("debian"));
	return findFileInDir(this->kernelDirName, modName, ".ko", exclude);
}

std::list<std::string> Kernel::getKernelModules() {
	if (this->moduleInstanceMap.size() == 0) {
		this->loadKernelModules();
	}
	std::list<std::string> strList;
	for (auto &mod : this->moduleInstanceMap) {
		strList.push_back(mod.first);
	}
	return strList;
}

Instance Kernel::getKernelModuleInstance(std::string modName) {
	std::replace(modName.begin(), modName.end(), '-', '_');
	auto moduleInstance = this->moduleInstanceMap.find(modName);
	if (moduleInstance != this->moduleInstanceMap.end()) {
		return moduleInstance->second;
	}
	assert(false);
	return Instance();
}

void Kernel::loadKernelModules() {
	this->moduleInstanceMap.clear();
	Instance modules = this->symbols.findVariableByName("modules")->getInstance();
	Instance module  = modules.memberByName("next", true);
	modules          = modules.changeBaseType("module");
	module           = module.changeBaseType("module");

	while (module != modules) {
		std::string moduleName = module.memberByName("name").getRawValue<std::string>();
		this->moduleInstanceMap[moduleName] = module;
		module = this->nextModule(module);
	}
}

uint64_t Kernel::getSystemMapAddress(const std::string &name,
                                            bool priv) {
	auto symbol = this->symbolMap.find(name);
	if (symbol != this->symbolMap.end()) {
		return symbol->second;
	}
	if (!priv) {
		return 0;
	}

	symbol = this->privSymbolMap.find(name);
	if (symbol != this->privSymbolMap.end()) {
		return symbol->second;
	}
	return 0;
}
void Kernel::addSymbolAddress(const std::string &name,
                                     uint64_t address) {
	std::string newName = name;
	while (this->moduleSymbolMap.find(newName) != this->moduleSymbolMap.end()) {
		newName = newName.append("_");
	}
	this->moduleSymbolMap[newName] = address;
}

uint64_t Kernel::getSymbolAddress(const std::string &name) {
	auto symbol = this->moduleSymbolMap.find(name);
	if (symbol != this->moduleSymbolMap.end()) {
		return symbol->second;
	}
	return 0;
}

std::string Kernel::getSymbolName(uint64_t address) {
	auto symbol = this->moduleSymbolRevMap.find(address);
	if (symbol != this->moduleSymbolRevMap.end()) {
		return symbol->second;
	}
	return "";
}

bool Kernel::isSymbol(uint64_t address) {
	if (this->moduleSymbolRevMap.find(address) !=
	    this->moduleSymbolRevMap.end()) {

		return true;
	}
	return false;
}

uint64_t Kernel::getContainingSymbol(uint64_t address) {
	auto iter = this->moduleSymbolRevMap.upper_bound(address);
	if (iter != this->moduleSymbolRevMap.end() &&
	    iter-- != this->moduleSymbolRevMap.begin()) {

		return iter->first;
	}
	return 0;
}

void Kernel::dumpSymbols() {
	//std::ofstream outfile
	//("/home/kittel/linux-symbols-3.16.txt",std::ofstream::binary);
	//for (auto &symbol : this->moduleSymbolRevMap) {
	//	outfile << std::hex << symbol.first << std::dec
	//	        << " " << symbol.second << std::endl;
	//}
	//outfile.close();
}

void Kernel::addFunctionAddress(const std::string &name,
                                       uint64_t address) {
	std::string newName = name;
	while (this->functionSymbolMap.find(newName) !=
	       this->functionSymbolMap.end()) {

		newName = newName.append("_");
	}
	this->functionSymbolMap[newName] = address;
}

uint64_t Kernel::getFunctionAddress(const std::string &name) {
	auto function = this->functionSymbolMap.find(name);
	if (function != this->functionSymbolMap.end()) {
		return function->second;
	}
	return 0;
}

std::string Kernel::getFunctionName(uint64_t address) {
	auto function = this->functionSymbolRevMap.find(address);
	if (function != this->functionSymbolRevMap.end()) {
		return function->second;
	}
	return "";
}

bool Kernel::isFunction(uint64_t address) {
	if (this->functionSymbolRevMap.find(address) !=
	    this->functionSymbolRevMap.end()) {
		return true;
	}
	return false;
}

void Kernel::updateRevMaps() {
	this->moduleSymbolRevMap.clear();
	this->functionSymbolRevMap.clear();

	for (auto &i : this->moduleSymbolMap) {
		this->moduleSymbolRevMap[i.second] = i.first;
	}
	for (auto &i : this->functionSymbolMap) {
		this->functionSymbolRevMap[i.second] = i.first;
	}
}

void Kernel::parseSystemMap() {
	std::string sysMapFileName = this->kernelDirName;
	sysMapFileName.append("/System.map");
	std::string line;
	std::ifstream sysMapFile(sysMapFileName);
	if (sysMapFile.is_open()) {
		while (sysMapFile.good()) {
			uint64_t address;
			char mode = '\0';
			std::string varname;
			std::getline(sysMapFile, line);
			std::stringstream iss(line);
			iss >> std::hex >> address >> mode >> varname;

			if (std::isupper(mode)) {
				symbolMap[varname] = address;
			} else {
				privSymbolMap[varname] = address;
			}
		}
		sysMapFile.close();
	} else {
		std::cout << "Unable to open file" << std::endl;
		return;
	}
}


ParavirtState *Kernel::getParavirtState() {
	return &this->paravirt;
}

uint64_t Kernel::findAddressOfSymbol(const std::string &symbolName) {
	// First look into the system map.
	// As we depend on dwarf anyway we use that information to find
	// a variable.

	uint64_t address = this->getSystemMapAddress(symbolName);
	if (address != 0) {
		return address;
	}
	address = this->getSymbolAddress(symbolName);
	if (address != 0) {
		return address;
	}
	address = this->getFunctionAddress(symbolName);
	if (address != 0) {
		return address;
	}

	// Variable not found in system.map
	// Try to find the variable by name in insight.
	Function *func = this->symbols.findFunctionByName(symbolName);
	if (func && func->getAddress()) {
		return func->getAddress();
	}

	Variable *var = this->symbols.findVariableByName(symbolName);
	if (var && var->getLocation()) {
		return var->getLocation();
	}
	std::cout << COLOR_RED << COLOR_BOLD
	          << "Could not find address for variable " << symbolName
	          << COLOR_NORM << COLOR_BOLD_OFF << std::endl;
	assert(false);
	return 0;
}

