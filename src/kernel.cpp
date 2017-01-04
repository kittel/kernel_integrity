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

#include "elfuserspaceloader.h"

#include "libdwarfparser/variable.h"
#include "libdwarfparser/function.h"
#include "libdwarfparser/array.h"

namespace kernint {

Kernel::Kernel()
	:
	paravirt{this},
	tm{this} {}

void Kernel::setVMIInstance(VMIInstance *vmi) {
	this->vmi = vmi;
}

void Kernel::setKernelDir(const std::string &dirName) {
	std::cout << "setting kernel dir to " << dirName << std::endl;
	this->kernelDirName = dirName;
}

TaskManager *Kernel::getTaskManager() {
	return &this->tm;
}

void Kernel::initTaskManager() {
	this->tm.init();
}

ElfModuleLoader *Kernel::loadModule(const std::string &moduleNameOrig) {
	std::string moduleName{moduleNameOrig};
	std::replace(moduleName.begin(), moduleName.end(), '-', '_');

	moduleMapMutex.lock();
	// Check if module is already loaded
	if (this->moduleMap.find(moduleName) != this->moduleMap.end()) {
		// This might be nullptr! Think about
		while (this->moduleMap[moduleName] == nullptr) {
			this->moduleMapMutex.unlock();
			std::this_thread::yield();
			this->moduleMapMutex.lock();
		}
		auto module = this->moduleMap[moduleName];
		this->moduleMapMutex.unlock();
		return module;
	}
	this->moduleMap[moduleName] = nullptr;
	this->moduleMapMutex.unlock();

	std::string filename = this->findModuleFile(moduleName);
	if (filename.empty()) {
		std::cout << moduleName << ": Module File not found" << std::endl;
		assert(false);
		return nullptr;
	}
	ElfFile *file = ElfFile::loadElfFile(filename);

	auto module = file->parseKernelModule(moduleName, this);
	assert(module);

	this->moduleMapMutex.lock();
	this->moduleMap[moduleName] = module;
	this->moduleMapMutex.unlock();

	return module;
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

	for ( auto &module : this->moduleMap ) {
		if(!module.second) {
			std::cout << "missing module for " << module.first << std::endl;
		}

		assert(module.second);
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

			this->symbols.addSysmapSymbol(varname, address, not std::isupper(mode));
		}
		sysMapFile.close();
	} else {
		std::cout << "Unable to open systemmap file at '"
		          << sysMapFileName << "'" << std::endl;
		return;
	}
}


ParavirtState *Kernel::getParavirtState() {
	return &this->paravirt;
}

} // namespace kernint
