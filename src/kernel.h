#ifndef KERNELMANAGER_H
#define KERNELMANAGER_H

#include <iostream>
#include <list>
#include <map>
#include <unordered_map>
#include <mutex>
#include <vector>

#include "libdwarfparser/symbolmanager.h"
#include "libdwarfparser/instance.h"
#include "libvmiwrapper/libvmiwrapper.h"

#include "paravirt_state.h"
#include "userspacemanager.h"
#include "taskmanager.h"

class ElfLoader;

class Kernel {
public:
	Kernel();
	virtual ~Kernel() = default;

	void setKernelDir(const std::string &dirName);

	void setVMIInstance(VMIInstance *vmi);

	void loadKernelModules();
	std::list<std::string> getKernelModules();
	Instance getKernelModuleInstance(std::string modName);

	void loadAllModules();
	void loadModuleThread(std::list<std::string> &modList,
	                      std::mutex &modMutex);
	ElfLoader *loadModule(const std::string &moduleName);
	void parseSystemMap();

	/*
	 * @param name   Name of the symbol
	 * @return       Address of the symbol
	 *
	 * Notice: This function only returns the address of public symbols
	 *
	 */
	uint64_t getSystemMapAddress(const std::string &name, bool priv = false);

	void addSymbolAddress(const std::string &name, uint64_t address);
	uint64_t getSymbolAddress(const std::string &name);
	std::string getSymbolName(uint64_t address);
	bool isSymbol(uint64_t address);
	void dumpSymbols();

	void addFunctionAddress(const std::string &name, uint64_t address);
	uint64_t getFunctionAddress(const std::string &name);
	std::string getFunctionName(uint64_t address);
	uint64_t getContainingSymbol(uint64_t address);
	bool isFunction(uint64_t address);

	virtual uint64_t findAddressOfSymbol(const std::string &symbolName);

	void updateRevMaps();

	ParavirtState *getParavirtState();
	UserspaceManager* getUserspace();
	TaskManager *getTaskManager();

	void initTaskManager();

	VMIInstance *vmi;

	/**
	 * Symbol position tracking and querying.
	 */
	SymbolManager symbols;

protected:
	ParavirtState paravirt;
	UserspaceManager userspace;
	TaskManager tm;

	std::mutex moduleMapMutex;
	typedef std::unordered_map<std::string, ElfLoader*> ModuleMap;
	ModuleMap moduleMap;

private:
	std::string kernelDirName;

	typedef std::unordered_map<std::string, Instance> ModuleInstanceMap;
	ModuleInstanceMap moduleInstanceMap;

	Instance nextModule(Instance &instance);
	std::string findModuleFile(std::string modName) const;

	typedef std::unordered_map<std::string, uint64_t> SymbolMap;
	typedef std::map<uint64_t, std::string> SymbolRevMap;
	SymbolMap symbolMap;
	SymbolMap privSymbolMap;

	SymbolMap moduleSymbolMap;
	SymbolMap functionSymbolMap;
	SymbolRevMap moduleSymbolRevMap;
	SymbolRevMap functionSymbolRevMap;
};


#endif  /* KERNELMANAGER_H */
