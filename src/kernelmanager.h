#ifndef KERNELMANAGER_H
#define KERNELMANAGER_H

#include <iostream>
#include <list>
#include <map>

#include "libdwarfparser/instance.h"

class ElfLoader;

class KernelManager{

	public:
		KernelManager();
		
		void setKernelDir(std::string dirName);

		void loadKernelModules();
		std::list<std::string> getKernelModules();
		Instance getKernelModuleInstance(std::string modName);

		void loadAllModules();
		ElfLoader *loadModule(std::string moduleName);
		void parseSystemMap();

		/*
		 * @param name   Name of the symbol
		 * @return       Address of the symbol
		 *
		 * Notice: This function only returns the address of public symbols
		 *
		 */
		uint64_t getSystemMapAddress(std::string name);

		void addSymbolAddress(std::string name, uint64_t address);
		uint64_t getSymbolAddress(std::string name);
		std::string getSymbolName(uint64_t address);
		bool isSymbol(uint64_t address);
		
		void addFunctionAddress(std::string name, uint64_t address);
		uint64_t getFunctionAddress(std::string name);
		std::string getFunctionName(uint64_t address);
		bool isFunction(uint64_t address);

		void updateRevMaps();

	protected:
		typedef std::map<std::string, ElfLoader*> ModuleMap;
		ModuleMap moduleMap;
		

	private:
		std::string dirName;
		
		typedef std::map<std::string, Instance> ModuleInstanceMap;
		ModuleInstanceMap moduleInstanceMap;

		Instance nextModule(Instance &instance);
		std::string findModuleFile(std::string modName);

		typedef std::map<std::string, uint64_t> SymbolMap;
		typedef std::map<uint64_t, std::string> SymbolRevMap;
		SymbolMap symbolMap;

		SymbolMap moduleSymbolMap;
		SymbolMap functionSymbolMap;
		SymbolRevMap moduleSymbolRevMap;
		SymbolRevMap functionSymbolRevMap;
		
};


#endif  /* KERNELMANAGER_H */
