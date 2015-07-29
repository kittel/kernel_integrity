#ifndef KERNELMANAGER_H
#define KERNELMANAGER_H

#include <iostream>
#include <list>
#include <map>
#include <unordered_map>
#include <mutex>

#include "libdwarfparser/instance.h"

class ElfLoader;

class KernelManager{

	public:
		KernelManager();
		virtual ~KernelManager(){};
		
		void setKernelDir(const std::string &dirName);

		void loadKernelModules();
		std::list<std::string> getKernelModules();
		Instance getKernelModuleInstance(std::string modName);

		void loadAllModules();
		void loadModuleThread(std::list<std::string> &modList,
				std::mutex &modMutex);
		ElfLoader *loadModule(std::string moduleName);
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

		void updateRevMaps();

	protected:
		std::mutex moduleMapMutex;
		typedef std::map<std::string, ElfLoader*> ModuleMap;
		ModuleMap moduleMap;
		

	private:
		std::string dirName;
		
		typedef std::map<std::string, Instance> ModuleInstanceMap;
		ModuleInstanceMap moduleInstanceMap;

		Instance nextModule(Instance &instance);
		std::string findModuleFile(std::string modName);

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
