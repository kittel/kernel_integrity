#ifndef PROCESS_H_
#define PROCESS_H_

#include "elffile.h"
#include "libdwarfparser/symbolmanager.h"

class Instance;
class Kernel;
class ElfLoader;
class ElfProcessLoader;

class Process {
public:
	Process(const std::string &binaryName, Kernel *kernel);
	virtual ~Process() = default;

	ElfLoader *loadLibrary(const std::string &libraryName);

	std::string findLibraryFile(const std::string &libName);
	ElfProcessLoader *findLibByName(const std::string &name);

	void setLibraryDir(const std::string &dirName);

	ElfProcessLoader *loadExec();
	ElfLoader *loadVDSO();

	const std::string &getName();

	std::unordered_map<std::string, RelSym> *getSymMap();
	RelSym *findSymbolByName(const std::string &name);

	/**
	 * Check if the given pid is still scheduled in the kernel.
	 * + checks if libs the same and position
	 * + check if name is the same
	 * -> check via processes library map.
	 */
	bool isRunning() const;

	/**
	 * Return the pointer to the associated kernel
	 */
	Kernel *getKernel() const;
	
	SymbolManager symbols;

protected:
	Kernel *kernel;

	typedef std::unordered_map<std::string, ElfLoader*> LibraryMap;
	LibraryMap libraryMap;

	std::vector<std::string> libDirName;

	std::string binaryName;

	// TODO:
	std::vector<std::string> getArgv();
	std::unordered_map<std::string, std::string> getEnv();

	Instance *task_struct;
	pid_t pid;
};

#endif
