#ifndef USERSPACEMANAGER_H_
#define USERSPACEMANAGER_H_

#include <unordered_map>
#include <vector>

class ElfLoader;
class ElfProcessLoader;
class Kernel;
class Process;

/**
 * The UserspaceManager is in charge of handling userspace memory allocations.
 * It contains a list of all binary programs and all libraries.
 * It is also used to load userspace program memory.
 * The Manager is part of the Kernel.
 */

class UserspaceManager {
public:
	UserspaceManager(Kernel *kernel);
	virtual ~UserspaceManager() = default;

	void setLibraryDir(const std::string &dirName);

	ElfLoader *loadVDSO();
	ElfLoader *loadLibrary(const std::string &libraryName);

	std::string findLibraryFile(const std::string &libName);
	ElfProcessLoader *findLibByName(const std::string &name);

	ElfProcessLoader *loadExec(Process *process);

private:

	Kernel *kernel;

	std::vector<std::string> libDirName;

	typedef std::unordered_map<std::string,Process*> ProcessMap;
	ProcessMap processMap;

	typedef std::unordered_map<std::string, ElfLoader*> LibraryMap;
	LibraryMap libraryMap;


};





#endif /* USERSPACEMANAGER_H_ */
