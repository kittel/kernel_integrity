#ifndef ELFLOADER_H
#define ELFLOADER_H

#include "elffile.h"

#include "elfmodule.h"
#include "libdwarfparser/libdwarfparser.h"

#include <vector>

class ElfLoader;
class ElfLoader32;
class ElfLoader64;
class ElfLoader32Kernel;
class ElfLoader64Kernel;
class ElfLoader32Module;
class ElfLoader64Module;

class ElfFile;
class SegmentInfo;

class ParavirtState{

	public:
		ParavirtState();
		virtual ~ParavirtState();

		void updateState();


		Instance pv_init_ops;	
	    Instance pv_time_ops;
	    Instance pv_cpu_ops;
	    Instance pv_irq_ops;
	    Instance pv_apic_ops;
	    Instance pv_mmu_ops;
	    Instance pv_lock_ops;

		uint64_t nopFuncAddress;
	    uint64_t ident32NopFuncAddress;
	    uint64_t ident64NopFuncAddress;
		
		uint32_t pv_irq_opsOffset;
		uint32_t pv_cpu_opsOffset;
		uint32_t pv_mmu_opsOffset;

	private:
};

class ElfLoader{

	public:
		ElfLoader(ElfFile* elffile);
		virtual ~ElfLoader();

	protected:
		ElfFile* elffile;
		Instance* kernelModule;
		
		SegmentInfo textSegment;
	    std::vector<uint8_t> textSegmentContent;
	    std::vector<uint8_t> jumpTable;
		
		SegmentInfo dataSegment;
		
		const unsigned char* const* ideal_nops;
		void  add_nops(void *insns, uint8_t len);

		ParavirtState paravirtState;

		uint8_t paravirt_patch_nop(void);
		uint8_t paravirt_patch_ignore(unsigned len);
		uint8_t paravirt_patch_insns(void *insnbuf, unsigned len,
				const char *start, const char *end);
		uint8_t paravirt_patch_jmp(void *insnbuf, uint64_t target, uint64_t addr, uint8_t len);
		uint8_t paravirt_patch_call(void *insnbuf, uint64_t target, uint16_t tgt_clobbers,
				uint64_t addr, uint16_t site_clobbers, uint8_t len);
		uint8_t paravirt_patch_default(uint32_t type, uint16_t clobbers, void *insnbuf,
				uint64_t addr, uint8_t len);
		uint32_t paravirtNativePatch(uint32_t type, uint16_t clobbers, void *ibuf,
				unsigned long addr, unsigned len);

		uint64_t get_call_destination(uint32_t type);

		void applyAltinstr();
		void applyParainstr();
		void applySmpLocks();
		void applyMcount(SegmentInfo &info);
//		void applyTracepoints(SegmentInfo tracePoint, SegmentInfo rodata, QByteArray &segmentData);
		void applyJumpEntries(uint64_t jumpStart, uint32_t numberOfEntries);
		
//		static QList<uint64_t> _paravirtJump;
//		static QList<uint64_t> _paravirtCall;

		virtual void updateSegmentInfoMemAddress(SegmentInfo &info) = 0;
		virtual void parseElfFile();
		virtual void initText() = 0;
		virtual void initData() = 0;

};

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
		uint64_t getSystemMapAddress(std::string name);

	private:
		std::string dirName;
		
		typedef std::map<std::string, ElfLoader*> ModuleMap;
		ModuleMap moduleMap;
		
		typedef std::map<std::string, Instance> ModuleInstanceMap;
		ModuleInstanceMap moduleInstanceMap;

		Instance nextModule(Instance &instance);
		std::string findModuleFile(std::string modName);

		typedef std::map<std::string, uint64_t> SymbolMap;
		SymbolMap symbolMap;
		
};

class ElfKernelLoader : public ElfLoader, public KernelManager {
	public:
		ElfKernelLoader(ElfFile* elffile);
		ElfKernelLoader(ElfFile* elffile, std::string dirName);
		virtual ~ElfKernelLoader();

	protected:

		SegmentInfo vvarSegment;
		SegmentInfo dataNosaveSegment;
		SegmentInfo bssSegment;
		SegmentInfo rodataSegment;
		
	    uint64_t fentryAddress;
	    uint64_t genericUnrolledAddress;


		int apply_relocate();

		void updateSegmentInfoMemAddress(SegmentInfo &info);
		
		virtual void initText();
		virtual void initData();

	private:

};

class ElfModuleLoader : public ElfLoader {
	public:
		ElfModuleLoader(ElfFile* elffile, 
		        std::string name = "", 
		        KernelManager* parent = 0);
		virtual ~ElfModuleLoader();

		virtual void applyRelocationsOnSection(uint32_t relSectionID) = 0;
	protected:
		void updateSegmentInfoMemAddress(SegmentInfo &info);
		uint8_t * findMemAddressOfSegment(std::string segName);
		
		virtual void initText();
		virtual void initData();

		void loadDependencies();
		
		std::string modName;
		KernelManager* parent;
		
};

class ElfKernelLoader32 : public ElfKernelLoader{
	public:
		ElfKernelLoader32(ElfFile32* elffile);
		virtual ~ElfKernelLoader32();
	protected:
};

class ElfModuleLoader32 : public ElfModuleLoader{
	public:
		ElfModuleLoader32(ElfFile32* elffile, 
		        std::string name = "", 
		        KernelManager* parent = 0);
		virtual ~ElfModuleLoader32();
	protected:
};

class ElfKernelLoader64 : public ElfKernelLoader{
	public:
		ElfKernelLoader64(ElfFile64* elffile);
		virtual ~ElfKernelLoader64();

	protected:
};

class ElfModuleLoader64 : public ElfModuleLoader{
	public:
		ElfModuleLoader64(ElfFile64* elffile, 
		        std::string name = "", 
		        KernelManager* parent = 0);
		virtual ~ElfModuleLoader64();

		void applyRelocationsOnSection(uint32_t relSectionID);
	protected:
		uint64_t relocateShnUndef(std::string moduleName);
};


#endif /* ELFLOADER_H */
