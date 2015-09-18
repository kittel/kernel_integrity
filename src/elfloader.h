#ifndef ELFLOADER_H
#define ELFLOADER_H

#include "elffile.h"

#include "elfmodule.h"
#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

#include "kernel_headers.h"

#include <vector>
#include <map>
#include <set>


/* An ElfLoader is a memory representation we construct from the whitelisted
 * file. After a full initialization (depending on the type of ELF file) one
 * should be able to bytewise compare the actual memory with an instance of this
 * class.
 */
class ElfLoader{
	
	friend class ElfKernelLoader;
	friend class ElfModuleLoader;
	friend class KernelValidator;
	friend class ElfProcessLoader;  
	friend class ProcessValidator;  

	public:
		virtual ~ElfLoader();

		virtual std::string getName() = 0;
		ParavirtState* getPVState();

	protected:
		ElfLoader(ElfFile* elffile, ParavirtState* para);
		
		ElfFile* elffile;           // Wrapped ElfFile, provides to file and seg
		Instance* debugInstance;    // Wrapped debug instance of the file
		
		SectionInfo textSegment;    // The first big memory segment
	    std::vector<uint8_t> textSegmentContent;
		uint32_t textSegmentLength;

	    std::vector<uint8_t> jumpTable;
		std::vector<uint8_t> roData;

		std::map<uint64_t, int32_t> jumpEntries;
		std::set<uint64_t> jumpDestinations;
		std::set<uint64_t> smpOffsets;
		
		SectionInfo dataSection;    // The second big memory segment
		SectionInfo bssSection;     // The last memory segment
		SectionInfo roDataSection;

		const unsigned char* const* ideal_nops;
		void add_nops(void *insns, uint8_t len);

		ParavirtState* paravirtState; 

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
		void applyMcount(SectionInfo &info);
//		void applyTracepoints(SectionInfo tracePoint, SectionInfo rodata, QByteArray &segmentData);
		void applyJumpEntries(uint64_t jumpStart, uint32_t numberOfEntries);
		
//		static QList<uint64_t> _paravirtJump;
//		static QList<uint64_t> _paravirtCall;

		virtual void updateSectionInfoMemAddress(SectionInfo &info) = 0;
		virtual void parseElfFile();
		virtual void initText() = 0;
		virtual void initData() = 0;
		virtual void addSymbols() = 0;

		bool isCodeAddress(uint64_t addr);
		virtual bool isDataAddress(uint64_t addr) = 0;

};

#include "elfkernelloader.h"
#include "elfmoduleloader.h"
#include "elfprocessloader.h"

#endif /* ELFLOADER_H */
