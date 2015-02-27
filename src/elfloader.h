#ifndef ELFLOADER_H
#define ELFLOADER_H

#include "elffile.h"

#include "elfmodule.h"
#include "libdwarfparser/libdwarfparser.h"

#include "kernel_headers.h"

#include <vector>

class ElfLoader{
	
	friend class ElfKernelLoader;
	friend class ElfModuleLoader;
	public:
		ElfLoader(ElfFile* elffile);
		virtual ~ElfLoader();

		virtual std::string getName() = 0;

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

#include "elfkernelloader.h"
#include "elfmoduleloader.h"

#endif /* ELFLOADER_H */
