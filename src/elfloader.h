#ifndef ELFLOADER_H
#define ELFLOADER_H

#include "elffile.h"

#include "elfmodule.h"

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

class ElfLoader{

	public:
		ElfLoader(ElfFile* elffile);
		virtual ~ElfLoader();

	protected:
		ElfFile* elffile;
		
		SegmentInfo textSegment;
		SegmentInfo dataSegment;
		
		const unsigned char* const* ideal_nops;
		void  add_nops(void *insns, uint8_t len);

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
		void applyJumpEntries(uint64_t jumpStart = 0, uint64_t jumpStop = 0);
		
//		static QList<uint64_t> _paravirtJump;
//		static QList<uint64_t> _paravirtCall;

		virtual void updateSegmentInfoMemAddress(SegmentInfo &info) = 0;
		virtual void parseElfFile();
		virtual void initText() = 0;
		virtual void initData() = 0;

};

class ElfKernelLoader : public ElfLoader {
	public:
		ElfKernelLoader(ElfFile* elffile);
		virtual ~ElfKernelLoader();

	protected:

		SegmentInfo vvarSegment;
		SegmentInfo dataNosaveSegment;
		SegmentInfo bssSegment;
		SegmentInfo rodataSegment;
		
	    uint64_t fentryAddress;
	    uint64_t genericUnrolledAddress;

	    std::vector<unsigned char> textSegmentContent;
	    std::vector<unsigned char> jumpTable;

		int apply_relocate();

		void updateSegmentInfoMemAddress(SegmentInfo &info);
		
		virtual void initText();
		virtual void initData();
	private:
};

class ElfModuleLoader : public ElfLoader {
	public:
		ElfModuleLoader(ElfFile* elffile);
		virtual ~ElfModuleLoader();

	protected:
		void updateSegmentInfoMemAddress(SegmentInfo &info);
		
		virtual void initText();
		virtual void initData();

		void loadDependencies();

	private:
		
};

class ElfKernelLoader32 : public ElfKernelLoader{
	public:
		ElfKernelLoader32(ElfFile32* elffile);
		virtual ~ElfKernelLoader32();
	protected:
};

class ElfModuleLoader32 : ElfModuleLoader{
	public:
		ElfModuleLoader32();
		virtual ~ElfModuleLoader32();
	protected:
};

class ElfKernelLoader64 : public ElfKernelLoader{
	public:
		ElfKernelLoader64(ElfFile64* elffile);
		virtual ~ElfKernelLoader64();

	protected:


};

class ElfModuleLoader64 : ElfModuleLoader{
	public:
		ElfModuleLoader64();
		virtual ~ElfModuleLoader64();

	protected:

};


#endif /* ELFLOADER_H */
