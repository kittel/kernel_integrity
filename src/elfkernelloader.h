#ifndef ELFKERNELOADER_H
#define ELFKERNELOADER_H

#include "elfloader.h"
#include "kernelmanager.h"


class ElfKernelLoader : public ElfLoader, public KernelManager {
	public:
		ElfKernelLoader(ElfFile* elffile);
		ElfKernelLoader(ElfFile* elffile, std::string dirName);
		virtual ~ElfKernelLoader();

		ElfLoader* getModuleForAddress(uint64_t address);

		std::string getName();
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

#include "elfkernelloader32.h"
#include "elfkernelloader64.h"

#endif  /* ELFKERNELOADER_H */