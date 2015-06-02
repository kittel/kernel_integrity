#ifndef ELFKERNELOADER_H
#define ELFKERNELOADER_H

#include "elfloader.h"
#include "kernelmanager.h"


class ElfKernelLoader : public ElfLoader, public KernelManager {
	friend class KernelValidator;

	public:
		ElfKernelLoader(ElfFile* elffile);
		ElfKernelLoader(ElfFile* elffile, std::string dirName);
		virtual ~ElfKernelLoader();

		ElfLoader* getModuleForAddress(uint64_t address);
		ElfLoader* getModuleForCodeAddress(uint64_t address);

		std::string getName();
	protected:

		SegmentInfo vvarSegment;
		SegmentInfo dataNosaveSegment;
		SegmentInfo rodataSegment;
		
	    uint64_t fentryAddress;
	    uint64_t genericUnrolledAddress;

		uint64_t idt_tableAddress;
		uint64_t nmi_idt_tableAddress;
		uint64_t sinittextAddress;
		uint64_t irq_entries_startAddress;

		int apply_relocate();

		void updateSegmentInfoMemAddress(SegmentInfo &info);
		
		virtual void initText();
		virtual void initData();
		
		bool isDataAddress(uint64_t addr);

	private:

};

#include "elfkernelloader32.h"
#include "elfkernelloader64.h"

#endif  /* ELFKERNELOADER_H */
