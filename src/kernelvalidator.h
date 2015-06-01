#ifndef KERNELVALIDATOR_H
#define KERNELVALIDATOR_H

#include "elffile.h"
#include "elfloader.h"

#include "libvmiwrapper/libvmiwrapper.h"
#include "libdwarfparser/libdwarfparser.h"

#include "helpers.h"

class KernelValidator {
	public:
		KernelValidator(std::string dirName,
			        	VMIInstance* vmi,
						std::string targetsFile);
		virtual ~KernelValidator();


		uint64_t validatePages();
		void validatePage(page_info_t *page);
		void setOptions(bool lm = false, bool cv = true, bool pe = true);
		static KernelValidator* getInstance();

	protected:

	private:

		struct {
			bool loopMode;
			bool codeValidation;
			bool pointerExamination;
		} options;

		static KernelValidator* instance;
		VMIInstance* vmi;
		ElfKernelLoader* kernelLoader;
		std::map<uint64_t,uint64_t> stackAddresses;
		std::multimap<uint64_t,uint64_t> callTargets;
		
		void validateCodePage(page_info_t *page, ElfLoader* elf);
		void validateDataPage(page_info_t *page, ElfLoader* elf);
		uint64_t globalCodePtrs;
		void validateStackPage(uint8_t* memory,
				uint64_t stackBottom, uint64_t stackEnd);

		void updateStackAddresses();

		void displayChange(uint8_t* memory, uint8_t* reference, 
		                   int32_t offset, int32_t size);

		void loadKernel(std::string dirName);

		uint64_t findCodePtrs(page_info_t* page, uint8_t* pageInMem);
		uint64_t isReturnAddress(uint8_t* ptr, uint32_t offset, uint64_t index);


};

#endif /* KERNELVALIDATOR_H */
