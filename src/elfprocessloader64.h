#ifndef ELFPROCESSLOADER64_H
#define ELFPROCESSLOADER64_H

#include <algorithm>
#include <vector>
#include <unordered_map>
#include <elf.h>

#include "helpers.h"
#include "elfprocessloader.h"

#ifndef ASLROFFTYPE_M
#define ASLROFFTYPE_M

#define ASLR_BRK    1
#define ASLR_STACK  2
#define ASLR_VDSO   3

#endif //ASLROFFTYPE_M

// The beauty of forward declarations
class ElfProcessLoader64;

/* This class represents a symbol a loader may export for relocation */
class RelSym{
	public:
			std::string name;           // name of the symbol
			uint64_t value;             // final vaddr after loading
			uint8_t info;               // corresponding type and sym in parent
			uint32_t shndx;             // linked section index in parent
			ElfProcessLoader64* parent; // lib in which this sym is defined

	RelSym(std::string, uint64_t, uint8_t, uint32_t, ElfProcessLoader64*);
	~RelSym();
};


/*
 * This class is a derivated ElfProcessLoader for use with 64-Bit Systems.
 * It holds a process image for validation, which is derived from the original
 * ELF by retracing the building process in the target system.
 *
 */
class ElfProcessLoader64 : public ElfProcessLoader{
/*  Important members inherited from higher classes:
 *
 *  protected:
 *      ElfFile                 *elffile;
 *      Instance                debugInstance;
 *      SegmentInfo             textSegment;
 *-------------------------------------------------------
 *  containing the following members:
 *      std::string segName;    // name of the segment, init with first sec name
 *      uint32_t    segID;      // section ID in SHT
 *      uint8_t *   index;      // section offset from beginning of ELF file
 *                              // if dereferenced contains data of the section
 *      uint8_t *   memindex;   // target virtual address in process image
 *                                 _BEWARE_: in PIC this field is subject to 
 *                                 _secure_ dynamic modifications by the loader
 *                                 to suit a given address space! It may not
 *                                 resemble the original entry in the whitelisted
 *                                 ELF-File.
 *      uint32_t    size;       // size of the section content
 *-------------------------------------------------------
 *
 *      std::vector<uint8_t>    textSegmentContent; // actual textSegment data 
 *      uint32_t                textSegmentLength;  // size of the processImage 
 */
	friend class ProcessValidator;

	private:
		std::string execName;
		bool bindLazy;
		bool isDynamicExec; // if exec : linking type of this exec
                            // if vdso : linking type of calling exec
		bool isInLibs;
		bool isRelocatable;
		std::string vdsoPath;       // path to whitelisted vdso
		std::vector<ElfProcessLoader64*> *suppliedLibraries; // whitelisted libraries
		ElfProcessLoader64 *memImageVDSO; // whitelisted VDSO image
		uint64_t vdsoAddr; // if exec : Starting vaddr of the VDSO Image
                           // if vdso : 0 [the vdso doesn't care where it is at]
		std::vector<std::string> depNames; // names of direct dependencies
					
		uint64_t dataSegBaseAddr; // vmemAddress of dataSegment beginning (PHT)
		uint64_t textSegBaseAddr; // dito
		uint64_t dataSegBaseOff;  // in file offset of dataSegment (PHT)
		uint64_t textSegBaseOff;  // dito
		uint8_t dataSegPHTid;     // PHTid of first entry in dataSeg
		uint8_t textSegPHTid;     // dito
		uint8_t dataSegSHTid;     // SHT id ...
		uint8_t textSegSHTid;     // dito
		uint32_t pageSize;        // std pageSize (0x1000 on current x86-64)

		SegmentInfo dataSegment;  // handler for dataSegment (after init)
		SegmentInfo heapSegment;  // handler for optional heap segment
		std::vector<uint8_t> dataSegmentContent;   // actual dataSegment data
		std::vector<uint8_t> heapSegmentContent;
		uint32_t dataSegmentLength;                // size of the processImage
		uint32_t heapSegmentLength;

		std::vector<RelSym*> providedSyms; // symbols provided by this loader
		std::map<std::string, uint32_t> neededSyms; // first:name, second:symtabID


		std::vector<Elf64_Rel> rel;   // relocation entries of the file (.rel)
		std::vector<Elf64_Rela> rela; // dito (.rela)


	public:
		ElfProcessLoader64(ElfFile64 *elffile, 
			   	KernelManager *parent,
		        std::string name = ""
				);
		virtual ~ElfProcessLoader64();
		virtual void printImage();
		virtual std::string getName();
        virtual uint64_t getVDSOAddr();
		virtual uint64_t getTextStart();
		virtual uint64_t getDataStart();
		virtual uint64_t getDataOff();
		virtual uint64_t getTextOff();
		virtual uint64_t getHeapStart();
        virtual uint32_t getTextSize();
		virtual uint32_t getDataSize();

		virtual std::vector<RelSym*> getProvidedSyms();
		virtual std::vector<ElfProcessLoader64*> *getLibraries();

		virtual void parseElfFile();// Initialize the complete image
		virtual void initIsRelocatable();
		virtual void initDepNames();
		virtual std::vector<std::string> getDepNames(); // get Names of needed libraries

	protected:
		virtual void supplyVDSO(ElfProcessLoader64 *vdso);
		virtual void supplyLibraries(std::vector<ElfProcessLoader64*> *libs);

		virtual void initText();    // Initialize the first memory segment
		virtual void initData();    // Initialize the second memory segment
        virtual void initIsDynamic(); //check if the binary is dynamically linked

        //Add all sections between [startAddr,endAddr) to the target image
        virtual void addSectionsToSeg(ElfFile64 *elf, int nrSecHeaders,
                                      int prevMemAddr, int prevSecSize,
                                      uint64_t startAddr, uint64_t endAddr,
                                      SegmentInfo *handler,
                                      std::vector<uint8_t> *target,
                                      uint32_t *targetLength);


		virtual bool isCodeAddress(uint64_t addr);
		virtual bool isDataAddress(uint64_t addr);
		virtual bool isTextOffset(uint64_t off);
		virtual bool isDataOffset(uint64_t off);
		virtual bool isInLibraries(ElfProcessLoader64 *lib);
		virtual bool isDynamic();

        virtual uint32_t appendSegToImage(SegmentInfo *segment,
                                          std::vector<uint8_t> *target,
                                          uint32_t offset);
		virtual uint32_t appendVecToImage(std::vector<uint8_t> *src,
                                          std::vector<uint8_t> *target);
        virtual uint32_t appendDataToImage(const void *data,
                                           uint32_t len,
                                           std::vector<uint8_t> *target);

		virtual ElfProcessLoader64* getExecForAddress(uint64_t);
		virtual SegmentInfo* getSegmentForAddress(uint64_t addr);

		virtual std::vector<Elf64_Rel> getRelEntries();
		virtual std::vector<Elf64_Rela> getRelaEntries();

		virtual void initProvidedSymbols();

		virtual uint64_t getVAForAddr(uint64_t addr, uint32_t shtID);


		virtual void applyLoadRel(std::unordered_map<std::string, RelSym*> *map);
		virtual int evalLazy(uint64_t addr,
						std::unordered_map<std::string, RelSym*> *map);
//		TODO use template instead of two separate functions
		virtual void relocate(Elf64_Rela* rel,
						std::unordered_map<std::string, RelSym*> *map);
		virtual void relocate(Elf64_Rel* rel,
						std::unordered_map<std::string, RelSym*> *map);
		virtual void writeRelValue(uint64_t locAddr, uint64_t symAddr);
        virtual void updateMemIndex(uint64_t addr, uint8_t segNr);
		virtual void setHeapSegment(SegmentInfo* heap);
		virtual void setIsLib(bool isLib);

		virtual uint64_t getOffASLR(uint8_t type); //TODO
};


#endif  /* ELFPROCESSLOADER64_H */
