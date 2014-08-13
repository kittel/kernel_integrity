#include "helpers.h"
#include "elfloader.h"

#include "exceptions.h"
#include "kernel_headers.h"


#include <cstring>
#include <cassert>

#include <iostream>
#include <typeinfo>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"


ElfLoader::ElfLoader(ElfFile* elffile):
	elffile(elffile),
	textSegment(),
	dataSegment(){

	this->ideal_nops = p6_nops;

}
ElfLoader::~ElfLoader(){}

void  ElfLoader::add_nops(void *insns, uint8_t len)
{
    while (len > 0) {
        unsigned int noplen = len;
        if (noplen > ASM_NOP_MAX)
            noplen = ASM_NOP_MAX;
        memcpy(insns, (void*) ideal_nops[noplen], noplen);
        insns = (void *) ((char*) insns + noplen);
        len -= noplen;
    }
}

uint8_t ElfLoader::paravirt_patch_nop(void) { return 0; }

uint8_t ElfLoader::paravirt_patch_ignore(unsigned len) { return len; }

uint8_t ElfLoader::paravirt_patch_insns(void *insnbuf, unsigned len,
                              const char *start, const char *end)
{
    uint8_t insn_len = end - start;

    if (insn_len > len || start == NULL)
        insn_len = len;
    else
        memcpy(insnbuf, start, insn_len);

    return insn_len;
}

uint8_t ElfLoader::paravirt_patch_jmp(void *insnbuf, uint64_t target, uint64_t addr, uint8_t len)
{
    if (len < 5) return len;

    uint32_t delta = target - (addr + 5);

    *((char*) insnbuf) = 0xe9;
    *((uint32_t*) ((char*) insnbuf + 1)) = delta;

    std::cout << "Patching jump @ " << std::hex << addr << std::dec << std::endl;

    return 5;
}

uint8_t ElfLoader::paravirt_patch_call(void *insnbuf, uint64_t target, uint16_t tgt_clobbers, uint64_t addr, uint16_t site_clobbers, uint8_t len)
{
    if (tgt_clobbers & ~site_clobbers) return len;
    if (len < 5) return len;

    uint32_t delta = target - (addr + 5);

    *((char*) insnbuf) = 0xe8;
    *((uint32_t*) ((char*) insnbuf + 1)) = delta;

    return 5;
}

uint64_t ElfLoader::get_call_destination(uint32_t type)
{
    //These structs contain a function pointers.
    //In memory they are directly after each other.
    //Thus type is an index into the resulting array.

    Instance pv_init_ops = Variable::findVariableByName("pv_init_ops")->getInstance();
    Instance pv_time_ops = Variable::findVariableByName("pv_time_ops")->getInstance();
    Instance pv_cpu_ops  = Variable::findVariableByName("pv_cpu_ops" )->getInstance();
    Instance pv_irq_ops  = Variable::findVariableByName("pv_irq_ops" )->getInstance();
    Instance pv_apic_ops = Variable::findVariableByName("pv_apic_ops")->getInstance();
    Instance pv_mmu_ops  = Variable::findVariableByName("pv_mmu_ops" )->getInstance();
    Instance pv_lock_ops = Variable::findVariableByName("pv_lock_ops")->getInstance();

    if(type < pv_init_ops.size()) 
		return pv_init_ops.memberByOffset(type).getRawValue<uint64_t>();
    type -= pv_init_ops.size();
    if(type < pv_time_ops.size()) 
		return pv_time_ops.memberByOffset(type).getRawValue<uint64_t>();
    type -= pv_time_ops.size();
    if(type < pv_cpu_ops.size())  
		return pv_cpu_ops .memberByOffset(type).getRawValue<uint64_t>();
    type -= pv_cpu_ops.size();
    if(type < pv_irq_ops.size())  
		return pv_irq_ops .memberByOffset(type).getRawValue<uint64_t>();
    type -= pv_irq_ops.size();
    if(type < pv_apic_ops.size()) 
		return pv_apic_ops.memberByOffset(type).getRawValue<uint64_t>();
    type -= pv_apic_ops.size();
    if(type < pv_mmu_ops.size())  
		return pv_mmu_ops .memberByOffset(type).getRawValue<uint64_t>();
    type -= pv_mmu_ops.size();
    if(type < pv_lock_ops.size()) 
		return pv_lock_ops.memberByOffset(type).getRawValue<uint64_t>();

    return 0;
}

uint8_t ElfLoader::paravirt_patch_default(uint32_t type, uint16_t clobbers, void *insnbuf,
                                uint64_t addr, uint8_t len)
{
    uint8_t ret = 0;
    //Get Memory of paravirt_patch_template + type
    uint64_t opfunc = get_call_destination(type);

//    std::cout << "Call address is: " << hex
//                   << opfunc << " "
//                   << dec << std::endl;

    uint64_t nopFuncAddress = 0;
    uint64_t ident32NopFuncAddress = 0;
    uint64_t ident64NopFuncAddress = 0;
	
    nopFuncAddress = this->elffile->
				findAddressOfVariable("_paravirt_nop");
    ident32NopFuncAddress = this->elffile->
				findAddressOfVariable("_paravirt_ident_32");
    ident64NopFuncAddress = this->elffile->
				findAddressOfVariable("_paravirt_ident_64");
	assert(ident64NopFuncAddress);

    //Get pv_cpu_ops to check offsets in else clause
    const Structured * pptS = 
		dynamic_cast<const Structured*>(
				BaseType::findBaseTypeByName("paravirt_patch_template"));
	assert(pptS);

    uint32_t pv_cpu_opsOffset = pptS->memberOffset("pv_cpu_ops");
    Variable *pv_cpu_ops_var = Variable::findVariableByName("pv_cpu_ops");
	assert(pv_cpu_ops_var);
    Instance pv_cpu_ops = pv_cpu_ops_var->getInstance();
    
    if (!opfunc)
    {
        // opfunc == NULL
        /* If there's no function, patch it with a ud2a (BUG) */
        //If this is a module this is a bug anyway so this should not happen.
        //ret = paravirt_patch_insns(insnbuf, len, ud2a, ud2a+sizeof(ud2a));
        //If this the kernel this can happen and is only filled with nops
        ret = paravirt_patch_nop();
    }
    //TODO get address of Function Paravirt nop
    else if (opfunc == nopFuncAddress){
        /* If the operation is a nop, then nop the callsite */
        ret = paravirt_patch_nop();
	}
    /* identity functions just return their single argument */
    else if (opfunc == ident32NopFuncAddress){
        ret = paravirt_patch_insns(insnbuf, len, start__mov32, end__mov32);
	}
    else if (opfunc == ident64NopFuncAddress){
        ret = paravirt_patch_insns(insnbuf, len, start__mov64, end__mov64);
	}
    else if (type == pv_cpu_opsOffset + pv_cpu_ops.memberOffset("iret") ||
             type == pv_cpu_opsOffset + pv_cpu_ops.memberOffset("irq_enable_sysexit") ||
             type == pv_cpu_opsOffset + pv_cpu_ops.memberOffset("usergs_sysret32") ||
             type == pv_cpu_opsOffset + pv_cpu_ops.memberOffset("usergs_sysret64"))
    {
        /* If operation requires a jmp, then jmp */
        //std::cout << "Patching jump!" << std::endl;
        ret = paravirt_patch_jmp(insnbuf, opfunc, addr, len);
        //TODO add Jump Target
		//if (!_paravirtJump.contains(opfunc))
        //{
        //    _paravirtJump.append(opfunc);
        //}
    }
    else
    {
        /* Otherwise call the function; assume target could
           clobber any caller-save reg */
        ret = paravirt_patch_call(insnbuf, opfunc, CLBR_ANY,
                                  addr, clobbers, len);
		//TODO add call target
        //if (!_paravirtCall.contains(opfunc))
        //{
        //    _paravirtCall.append(opfunc);
        //}
    }
    return ret;
}

uint32_t ElfLoader::paravirtNativePatch(uint32_t type, uint16_t clobbers, void *ibuf,
                             unsigned long addr, unsigned len)
{
    uint32_t ret = 0;

    const Structured * pptS = 
		dynamic_cast<const Structured*>(
				BaseType::findBaseTypeByName("paravirt_patch_template"));
	assert(pptS);

    uint32_t pv_irq_opsOffset = pptS->memberOffset("pv_irq_ops");
    Variable *pv_irq_ops_var = Variable::findVariableByName("pv_irq_ops");
	assert(pv_irq_ops_var);
    Instance pv_irq_ops = pv_irq_ops_var->getInstance();
	
    uint32_t pv_cpu_opsOffset = pptS->memberOffset("pv_cpu_ops");
    Variable *pv_cpu_ops_var = Variable::findVariableByName("pv_cpu_ops");
	assert(pv_cpu_ops_var);
    Instance pv_cpu_ops = pv_cpu_ops_var->getInstance();
    
	uint32_t pv_mmu_opsOffset = pptS->memberOffset("pv_mmu_ops");
    Variable *pv_mmu_ops_var = Variable::findVariableByName("pv_mmu_ops");
	assert(pv_mmu_ops_var);
    Instance pv_mmu_ops = pv_mmu_ops_var->getInstance();
    

#define PATCH_SITE(ops, x)		\
  else if(type == ops##Offset + ops.memberOffset("" #x )) \
  {                                                         \
      ret = paravirt_patch_insns(ibuf, len, start_##ops##_##x, end_##ops##_##x);    \
  } 

    if(false){}
    PATCH_SITE(pv_irq_ops, restore_fl)
    PATCH_SITE(pv_irq_ops, save_fl)
    PATCH_SITE(pv_irq_ops, irq_enable)
    PATCH_SITE(pv_irq_ops, irq_disable)
    PATCH_SITE(pv_cpu_ops, iret)
    PATCH_SITE(pv_cpu_ops, irq_enable_sysexit)
    PATCH_SITE(pv_cpu_ops, usergs_sysret32)
    PATCH_SITE(pv_cpu_ops, usergs_sysret64)
    PATCH_SITE(pv_cpu_ops, swapgs)
    PATCH_SITE(pv_mmu_ops, read_cr2)
    PATCH_SITE(pv_mmu_ops, read_cr3)
    PATCH_SITE(pv_mmu_ops, write_cr3)
    PATCH_SITE(pv_cpu_ops, clts)
    PATCH_SITE(pv_mmu_ops, flush_tlb_single)
    PATCH_SITE(pv_cpu_ops, wbinvd)

    else
    {
        ret = paravirt_patch_default(type, clobbers, ibuf, addr, len);
    }
#undef PATCH_SITE
    return ret;
}

void ElfLoader::applyAltinstr(){
    uint8_t *instr;
    uint8_t *replacement;
    unsigned char insnbuf[255-1];

	SegmentInfo altinst = this->elffile->findSegmentWithName(".altinstructions");
	if (!altinst.index) return;

    SegmentInfo altinstreplace;
	altinstreplace = this->elffile->
			findSegmentWithName(".altinstr_replacement");

    struct alt_instr *start = (struct alt_instr*) altinst.index;
    struct alt_instr *end = (struct alt_instr*) (altinst.index + altinst.size);

	this->updateSegmentInfoMemAddress(altinstreplace);
	
	//Find boot_cpu_data in kernel
	Variable *boot_cpu_data_var = Variable::findVariableByName("boot_cpu_data");
	assert(boot_cpu_data_var);

	Instance boot_cpu_data = boot_cpu_data_var->getInstance();

    for(struct alt_instr * a = start ; a < end ; a++)
    {
        //if (!boot_cpu_has(a->cpuid)) continue;
		
        Instance x86_capability = boot_cpu_data.memberByName("x86_capability");
        if (!((x86_capability.arrayElem(a->cpuid / 32).
						getRawValue<uint32_t>() >> (a->cpuid % 32)) & 0x1)){ 
			continue;
        }

        instr = ((uint8_t *)&a->instr_offset) + a->instr_offset;
        replacement = ((uint8_t *)&a->repl_offset) + a->repl_offset;

		//If this is the a kernel then adjust the address of the instruction to replace
        if(dynamic_cast<ElfKernelLoader*>(this))
        {
            instr -= (uint64_t)(this->textSegment.index - 
					(uint64_t) this->elffile->getFileContent());
        }

        memcpy(insnbuf, replacement, a->replacementlen);

        // 0xe8 is a relative jump; fix the offset.
        if (insnbuf[0] == 0xe8 && a->replacementlen == 5)
        {
            //If replacement is in the altinstr_replace section fix the offset.
            if(replacement >= (uint8_t *)altinstreplace.index && 
				replacement < (uint8_t *)altinstreplace.index + altinstreplace.size)
            {
                *(int32_t *)(insnbuf + 1) -= (altinstreplace.index - this->textSegment.index) - (altinstreplace.memindex - this->textSegment.memindex);

            }
            *(int32_t *)(insnbuf + 1) += replacement - instr;
        }

        //add_nops
        add_nops(insnbuf + a->replacementlen, a->instrlen - a->replacementlen);

        memcpy(instr, insnbuf, a->instrlen);
    }
}

void ElfLoader::applyParainstr(){
	SegmentInfo info = this->elffile->findSegmentWithName(".parainstructions");
	if (!info.index) return;
    
    //TODO add paravirt entries
    //bool addParavirtEntries = false;	
	//if(context.paravirtEntries.size() == 0) addParavirtEntries = true;
	
    struct paravirt_patch_site *start = (struct paravirt_patch_site *) info.index;
    struct paravirt_patch_site *end = (struct paravirt_patch_site *) (info.index + info.size);

    char insnbuf[254];

    //noreplace_paravirt is 0 in the kernel
    //http://lxr.free-electrons.com/source/arch/x86/kernel/alternative.c#L45
    //if (noreplace_paravirt) return;

    for (struct paravirt_patch_site *p = start; p < end; p++) {
        unsigned int used;

        //BUG_ON(p->len > MAX_PATCH_LEN);
		//parainstructions: impossible length
        assert(p->len < 255);

		//TODO readd when needed
		//if(addParavirtEntries) {
		//    this->paravirtEntries.insert((uint64_t) p->instr);
		//}
		
        //p->instr points to text segment in memory
        //let it point to the address in the elf binary
        uint8_t * instrInElf = p->instr;
        instrInElf -= (uint64_t) this->textSegment.memindex;
        instrInElf += (uint64_t) this->textSegment.index;

        /* prep the buffer with the original instructions */
        memcpy(insnbuf, instrInElf, p->len);

        //p->instrtype is used as an offset to an array of pointers. 
		//Here we only use ist as Offset.
        used = paravirtNativePatch(p->instrtype * 8, p->clobbers, insnbuf,
                                   (unsigned long)p->instr, p->len);

		//"parainstructions: impossible length"
        assert(p->len < 255);

        /* Pad the rest with nops */
        add_nops(insnbuf + used, p->len - used);      //add_nops
        memcpy(instrInElf, insnbuf, p->len);   //memcpy
    }
}

void ElfLoader::applySmpLocks(){
	SegmentInfo info = this->elffile->findSegmentWithName(".smp_locks");
	if (!info.index) return;
}

void ElfLoader::applyMcount(SegmentInfo &info){
	UNUSED(info);
}

void ElfLoader::applyJumpEntries(uint64_t jumpStart, uint64_t jumpStop){
	UNUSED(jumpStart);
	UNUSED(jumpStop);
}

void ElfLoader::parseElfFile(){
	this->initText();
	this->initData();
}

//int ElfLoader64::apply_relocate()
//{
//	char* fileContent = this->elffile->getFileContent;
//
//    Elf64_Rela *rel = (Elf64_Rela *) (fileContent + elf64Shdr[context.relsec].sh_offset);
//    Elf32_Word sectionId = sechdrs[context.relsec].sh_info;
//    QString sectionName = QString(fileContent + sechdrs[context.shstrindex].sh_offset + sechdrs[sectionId].sh_name);
//
//    //Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;
//
//    Elf64_Sym *symBase = (Elf64_Sym *) (fileContent + sechdrs[context.symindex].sh_offset);
//    Elf64_Sym *sym;
//
//    void *locInElf = 0;
//    void *locInMem = 0;
//    void *locOfRelSectionInMem = 0;
//    void *locOfRelSectionInElf = 0;
//    uint64_t val;
//    uint64_t i;
//
//    void *sectionBaseElf = (void *) (fileContent + sechdrs[sectionId].sh_offset);
//    void *sectionBaseMem = 0;
//
//    sectionBaseMem = (void *) findMemAddressOfSegment(context, sectionName);
//
//    bool doPrint = false;
//
//    //if(sectionName.compare("__kcrctab_gpl") == 0) doPrint = true;
//
//    if(doPrint) std::cout << "Section to Relocate: " << sectionName << dec << std::endl;
//
//    for (i = 0; i < sechdrs[context.relsec].sh_size / sizeof(*rel); i++) {
//        /* This is where to make the change */
//        //loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr
//        //        + rel[i].r_offset;
//        locInElf = (void *) ((char*)sectionBaseElf + rel[i].r_offset);
//        locInMem = (void *) ((char*)sectionBaseMem + rel[i].r_offset);
//
//        /* This is the symbol it is referring to.  Note that all
//               undefined symbols have been resolved.  */
//        //sym = (Elf64_Sym *)sechdrs[symindex].sh_addr
//        //        + ELF64_R_SYM(rel[i].r_info);
//        //sym = (Elf64_Sym *) (fileContent + sechdrs[context.symindex].sh_offset)
//        //        + ELF64_R_SYM(rel[i].r_info);
//        sym = symBase + ELF64_R_SYM(rel[i].r_info);
//
//        Variable* v = NULL;
//        Instance symbol;
//
//        QString symbolName = QString(&((fileContent + sechdrs[context.strindex].sh_offset)[sym->st_name]));
//
//        /////////////////////////////////////////////////////////////////////
//        //if ((unsigned long) locInMem == 0xffffffffa0000006) doPrint = true;
//        //if (rel[i].r_offset == 0xf1f) doPrint = true;
//        //if (symbolName.compare("snd_pcm_set_sync") == 0) doPrint = true;
//        //if(context.currentModule.member("name").toString().compare("\"virtio_balloon\"") == 0 && rel[i].r_offset == 0xb43) doPrint = true;
//        //        sectionName.compare(".altinstructions") == 0 && i <= 1) doPrint = true;
//        /////////////////////////////////////////////////////////////////////
//
//        if(doPrint) std::cout << std::endl;
//        if(doPrint) std::cout << "Loc in Elf: " << hex << locInElf << dec << std::endl;
//        if(doPrint) std::cout << "Loc in Mem: " << hex << locInMem << dec << std::endl;
//        if(doPrint) std::cout << "Sym: " << hex << symbolName << " @ " << sym << " (Offset: 0x" << ELF64_R_SYM(rel[i].r_info) << " , Info: 0x" << sym->st_info << " )" << " Bind type: " << ELF64_ST_BIND(sym->st_info) << dec << std::endl;
//
//        if(doPrint) std::cout << "Name of current Section: " << QString(fileContent + sechdrs[context.shstrindex].sh_offset + sechdrs[sectionId].sh_name) << std::endl;
//        //			std::cout << "type " << (int)ELF64_R_TYPE(rel[i].r_info) << " st_value " << sym->st_value << " r_addend " << rel[i].r_addend << " loc " << hex << (u64)loc << dec << std::endl;
//
//        switch(sym->st_shndx){
//        case SHN_COMMON:
//            if(doPrint) std::cout << "Symtype SHN_UNDEF" << std::endl;
//            debugerr("This should not happen!");
//            continue; //TODO REMOVE
//            break;
//        case SHN_ABS:
//            if(doPrint) std::cout << "Symtype SHN_ABS" << std::endl;
//            //printf("Nothing to do!\n");
//            break;
//        case SHN_UNDEF:
//            //debugerr("Sym Type: SHN_UNDEF");
//
//            //Resolve Symbol and write to st_value
//            if(doPrint) std::cout << "Symtype SHN_UNDEF" << std::endl;
//            if(doPrint) std::cout << "System Map contains " << _sym.memSpecs().systemMap.count(symbolName) << " Versions of that symbol." << std::endl;
//
//
//            if(_symTable.contains(symbolName))
//            {
//                sym->st_value = _symTable.value(symbolName);
//                if(doPrint) std::cout << "Found symbol @" << hex << sym->st_value << dec << std::endl;
//            }
//            //Try to find variable in system map
//            else if (_sym.memSpecs().systemMap.count(symbolName) > 0)
//            {
//                //std::cout << "Found Variable in system.map: " << &((fileContent + sechdrs[strindex].sh_offset)[sym->st_name]) << std::endl;
//                //sym->st_value = _sym.memSpecs().systemMap.value(symbolName).address;
//                QList<SystemMapEntry> symbols = _sym.memSpecs().systemMap.values(symbolName);
//                for (QList<SystemMapEntry>::iterator i = symbols.begin(); i != symbols.end(); ++i)
//                {
//                    SystemMapEntry currentEntry = (*i);
//
//                    //ELF64_ST_BIND(sym->st_info) => 0: Local, 1: Global, 2: Weak
//                    //currentEntry.type => 'ascii' lowercase: local, uppercase: global
//                    if (ELF64_ST_BIND(sym->st_info) == 1 && currentEntry.type >= 0x41 && currentEntry.type <= 0x5a)
//                    {
//                        if(doPrint) std::cout << "Symbol found in System Map: " << hex << currentEntry.address << " With type: Global" << dec << std::endl;
//                        sym->st_value = currentEntry.address;
//                    }
//                    else if (ELF64_ST_BIND(sym->st_info) == 0 && currentEntry.type >= 0x61 && currentEntry.type <= 0x7a)
//                    {
//                        if(doPrint) std::cout << "Symbol found in System Map: " << hex << currentEntry.address << " With type: Local" << dec << std::endl;
//                        sym->st_value = currentEntry.address;
//                    }
//                }
//            }
//            else
//            {
//                //std::cout << "Variable not found in system.map: " << &((fileContent + sechdrs[strindex].sh_offset)[sym->st_name]) << std::endl;
//                //Try to find the variable by name in insight.
//                v = _sym.factory().findVarByName(symbolName);
//                if (!v)
//                {
//                    //debugerr("Variable " << &((fileContent + sechdrs[strindex].sh_offset)[sym->st_name]) << " not found! ERROR!");
//                    QList<BaseType*> types = _sym.factory().typesByName().values(symbolName);
//
//                    if(types.size() > 0)
//                    {
//                        BaseType* bt;
//                        //std::cout << "Type found in insight: " << &((fileContent + sechdrs[strindex].sh_offset)[sym->st_name]) << std::endl;
//                        for(int k = 0 ; k < types.size() ; k++)
//                        {
//                            bt = types.at(k);
//                            //std::cout << k << ": " << (bt && (bt->type() == rtFunction) ? "function" : "type") << " with size " <<  bt->size() << std::endl;
//                            // Only use the type if it is a function and got a defined size
//                            if( bt->type() == rtFunction && bt->size() > 0) { break; }
//
//                            if(k == types.size() - 1)
//                            {
//                                //std::cout << "Function not found in insight: " << symbolName << std::endl;
//                                //TODO handle this case does this happen??
//                            }
//                        }
//                        const Function* func = dynamic_cast<const Function*>(bt);
//
//                        if (func) {
//                            sym->st_value = func->pcLow();
//                            if(doPrint) std::cout << "Function found in: " << hex << sym->st_value << dec << std::endl;
//                            //TODO check if somewhere the startaddress is zero! bug!
////                            std::cout << Console::color(ctColHead) << "  Start Address:  "
////                                 << Console::color(ctAddress) << QString("0x%1").arg(
////                                                            func->pcLow(),
////                                                            _sym.memSpecs().sizeofPointer << 1,
////                                                            16,
////                                                            QChar('0'))
////                                 << Console::color(ctReset)
////                                 << std::endl;
//                        }
//
//                    } //Else no type with with the given name found.
//                    continue;
//                }
//                //std::cout << "Variable found in insight: " << &((fileContent + sechdrs[strindex].sh_offset)[sym->st_name]) << std::endl;
//                symbol = v->toInstance(_vmem, BaseType::trLexical, ksAll);
//                if(!symbol.isValid())
//                {
//                    debugerr("Symbol " << symbolName << " not found! ERROR!");
//                    continue;
//                }
//                //std::cout << "Symbol found with address : 0x" << hex << symbol.address() << dec << std::endl;
//                sym->st_value = symbol.address();
//
//                if(doPrint) std::cout << "Instance found: " << hex << sym->st_value << dec << std::endl;
//
//            }
//
//            break;
//        default:
//            if(doPrint) std::cout << "default: " << std::endl;
//            //debugerr("Sym Type: default: " << sym->st_shndx);
//
//            //TODO this is not right yet.
//            /* Divert to percpu allocation if a percpu var. */
//            if (sym->st_shndx == context.percpuDataSegment)
//            {
//                locOfRelSectionInMem = context.currentModule.member("percpu").toPointer();
//                //sym->st_value += (unsigned long)mod_percpu(mod);
//                if(doPrint) std::cout << "Per CPU variable" << std::endl;
//            }
//            else
//            {
//                QString relocSection = QString(&((fileContent + sechdrs[context.shstrindex].sh_offset)[sechdrs[sym->st_shndx].sh_name]));
//                locOfRelSectionInElf = (void *) findElfSegmentWithName(fileContent, relocSection).index;
//                locOfRelSectionInMem = (void *) findMemAddressOfSegment(context, relocSection);
//                if(doPrint) std::cout << "SectionName: " << hex << relocSection << dec << std::endl;
//            }
//
//            //Only add the location of the section if it was not already added
//            if(doPrint) std::cout << "old st_value: " << hex << sym->st_value << dec;
//            if(doPrint) std::cout << " locOfRelSectionInMem: " << hex << locOfRelSectionInMem << dec;
//            if(doPrint) std::cout << " locOfRelSectionInElf: " << hex << locOfRelSectionInElf << dec << std::endl;
//
//            if(sym->st_value < (long unsigned int) locOfRelSectionInMem)
//            {
//                sym->st_value += (long unsigned int) locOfRelSectionInMem;
//            }
//
//            break;
//        }
//
//        val = sym->st_value + rel[i].r_addend;
//
//        if(doPrint) std::cout << "raddend: " << hex << rel[i].r_addend << dec << std::endl;
//        if(doPrint) std::cout << "sym->value: " << hex << sym->st_value << dec << std::endl;
//        if(doPrint) std::cout << "val: " << hex << val << dec << std::endl;
//
//        switch (ELF64_R_TYPE(rel[i].r_info)) {
//        case R_X86_64_NONE:
//            break;
//        case R_X86_64_64:
//            *(uint64_t *)locInElf = val;
//            break;
//        case R_X86_64_32:
//            *(uint32_t *)locInElf = val;
//            if (val != *(uint32_t *)locInElf)
//                goto overflow;
//            break;
//        case R_X86_64_32S:
//            *(qint32 *)locInElf = val;
//            if(doPrint) std::cout << " 32S final value: " << hex << (qint32) val << dec << std::endl;
//            if ((qint64)val != *(qint32 *)locInElf)
//                goto overflow;
//            break;
//        case R_X86_64_PC32:
//
//            //This line is from the original source the loc here is the location within the loaded module.
//            //val -= (u64)loc;
//            if(sectionName.compare(".altinstructions") == 0)
//            {
//                //This is later used to copy some memory
//                val = val - (uint64_t)locOfRelSectionInMem + (uint64_t)locOfRelSectionInElf - (uint64_t)locInElf;
//            }
//            else
//            {
//                //This is used as relocation in memory
//                val -= (uint64_t)locInMem;
//            }
//            if(doPrint) std::cout << "PC32 final value: " << hex << (uint32_t) val << dec << std::endl;
//            *(uint32_t *)locInElf = val;
//#if 0
//            if ((qint64)val != *(qint32 *)loc)
//                goto overflow;
//#endif
//            break;
//        default:
//            debugerr("Unknown rela relocation: " << ELF64_R_TYPE(rel[i].r_info));
//            return -ENOEXEC;
//        }
//        doPrint = false;
//    }
//    return 0;
//
//overflow:
//    Console::err() << "overflow in relocation type " << (int)ELF64_R_TYPE(rel[i].r_info) << " val " << hex << val << std::endl;
//    Console::err() << "likely not compiled with -mcmodel=kernel" << std::endl;
//    return -ENOEXEC;
//	return 0;
//}

////////////////////////////////////////////////////

ElfKernelLoader::ElfKernelLoader(ElfFile* elffile):
	ElfLoader(elffile),
	vvarSegment(),
	dataNosaveSegment(),
	bssSegment(),
	rodataSegment(),
	fentryAddress(0),
	genericUnrolledAddress(0),

	textSegmentContent(),
	jumpTable(){}

ElfKernelLoader::~ElfKernelLoader(){}

void ElfKernelLoader::initText(void) {

	ElfFile64* elffile = dynamic_cast<ElfFile64*>(this->elffile);

	this->textSegment = elffile->findSegmentWithName(".text");
	this->updateSegmentInfoMemAddress(this->textSegment);
	
	this->dataSegment = elffile->findSegmentWithName(".data");
	this->vvarSegment = elffile->findSegmentWithName(".vvar");
	this->dataNosaveSegment = elffile->findSegmentWithName(".data_nosave");
	this->bssSegment = elffile->findSegmentWithName(".bss");


	this->fentryAddress = this->elffile->findAddressOfVariable("__fentry__");
	this->genericUnrolledAddress = this->
			elffile->findAddressOfVariable("copy_user_generic_unrolled");

	applyAltinstr();
	applyParainstr();
	applySmpLocks();


	this->textSegmentContent.insert(this->textSegmentContent.end(),
			this->textSegment.index,
			this->textSegment.index + this->textSegment.size);


	SegmentInfo info = elffile->findSegmentWithName(".notes");
	uint64_t offset = (uint64_t) info.index - (uint64_t) this->textSegment.index;
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			offset - this->textSegmentContent.size(), 0);
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			info.index, info.index + info.size);

	info = elffile->findSegmentWithName("__ex_table");
	offset = (uint64_t) info.index - (uint64_t) this->textSegment.index;
	this->textSegmentContent.insert(this->textSegmentContent.end(),
				offset - this->textSegmentContent.size(), 0);
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			info.index, info.index + info.size);


	//Apply Ftrace changes
	info = elffile->findSegmentWithName(".init.text");
	uint64_t initTextOffset = -(uint64_t) info.address + (uint64_t) info.index;

	info.index = (char *) elffile->findAddressOfVariable("__start_mcount_loc") + initTextOffset;
	info.size = (char *) elffile->findAddressOfVariable("__stop_mcount_loc") + initTextOffset - info.index;
	applyMcount(info);

	//TODO! also enable this some time later
	//Apply Tracepoint changes
	//    SegmentInfo rodata = findElfSegmentWithName(fileContent, ".rodata");
	//    qint64 rodataOffset = - (quint64)rodata.address + (quint64)rodata.index;
	//    info.index = (char *)findElfAddressOfVariable(fileContent, context, "__start___tracepoints_ptrs") + rodataOffset;
	//    info.size = (char *)findElfAddressOfVariable(fileContent, context, "__stop___tracepoints_ptrs") + rodataOffset - info.index ;
	//    applyTracepoints(info, rodata, context, textSegmentContent);

	info = elffile->findSegmentWithName(".data");
	int64_t dataOffset = -(uint64_t) info.address + (uint64_t) info.index;
	uint64_t jumpStart = elffile->findAddressOfVariable("__start___jump_table");
	uint64_t jumpStop = elffile->findAddressOfVariable("__stop___jump_table");

	info.index = (char *) jumpStart + dataOffset;
	info.size = (char *) jumpStop + dataOffset - info.index;

	//Save the jump_labels section for later reference.
	if (info.index != 0){
		this->jumpTable.insert(this->jumpTable.end(),
					info.index, info.index + info.size);
	}

	applyJumpEntries( jumpStart, jumpStop);
}

//TODO the following must also be put in its own function
//
//	// Hash
//	QCryptographicHash hash(QCryptographicHash::Sha1);
//
//	for (int i = 0;
//			i <= context.textSegmentContent.size() / KERNEL_CODEPAGE_SIZE;
//			i++) {
//		PageData page = PageData();
//		hash.reset();
//		// Caclulate hash of one segment at the ith the offset
//		QByteArray segment = context.textSegmentContent.mid(
//				i * KERNEL_CODEPAGE_SIZE, KERNEL_CODEPAGE_SIZE);
//		if (!segment.isEmpty()) {
//			//Remember how long the contents of the text segment are,
//			//this is to identify the uninitialized data
//			if (segment.size() != KERNEL_CODEPAGE_SIZE) {
//				if ((segment.size() + 1) % PAGE_SIZE != 0) {
//					quint32 size = segment.size();
//					size += PAGE_SIZE - (size % PAGE_SIZE);
//					context.textSegmentInitialized = i * KERNEL_CODEPAGE_SIZE
//							+ size;
//				}
//			}
//			segment = segment.leftJustified(KERNEL_CODEPAGE_SIZE, 0);
//			page.content = segment;
//			hash.addData(page.content);
//			page.hash = hash.result();
//			context.textSegmentData.append(page);
//		}
//		//Console::out() << "The " << i << "th segment got a hash of: " << segmentHashes.last().toHex() << " Sections." << endl;
//	}
//
void ElfKernelLoader::initData(void){

//	//TODO
//	//.data
//	//.vvar
//	QByteArray vvarSegmentContent = QByteArray();
//	vvarSegmentContent.append(context.vvarSegment.index,
//			context.vvarSegment.size);
//	for (int i = 0; i <= vvarSegmentContent.size() / 0x1000; i++) {
//		PageData page = PageData();
//		hash.reset();
//		// Caclulate hash of one segment at the ith the offset
//		QByteArray segment = vvarSegmentContent.mid(i * 0x1000, 0x1000);
//		if (!segment.isEmpty()) {
//			segment = segment.leftJustified(0x1000, 0);
//			page.content = segment;
//			hash.addData(page.content);
//			page.hash = hash.result();
//			context.vvarSegmentData.append(page);
//		}
//	}
//	//.data_nosave
//	QByteArray dataNosaveSegmentContent = QByteArray();
//	dataNosaveSegmentContent.append(context.vvarSegment.index,
//			context.vvarSegment.size);
//	for (int i = 0; i <= dataNosaveSegmentContent.size() / 0x1000; i++) {
//		PageData page = PageData();
//		hash.reset();
//		// Caclulate hash of one segment at the ith the offset
//		QByteArray segment = dataNosaveSegmentContent.mid(i * 0x1000, 0x1000);
//		if (!segment.isEmpty()) {
//			segment = segment.leftJustified(0x1000, 0);
//			page.content = segment;
//			hash.addData(page.content);
//			page.hash = hash.result();
//			context.dataNosaveSegmentData.append(page);
//		}
//	}
//	//.bss
//
}
//
//	//Initialize the symTable in the context for later reference
//	if (fileContent[4] == ELFCLASS32) {
//		//TODO
//	} else if (fileContent[4] == ELFCLASS64) {
//		Elf64_Ehdr * elf64Ehdr = (Elf64_Ehdr *) fileContent;
//		Elf64_Shdr * elf64Shdr = (Elf64_Shdr *) (fileContent
//				+ elf64Ehdr->e_shoff);
//
//		quint32 symSize = elf64Shdr[context.symindex].sh_size;
//		Elf64_Sym *symBase = (Elf64_Sym *) (fileContent
//				+ elf64Shdr[context.symindex].sh_offset);
//
//		for (Elf64_Sym * sym = symBase;
//				sym < (Elf64_Sym *) (((char*) symBase) + symSize); sym++) {
//			//We also need to know about private functions for data verification, so also save them here.
//			//TODO fix scope
//			if (ELF64_ST_TYPE(sym->st_info) & (STT_FUNC)
//					|| (ELF64_ST_TYPE(sym->st_info) == (STT_NOTYPE)))
//					//if(ELF64_ST_TYPE(sym->st_info) & (STT_FUNC) || (ELF64_ST_TYPE(sym->st_info) == (STT_NOTYPE) && ELF64_ST_BIND(sym->st_info) & STB_GLOBAL))
//					{
//				QString symbolName =
//						QString(
//								&((fileContent
//										+ elf64Shdr[context.strindex].sh_offset)[sym->st_name]));
//				quint64 symbolAddress = sym->st_value;
//				_funcTable.insert(symbolName, symbolAddress);
//			}
//			if (ELF64_ST_BIND(sym->st_info) & STB_GLOBAL) {
//				QString symbolName =
//						QString(
//								&((fileContent
//										+ elf64Shdr[context.strindex].sh_offset)[sym->st_name]));
//				quint64 symbolAddress = sym->st_value;
//				if (!_symTable.contains(symbolName)) {
//					_symTable.insert(symbolName, symbolAddress);
//				}
//			}
//		}
//	}
//
//	return context;
// end of parseElfFile()

void ElfKernelLoader::updateSegmentInfoMemAddress(SegmentInfo &info){
	info.memindex = (char*) info.address;
}

////////////////////////////////////////////////////

ElfModuleLoader::ElfModuleLoader(ElfFile* elffile):
	ElfLoader(elffile){}

ElfModuleLoader::~ElfModuleLoader(){}

void ElfModuleLoader::loadDependencies(void) {
	SegmentInfo miS = elffile->findSegmentWithName(".modinfo");

	//parse .modinfo and load dependencies
	char *modinfo = (char*) miS.memindex;
	while (modinfo < (char*) (miS.memindex) + miS.size)
	{
		if(!*modinfo) modinfo++;
		std::string string = std::string(modinfo);

		//if(string.compare(0, 7, "depends")){
		//	std::string dependencies = split("=").at(1).split(',');

		//	//std::cout << "Parsing dependencies:"<< std::endl;
		//	for(int i = 0; i < dependencies.size(); i++)
		//	{
		//		if (dependencies.at(i).compare(""))
		//		{
		//			loadElfModule(dependencies.at(i), findModuleByName(dependencies.at(i)));
		//		}
		//	}
		//	//std::cout << "Done Parsing dependencies:"<< std::endl;
		//	break;
		//}
		modinfo += string.length() + 1;
	}

}

void ElfModuleLoader::initText(void) {
        
	if (!this->elffile->isRelocatable()){
		assert(false);
		std::cout << "Not a relocatable module" << std::endl;
	}

	this->textSegment = elffile->findSegmentWithName(".text");
	this->dataSegment = elffile->findSegmentWithName(".data");

	SegmentInfo percpuDataSegment = elffile->findSegmentWithName(".data..percpu");

	this->loadDependencies();
//
//        ///* loop through every section */
//        for(unsigned int i = 0; i < elf64Ehdr->e_shnum; i++)
//        {
//
//            /* if Elf64_Shdr.sh_addr isn't 0 the section will appear in memory*/
//            tempBuf = fileContent + elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset + elf64Shdr[i].sh_name;
//            unsigned int infosec = elf64Shdr[i].sh_info;
//
//            /* Not a valid relocation section? */
//            if (infosec >= elf64Ehdr->e_shnum)
//                continue;
//
//            /* Don't bother with non-allocated sections */
//            if (!(elf64Shdr[infosec].sh_flags & SHF_ALLOC))
//                continue;
//
//            if (elf64Shdr[i].sh_type == SHT_REL){
//                std::cout << "Section '" << tempBuf << "': apply_relocate" << std::endl;
//                //TODO this is only in the i386 case!
//                //apply_relocate(fileContent, elf64Shdr, symindex, strindex, i);
//            }
//            else if (elf64Shdr[i].sh_type == SHT_RELA){
//
//                context.relsec = i;
//                apply_relocate_add(elf64Shdr, context);
//                //std::cout << "Section '" << tempBuf << "': apply_relocate_add" << std::endl;
//            }
//            //printf("Section '%s' with type: %i starts at 0x%08X and ends at 0x%08X\n", tempBuf, elf64Shdr[i].sh_type, elf64Shdr[i].sh_offset, elf64Shdr[i].sh_offset + elf64Shdr[i].sh_size);
//
//        }
//
//
////64bit part end
//
//    //module_finalize  => http://lxr.free-electrons.com/source/arch/x86/kernel/module.c#L167
//
//    SegmentInfo info = findElfSegmentWithName(fileContent, ".altinstructions");
//    if (info.index) applyAltinstr(info, context);
//
//    info = findElfSegmentWithName(fileContent, ".parainstructions");
//    if (info.index) applyParainstr(info, context);
//
//    info = findElfSegmentWithName(fileContent, ".smp_locks");
//    if (info.index) applySmpLocks(info, context);
//
//    //Content of text section in memory:
//    //same as the sections in the elf binary
//
//    context.textSegmentContent.clear();
//    context.textSegmentContent.append(context.textSegment.index, context.textSegment.size);
//
//    if(fileContent[4] == ELFCLASS32)
//    {
//        //TODO
//    }
//    else if(fileContent[4] == ELFCLASS64)
//    {
//        Elf64_Ehdr * elf64Ehdr = (Elf64_Ehdr *) fileContent;
//        Elf64_Shdr * elf64Shdr = (Elf64_Shdr *) (fileContent + elf64Ehdr->e_shoff);
//        for(unsigned int i = 0; i < elf64Ehdr->e_shnum; i++)
//        {
//            QString sectionName = QString(fileContent + elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset + elf64Shdr[i].sh_name);
//
//            if(elf64Shdr[i].sh_flags == (SHF_ALLOC | SHF_EXECINSTR) &&
//                    sectionName.compare(".text") != 0 &&
//                    sectionName.compare(".init.text") != 0)
//            {
//                context.textSegmentContent.append(fileContent + elf64Shdr[i].sh_offset, elf64Shdr[i].sh_size);
//            }
//        }
//    }
//
//
//    //Save the jump_labels section for later reference.
//
//    info = findElfSegmentWithName(fileContent, "__jump_table");
//    if(info.index != 0) context.jumpTable.append(info.index, info.size);
//
//    updateKernelModule(context);
//
//    //Initialize the symTable in the context for later reference
//    if(fileContent[4] == ELFCLASS32)
//    {
//        //TODO
//    }
//    else if(fileContent[4] == ELFCLASS64)
//    {
//        Elf64_Ehdr * elf64Ehdr = (Elf64_Ehdr *) fileContent;
//        Elf64_Shdr * elf64Shdr = (Elf64_Shdr *) (fileContent + elf64Ehdr->e_shoff);
//
//        uint32_t symSize = elf64Shdr[context.symindex].sh_size;
//        Elf64_Sym *symBase = (Elf64_Sym *) (fileContent + elf64Shdr[context.symindex].sh_offset);
//
//        for(Elf64_Sym * sym = symBase; sym < (Elf64_Sym *) (((char*) symBase) + symSize) ; sym++)
//        {
//            if((ELF64_ST_TYPE(sym->st_info) & (STT_OBJECT | STT_FUNC)) && ELF64_ST_BIND(sym->st_info) & STB_GLOBAL )
//            {
//                QString symbolName = QString(&((fileContent + elf64Shdr[context.strindex].sh_offset)[sym->st_name]));
//                uint64_t symbolAddress = sym->st_value;
//
//
//                if(!_symTable.contains(symbolName))
//                {
//                    _symTable.insert(symbolName, symbolAddress);
//                }
//            }
//            //We also have to consider local functions
//            //if((ELF64_ST_TYPE(sym->st_info) & STT_FUNC) && ELF64_ST_BIND(sym->st_info) & STB_GLOBAL)
//            if((ELF64_ST_TYPE(sym->st_info) == STT_FUNC))
//            {
//                QString symbolName = QString(&((fileContent + elf64Shdr[context.strindex].sh_offset)[sym->st_name]));
//                if(symbolName.compare(QString("")) == 0) continue;
//                if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL){
//                    //Store local variables with uniq names
//                    QString moduleName = context.currentModule.member("name").toString();
//                    symbolName.append("_").append(moduleName.remove(QChar('"'), Qt::CaseInsensitive));
//                    QString newSymName = symbolName;
//                    int i = 2;
//                    while (_funcTable.contains(newSymName)){
//                        newSymName = symbolName;
//                        newSymName.append("_").append(i);
//                    }
//                    symbolName = newSymName;
//                }
//                uint64_t symbolAddress = sym->st_value;
//                context.textSegment.address = this->findMemAddressOfSegment(context, QString(".text"));
//                if(symbolAddress < context.textSegment.address){
//                    symbolAddress += context.textSegment.address;
//                }
//                if(!_funcTable.contains(symbolName))
//                {
//                    _funcTable.insert(symbolName, symbolAddress);
//                }
//            }
//        }
//    }
//    context.rodataSegment = this->findElfSegmentWithName(context.fileContent, QString(".note.gnu.build-id"));
//    context.rodataSegment.address = (this->findMemAddressOfSegment(context, QString(".note.gnu.build-id")));
//
//    context.rodataContent.clear();
//
//    if(fileContent[4] == ELFCLASS32)
//    {
//        //TODO
//    }
//    else if(fileContent[4] == ELFCLASS64)
//    {
//        Elf64_Ehdr * elf64Ehdr = (Elf64_Ehdr *) fileContent;
//        Elf64_Shdr * elf64Shdr = (Elf64_Shdr *) (fileContent + elf64Ehdr->e_shoff);
//        for(unsigned int i = 0; i < elf64Ehdr->e_shnum; i++)
//        {
//            if(((elf64Shdr[i].sh_flags == SHF_ALLOC  || elf64Shdr[i].sh_flags == (uint64_t) 0x32) &&
//                    ( elf64Shdr[i].sh_type == SHT_PROGBITS )) ||
//                 (elf64Shdr[i].sh_flags == SHF_ALLOC && elf64Shdr[i].sh_type == SHT_NOTE))
//            {
//                QString sectionName = QString(fileContent + elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset + elf64Shdr[i].sh_name);
//                if(sectionName.compare(QString(".modinfo")) == 0 ||
//                       sectionName.compare(QString("__versions")) == 0 ||
//                       sectionName.startsWith(".init") ) continue;
//                uint64_t align = (elf64Shdr[i].sh_addralign ?: 1) - 1;
//                uint64_t alignmentSize = (context.rodataContent.size() + align) & ~align;
//                context.rodataContent = context.rodataContent.leftJustified(alignmentSize, 0);
//                context.rodataContent.append(fileContent + elf64Shdr[i].sh_offset, elf64Shdr[i].sh_size);
//
////                std::cout << hex << "Adding Section "
////                               << context.currentModule.member("name").toString() << " / " << sectionName
////                               << " Align: " << alignmentSize << " Size: " << elf64Shdr[i].sh_size
////                               << dec << std::endl;
//            }
//        }
//    }
//
//    //writeModuleToFile(fileName, currentModule, fileContent );
//    return context;

}

void ElfModuleLoader::initData(void) {}

void ElfModuleLoader::updateSegmentInfoMemAddress(SegmentInfo &info){
	info.memindex = info.index;
	assert(false);
	UNUSED(info);
    //altinstrSegmentInMem = findMemAddressOfSegment(context, ".altinstr_replacement");
}

////////////////////////////////////////////////////

ElfKernelLoader32::ElfKernelLoader32(ElfFile32* elffile):
	ElfKernelLoader(elffile){
	//this->ParseElfFile();
}

ElfKernelLoader32::~ElfKernelLoader32(){}

////////////////////////////////////////////////////

ElfKernelLoader64::ElfKernelLoader64(ElfFile64* elffile):
	ElfKernelLoader(elffile){
	//this->parseElfFile();
}

ElfKernelLoader64::~ElfKernelLoader64(){}

