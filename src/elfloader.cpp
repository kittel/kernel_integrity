#include "helpers.h"
#include "elfloader.h"

#include "exceptions.h"
#include "kernel_headers.h"
#include <cassert>


#include <cstring>

#include <iostream>
#include <fstream>

#include <typeinfo>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"


ElfLoader::ElfLoader(ElfFile* elffile, ParavirtState* para):
	elffile(elffile),
	debugInstance(),
	textSegment(),
	textSegmentContent(),
	jumpTable(),
	roData(),
	jumpEntries(),
	jumpDestinations(),
	smpOffsets(),
	dataSegment(),
	bssSegment(),
	roDataSegment(),
	paravirtState(para){

	//get the current cpu architecture to adapt nops
	Instance ideal_nops_instance = 
		Variable::findVariableByName("ideal_nops")->getInstance();
	uint64_t p6_address = Variable::findVariableByName("p6_nops")->
		                                                getInstance().
							                        	getAddress();
	uint64_t k8_address = Variable::findVariableByName("k8_nops")->
		                                                getInstance().
							                        	getAddress();

	uint64_t nopaddr = ideal_nops_instance.getRawValue<uint64_t>(false);
	
	if (nopaddr == p6_address){
		this->ideal_nops = p6_nops;
	}else if (nopaddr == k8_address){
		this->ideal_nops = k8_nops;
	}

#ifdef DEBUG
	std::cout << "Trying to initialize ElfLoader..." << std::endl;
#endif

}

ElfLoader::~ElfLoader(){}

ParavirtState* ElfLoader::getPVState(){
	return paravirtState;
}

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
    // These structs contain a function pointers.
    // In memory they are directly after each other.
    // Thus type is an index into the resulting array.

    if(type < paravirtState->pv_init_ops.size()) 
		return paravirtState->pv_init_ops.memberByOffset(type)
		    .getRawValue<uint64_t>(false);
    type -= paravirtState->pv_init_ops.size();

    if(type < paravirtState->pv_time_ops.size()) 
		return paravirtState->pv_time_ops.memberByOffset(type)
		    .getRawValue<uint64_t>(false);
    type -= paravirtState->pv_time_ops.size();

    if(type < paravirtState->pv_cpu_ops.size())  
		return paravirtState->pv_cpu_ops .memberByOffset(type)
		    .getRawValue<uint64_t>(false);
    type -= paravirtState->pv_cpu_ops.size();

    if(type < paravirtState->pv_irq_ops.size())  
		return paravirtState->pv_irq_ops .memberByOffset(type)
		    .getRawValue<uint64_t>(false);
    type -= paravirtState->pv_irq_ops.size();

    if(type < paravirtState->pv_apic_ops.size()) 
		return paravirtState->pv_apic_ops.memberByOffset(type)
		    .getRawValue<uint64_t>(false);
    type -= paravirtState->pv_apic_ops.size();

    if(type < paravirtState->pv_mmu_ops.size())  
		return paravirtState->pv_mmu_ops .memberByOffset(type)
		    .getRawValue<uint64_t>(false);
    type -= paravirtState->pv_mmu_ops.size();

    if(type < paravirtState->pv_lock_ops.size()) 
		return paravirtState->pv_lock_ops.memberByOffset(type)
		    .getRawValue<uint64_t>(false);

    return 0;
}

uint8_t ElfLoader::paravirt_patch_default(uint32_t type, uint16_t clobbers, void *insnbuf,
                                uint64_t addr, uint8_t len)
{
    uint8_t ret = 0;
    //Get Memory of paravirt_patch_template + type
	uint64_t opfunc = get_call_destination(type);

    if (!opfunc)
    {
        // opfunc == NULL
        /* If there's no function, patch it with a ud2a (BUG) */
        //If this is a module this is a bug anyway so this should not happen.
        //ret = paravirt_patch_insns(insnbuf, len, ud2a, ud2a+sizeof(ud2a));
        //If this the kernel this can happen and is only filled with nops
        ret = paravirt_patch_nop();
    }
    else if (opfunc == paravirtState->nopFuncAddress){
        /* If the operation is a nop, then nop the callsite */
        ret = paravirt_patch_nop();
	}
    /* identity functions just return their single argument */
    else if (opfunc == paravirtState->ident32NopFuncAddress){
        ret = paravirt_patch_insns(insnbuf, len, start__mov32, end__mov32);
	}
    else if (opfunc == paravirtState->ident64NopFuncAddress){
        ret = paravirt_patch_insns(insnbuf, len, start__mov64, end__mov64);
	}
    else if (type == paravirtState->pv_cpu_opsOffset + 
				paravirtState->pv_cpu_ops.memberOffset("iret") ||
             type == paravirtState->pv_cpu_opsOffset + 
				paravirtState->pv_cpu_ops.memberOffset("irq_enable_sysexit") ||
             type == paravirtState->pv_cpu_opsOffset + 
				paravirtState->pv_cpu_ops.memberOffset("usergs_sysret32") ||
             type == paravirtState->pv_cpu_opsOffset + 
				paravirtState->pv_cpu_ops.memberOffset("usergs_sysret64"))
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


#define PATCH_SITE(ops, x)		\
  else if(type == paravirtState->ops##Offset + paravirtState->ops.memberOffset("" #x )) \
  {                                                         \
      ret = paravirt_patch_insns(ibuf, len, start_##ops##_##x, end_##ops##_##x);    \
  } 

    if(false){}
    PATCH_SITE(pv_irq_ops, restore_fl)
    PATCH_SITE(pv_irq_ops, save_fl)
    PATCH_SITE(pv_irq_ops, irq_enable)
    PATCH_SITE(pv_irq_ops, irq_disable)
    //PATCH_SITE(pv_cpu_ops, iret)
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
	uint64_t count = 0;
	uint64_t count_all = 0;
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
    Instance x86_capability = boot_cpu_data.memberByName("x86_capability");

	uint32_t cpuCaps[10] = {0};
	for (uint8_t i = 0; i < 10; i++){
		cpuCaps[i] = x86_capability.arrayElem(i).getRawValue<uint32_t>(false);
	}

    for(struct alt_instr * a = start ; a < end ; a++)
	{
        //if (!boot_cpu_has(a->cpuid)) continue;

		count_all += 1;
		
        if (!((cpuCaps[a->cpuid / 32] >> (a->cpuid % 32)) & 0x1)){ 
			continue;
        }

		count += 1;

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
		if(((uint64_t)instr) % 0x1000 == 0x70){
			std::cout << "Found in " << this->getName() << std::endl;
		}
        memcpy(instr, insnbuf, a->instrlen);
    }

//	std::cout << COLOR_CYAN << 
//	             "Applied " << count << " / " << 
//				 count_all << " Altinstructions" << 
//				 COLOR_NORM << std::endl;
}

void ElfLoader::applyParainstr(){
	uint64_t count = 0;
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

		count += 1;

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

        /* Pad the rest with nops */
        add_nops(insnbuf + used, p->len - used);      //add_nops
        memcpy(instrInElf, insnbuf, p->len);   //memcpy
    }
//	std::cout << COLOR_CYAN << 
//	             "Applied " << count << 
//				 " Paravirt instructions" << 
//				 COLOR_NORM << std::endl;
}

void ElfLoader::applySmpLocks(){
	SegmentInfo info = this->elffile->findSegmentWithName(".smp_locks");
	if (!info.index) return;
	this->updateSegmentInfoMemAddress(info);

    unsigned char lock = 0;
	uint64_t count = 0;
    
	int32_t * smpLocksStart = (int32_t *) info.index;
    int32_t * smpLocksStop  = (int32_t *) (info.index + info.size);
	
	//Find boot_cpu_data in kernel
	Variable *boot_cpu_data_var = Variable::findVariableByName("boot_cpu_data");
	assert(boot_cpu_data_var);
	
	Instance boot_cpu_data = boot_cpu_data_var->getInstance();
    Instance x86_capability = boot_cpu_data.memberByName("x86_capability");
    if (!((x86_capability.arrayElem(X86_FEATURE_UP / 32).
					getRawValue<uint32_t>(false) >> (X86_FEATURE_UP % 32)) & 0x1)){
        /* turn lock prefix into DS segment override prefix */
        lock = 0x3e;
    }else{
        /* turn DS segment override prefix into lock prefix */
        lock = 0xf0;
    }

    bool addSmpEntries = false;
    if(this->smpOffsets.size() == 0) addSmpEntries = true;
    
    for(int32_t * poff = smpLocksStart; poff < smpLocksStop ; poff++)
    {
		count += 1;
        uint8_t *ptr = (uint8_t *)poff + *poff;


        //Adapt offset in ELF
        int32_t offset = (info.index - this->textSegment.index) - 
			(info.memindex - this->textSegment.memindex);
        ptr -= offset;

		if (this->textSegment.containsElfAddress((uint64_t) ptr)){
	        *ptr = lock;

            if (addSmpEntries) {
		    	this->smpOffsets.insert((uint64_t) ptr - 
				                (uint64_t) this->textSegment.index);
		    }
		}
    }
//	std::cout << COLOR_CYAN << 
//	             "Applied " << count << 
//				 " SMP instructions" << 
//				 COLOR_NORM << 
//				 std::endl;
}

void ElfLoader::applyMcount(SegmentInfo &info){
    //See ftrace_init_module in kernel/trace/ftrace.c

	uint64_t count = 0;
    uint64_t * mcountStart = (uint64_t *) info.index;
    uint64_t * mcountStop  = (uint64_t *) (info.index + info.size);

    //bool addMcountEntries = false;
    //if(context.mcountEntries.size() == 0) addMcountEntries = true;
    for(uint64_t * i = mcountStart; i < mcountStop; i++)
    {
		count += 1;
        //if (addMcountEntries) context.mcountEntries.insert((*i));
		
        add_nops((void*) (this->textSegmentContent.data() + 
					       ((uint64_t) (*i) - 
							(uint64_t) this->textSegment.memindex)), 5);
    }
//	std::cout << COLOR_CYAN << 
//	             "Applied " << count << 
//				 " Mcount instructions" << 
//				 COLOR_NORM << 
//				 std::endl;
}

void ElfLoader::applyJumpEntries(uint64_t jumpStart, uint32_t numberOfEntries){
	uint64_t count = 0;
	// Apply the jump tables after the segments are adjacent
    // jump_label_apply_nops() => 
	// http://lxr.free-electrons.com/source/arch/x86/kernel/module.c#L205
    // the entry type is 0 for disable and 1 for enable

    bool addJumpEntries = false;
    if(this->jumpEntries.size() == 0) addJumpEntries = true;

    struct jump_entry * startEntry = 
		                (struct jump_entry *) this->jumpTable.data();
    struct jump_entry * endEntry   = 
		                (struct jump_entry *) (this->jumpTable.data() + 
												this->jumpTable.size());

	BaseType* jump_entry_bt = BaseType::findBaseTypeByName("jump_entry");
	BaseType* static_key_bt = BaseType::findBaseTypeByName("static_key");
    for(uint32_t i = 0 ; i < numberOfEntries ; i++)
    {
        Instance jumpEntry = Instance(NULL, 0);
		if (dynamic_cast<ElfKernelLoader*>(this)){
			uint64_t instanceAddress = 0;
			
			// This is not a real array in memory but has more readability
			instanceAddress = (uint64_t) &((struct jump_entry *) jumpStart)[i];
			
			jumpEntry = jump_entry_bt->getInstance(instanceAddress);
            
			//Do not apply jump entries to .init.text
			uint64_t codeAddress = jumpEntry.memberByName("code").getValue<uint64_t>();
            if (codeAddress > 
					(uint64_t) this->textSegment.memindex + 
					           this->textSegment.size){
                continue;
            }
		}
		else if (dynamic_cast<ElfModuleLoader*>(this)){
			assert(false);
			//	TODO!!!!
			//    jumpEntry = context.currentModule.member("jump_entries").arrayElem(i);
		}

        uint64_t keyAddress = jumpEntry.memberByName("key").getValue<uint64_t>();

        //if(doPrint) Console::out() << hex << "Code: " << jumpEntry.member("code").toUInt64() << " target: " << jumpEntry.member("target").toUInt64() << dec << endl;
        //if(doPrint) Console::out() << hex << "Code offset : " << jumpEntry.member("code").toUInt64() - textSegmentInMem << " target offset : " << jumpEntry.member("target").toUInt64() - textSegmentInMem << dec << endl;

        Instance key = static_key_bt->getInstance(keyAddress);
        uint64_t enabled = key.memberByName("enabled")
							  .memberByName("counter")
							  .getValue<int64_t>();

        //if(doPrint) Console::out() << hex << "Key @ " << keyAddress << " is: " << enabled << dec << endl;

		uint64_t codeEntry = jumpEntry.memberByName("code").getValue<uint64_t>();
        for (struct jump_entry * entry = startEntry ; entry < endEntry; entry++){
            //Check if current elf entry is current kernel entry
            if (codeEntry ==  entry->code)
            {

				count +=1;
                uint64_t patchOffset = entry->code - 
								(uint64_t) this->textSegment.memindex;

                char * patchAddress = (char *) (patchOffset + 
								(uint64_t) this->textSegmentContent.data());

                //if(doPrint) Console::out() << "Jump Entry @ " << hex << patchOffset << dec;
                //if(doPrint) Console::out() << " " << ((enabled) ? "enabled" : "disabled") << endl;

                int32_t destination = entry->target - (entry->code + 5);
                if(addJumpEntries){
                    this->jumpEntries.insert(
					    std::pair<uint64_t, int32_t>(entry->code, destination));
					this->jumpDestinations.insert(entry->target);
                }


                if(enabled)
                {
                    //if(doPrint) Console::out() << hex << "Patching jump " << 
					//    "@ : " << patchOffset << dec << endl;
                    *patchAddress = (char) 0xe9;
                    *((int32_t*) (patchAddress + 1)) = destination;
                }
                else
                {
                    add_nops(patchAddress, 5);      //add_nops
                }
            }
        }
    }
//	std::cout << COLOR_CYAN << 
//	             "Applied " << count << 
//				 " JMP entries" << 
//				 COLOR_NORM << 
//				 std::endl;
}

void ElfLoader::parseElfFile(){
	this->initText();
	this->initData();
}

bool ElfLoader::isCodeAddress(uint64_t addr){
	addr = addr | 0xffff000000000000;
	return this->textSegment.containsMemAddress(addr);
}

