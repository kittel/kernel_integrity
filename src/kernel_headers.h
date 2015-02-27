#ifndef KERNELHEADERS_H
#define KERNELHEADERS_H

#include <inttypes.h>

#define KERNINT_PAGE_SIZE MODULE_PAGE_SIZE

#define MODULE_PAGE_SIZE 0x1000ULL
#define KERNEL_CODEPAGE_SIZE 0x200000ULL

#define GENERIC_NOP1 0x90

#define P6_NOP1 GENERIC_NOP1
#define P6_NOP2 0x66,0x90
#define P6_NOP3 0x0f,0x1f,0x00
#define P6_NOP4 0x0f,0x1f,0x40,0
#define P6_NOP5 0x0f,0x1f,0x44,0x00,0
#define P6_NOP6 0x66,0x0f,0x1f,0x44,0x00,0
#define P6_NOP7 0x0f,0x1f,0x80,0,0,0,0
#define P6_NOP8 0x0f,0x1f,0x84,0x00,0,0,0,0
#define P6_NOP5_ATOMIC P6_NOP5

#define K8_NOP1 GENERIC_NOP1
#define K8_NOP2 0x66,K8_NOP1
#define K8_NOP3 0x66,K8_NOP2
#define K8_NOP4 0x66,K8_NOP3
#define K8_NOP5 K8_NOP3,K8_NOP2
#define K8_NOP6 K8_NOP3,K8_NOP3
#define K8_NOP7 K8_NOP4,K8_NOP3
#define K8_NOP8 K8_NOP4,K8_NOP4
#define K8_NOP5_ATOMIC 0x66,K8_NOP4

#define ASM_NOP_MAX 8

#define CLBR_ANY  ((1 << 4) - 1)

#define X86_FEATURE_UP          (3*32+ 9) /* smp kernel running on up */

/* Simple instruction patching code. */
#define DEF_NATIVE(ops, name, code) 					\
    extern const char start_##ops##_##name[], end_##ops##_##name[];	\
    asm("start_" #ops "_" #name ": " code "; end_" #ops "_" #name ":")

#define tostr(x) #x

extern const unsigned char p6nops[];
extern const unsigned char k8nops[];
extern const unsigned char * const p6_nops[];
extern const unsigned char * const k8_nops[];

extern const char ud2a[];

struct alt_instr {
    int32_t  instr_offset;       /* original instruction */
    int32_t  repl_offset;        /* offset to replacement instruction */
    uint16_t cpuid;              /* cpuid bit set for replacement */
    uint8_t  instrlen;           /* length of original instruction */
    uint8_t  replacementlen;     /* length of new instruction, <= instrlen */
};

struct paravirt_patch_site {
    uint8_t *instr;              /* original instructions */
    uint8_t instrtype;           /* type of this instruction */
    uint8_t len;                 /* length of original instruction */
    uint16_t clobbers;           /* what registers you may clobber */
};

struct static_key {
    uint32_t enabled;
};

struct jump_entry {
    uint64_t code;
    uint64_t target;
    uint64_t key;
};

struct tracepoint_func {
    void *func;
    void *data;
};

struct tracepoint {
    const char *name;               /* Tracepoint name */
    struct static_key key;
    void (*regfunc)(void);
    void (*unregfunc)(void);
    struct tracepoint_func *funcs;
};

DEF_NATIVE(pv_irq_ops, irq_disable, "cli");
DEF_NATIVE(pv_irq_ops, irq_enable, "sti");
DEF_NATIVE(pv_irq_ops, restore_fl, "pushq %rdi; popfq");
DEF_NATIVE(pv_irq_ops, save_fl, "pushfq; popq %rax");
DEF_NATIVE(pv_cpu_ops, iret, "iretq");
DEF_NATIVE(pv_mmu_ops, read_cr2, "movq %cr2, %rax");
DEF_NATIVE(pv_mmu_ops, read_cr3, "movq %cr3, %rax");
DEF_NATIVE(pv_mmu_ops, write_cr3, "movq %rdi, %cr3");
DEF_NATIVE(pv_mmu_ops, flush_tlb_single, "invlpg (%rdi)");
DEF_NATIVE(pv_cpu_ops, clts, "clts");
DEF_NATIVE(pv_cpu_ops, wbinvd, "wbinvd");

DEF_NATIVE(pv_cpu_ops, irq_enable_sysexit, "swapgs; sti; sysexit");
DEF_NATIVE(pv_cpu_ops, usergs_sysret64, "swapgs; sysretq");
DEF_NATIVE(pv_cpu_ops, usergs_sysret32, "swapgs; sysretl");
DEF_NATIVE(pv_cpu_ops, swapgs, "swapgs");

DEF_NATIVE(, mov32, "mov %edi, %eax");
DEF_NATIVE(, mov64, "mov %rdi, %rax");

#include "libdwarfparser/instance.h"

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


#endif  /* KERNELHEADERS_H */
