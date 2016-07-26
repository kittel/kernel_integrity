#ifndef KERNINT_KERNELHEADERS_H_
#define KERNINT_KERNELHEADERS_H_

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
#define DEF_NATIVE(ops, name, code)                                     \
	extern const char start_##ops##_##name[], end_##ops##_##name[]; \
	asm(".text\n start_" #ops "_" #name ": " code "; end_" #ops "_" #name ": nop")


#define tostr(x) #x


namespace kernint {

extern const unsigned char p6nops[];
extern const unsigned char k8nops[];
extern const unsigned char *const p6_nops[];
extern const unsigned char *const k8_nops[];

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

} // namespace kernint


#endif  /* KERNELHEADERS_H */
