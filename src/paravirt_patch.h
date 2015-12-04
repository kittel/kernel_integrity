#ifndef PARAVIRT_PATCH_H_
#define PARAVIRT_PATCH_H_

#include <cstdint>

class ElfLoader;
class ParavirtState;

class ParavirtPatcher {
public:
	ParavirtPatcher(ParavirtState *pvstate);
	virtual ~ParavirtPatcher() = default;

	ParavirtState *const pvstate;

	void add_nops(void *insns, uint8_t len);

	uint8_t patch_nop(void);
	uint8_t patch_ignore(unsigned len);
	uint8_t patch_insns(void *insnbuf,
	                    unsigned len,
	                    const char *start,
	                    const char *end);
	uint8_t patch_jmp(void *insnbuf,
	                  uint64_t target,
	                  uint64_t addr,
	                  uint8_t len);
	uint8_t patch_call(void *insnbuf,
	                   uint64_t target,
	                   uint16_t tgt_clobbers,
	                   uint64_t addr,
	                   uint16_t site_clobbers,
	                   uint8_t len);
	uint8_t paravirt_patch_default(uint32_t type,
	                               uint16_t clobbers,
	                               void *insnbuf,
	                               uint64_t addr,
	                               uint8_t len);
	uint32_t paravirtNativePatch(uint32_t type,
	                             uint16_t clobbers,
	                             void *ibuf,
	                             unsigned long addr,
	                             unsigned len);

	uint64_t get_call_destination(uint32_t type);

	void applyParainstr(ElfLoader *target);
};

#endif
