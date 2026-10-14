// aop.h
// Trigon, 2025

#ifndef aop_h
#define aop_h

#include <stdint.h>

struct aop_info_t {
    uint64_t basePA;
    uint64_t size;
    uint32_t ttbr0;
    uint32_t ttbr1;
    uint32_t targetPTE;
    uint32_t targetVA;
    uint64_t targetPA;
    uint32_t targetFunction;
    uint32_t targetPointer;
    uint32_t shellcodePTE;
    uint32_t shellcodeVA;
    uint8_t *mapped;
};

typedef enum {
    AOP_CMD_NONE = 0,
    AOP_CMD_READY,
    AOP_CMD_READ,
    AOP_CMD_WRITE,
    AOP_CMD_KERN_BASE
} aop_cmd_t;

int aop_init(uint64_t base, uint64_t size);
void aop_deinit(void);
uint32_t aop_physread32(uint64_t pa);
uint64_t aop_physread64(uint64_t pa);
void aop_physwrite32(uint64_t pa, uint32_t value);
void aop_physwrite64(uint64_t pa, uint64_t value);
uint64_t aop_find_phys_kbase(void);

#endif /* aop_h */
