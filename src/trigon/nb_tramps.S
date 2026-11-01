/* nb_tramps.S — 外部符号转发桩
 * 每个桩把参数原样转给 nb_imp[slot] 指向的真实函数地址。
 * 这样无需知道每个 API 的签名，参数/返回值完全透传。
 */
    .text

.macro NB_TRAMP name, slot
    .globl \name
    .p2align 2
\name:
    adrp x16, _nb_imp@PAGE
    add  x16, x16, _nb_imp@PAGEOFF
    ldr  x16, [x16, #(\slot * 8)]
    br   x16
.endm

/* CoreFoundation */
NB_TRAMP _CFDictionaryCreateMutable, 0
NB_TRAMP _CFDictionarySetValue,      1
NB_TRAMP _CFNumberCreate,            2
NB_TRAMP _CFRelease,                 3

/* IOKit */
NB_TRAMP _IOConnectCallMethod,       4
NB_TRAMP _IOServiceClose,            5
NB_TRAMP _IOServiceGetMatchingService, 6
NB_TRAMP _IOServiceMatching,         7
NB_TRAMP _IOServiceOpen,             8

/* IOSurface */
NB_TRAMP _IOSurfaceCreate,           9
NB_TRAMP _IOSurfaceGetBaseAddress,   10
NB_TRAMP _IOSurfaceLock,             11
NB_TRAMP _IOSurfaceUnlock,           12

/* mach */
NB_TRAMP _mach_make_memory_entry_64, 13
NB_TRAMP _mach_port_deallocate,      14
NB_TRAMP _mach_vm_deallocate,        15
NB_TRAMP _mach_vm_map,               16

/* libsystem */
NB_TRAMP _sysctlbyname,              17
NB_TRAMP _usleep,                    18

/* ── 入口：JS 调用 nb_set_imports 填表后，按符号偏移调用其它函数 ── */
    .globl _nb_set_imports
    .p2align 2
_nb_set_imports:
    adrp x9, _nb_imp@PAGE
    add  x9, x9, _nb_imp@PAGEOFF
    mov  x10, #0
1:
    cmp  x10, #32
    b.hs 2f
    ldr  x11, [x0, x10, lsl #3]
    str  x11, [x9, x10, lsl #3]
    add  x10, x10, #1
    b    1b
2:
    ret
