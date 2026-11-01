/* nb_shim.c — Trigon 扁平 blob 的运行时 shim
 * 设计：
 *   · libc 部分在本文件内自实现（小堆由 JS 传入，避免大 .bss）
 *   · CF / IOKit / IOSurface / mach 通过 nb_imp[] 函数指针表转发
 *   · 全局符号（kCFBooleanTrue 等）由 JS 在运行时拷入固定槽位
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <mach/mach.h>

/* FORTIFY 会把 memcpy 等变成 __builtin_*_chk，这里强制用我们自己的实现 */
#undef memcpy
#undef memmove
#undef memset
#undef strlen
#undef strcmp
#undef memmem
#undef bzero
#undef malloc
#undef calloc
#undef free

/* ── 导入表（由 JS 填充）── */
void *nb_imp[32];

/* ── 全局符号槽位（JS 运行时写入）── */
void *kCFBooleanTrue = 0;
void *kCFBooleanFalse = 0;
char kCFTypeDictionaryKeyCallBacks[64];
char kCFTypeDictionaryValueCallBacks[64];
void *__CFConstantStringClassReference = 0;
mach_port_t kIOMasterPortDefault = 0;
mach_port_t mach_task_self_ = 0;

/* SDK 已在 mach/vm_page_size.h 中声明，这里按原类型定义 */
vm_size_t vm_kernel_page_mask = 0;
int vm_kernel_page_shift = 0;

#include "info.h"
DeviceInfo gDeviceInfo;

/* ── 栈保护兜底 ── */
uint64_t __stack_chk_guard = 0;
void __stack_chk_fail(void) { for (;;) { } }

/* ── 堆：由 JS 传入 ── */
static unsigned char *g_heap = 0;
static uint64_t g_heap_size = 0;
static uint64_t g_heap_off = 0;

int nb_set_heap(void *p, uint64_t n) {
    g_heap = (unsigned char *)p;
    g_heap_size = n;
    g_heap_off = 0;
    return 0;
}

static void *nb_alloc(uint64_t n) {
    uint64_t aligned = (n + 15) & ~((uint64_t)15);
    if (!g_heap) return 0;
    if (g_heap_off + aligned > g_heap_size) return 0;
    void *p = g_heap + g_heap_off;
    g_heap_off += aligned;
    return p;
}

void *malloc(size_t n) { return nb_alloc(n); }
void *calloc(size_t a, size_t b) { return nb_alloc((uint64_t)a * b); }
void free(void *p) { (void)p; }

/* ── 内存/字符串 ── */
void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    for (size_t i = 0; i < n; i++) dp[i] = sp[i];
    return d;
}
void *memmove(void *d, const void *s, size_t n) {
    unsigned char *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    if (dp == sp || n == 0) return d;
    if (dp < sp) { for (size_t i = 0; i < n; i++) dp[i] = sp[i]; }
    else { for (size_t i = n; i > 0; i--) dp[i - 1] = sp[i - 1]; }
    return d;
}
void *memset(void *d, int c, size_t n) {
    unsigned char *dp = (unsigned char *)d;
    for (size_t i = 0; i < n; i++) dp[i] = (unsigned char)c;
    return d;
}
void bzero(void *d, size_t n) { memset(d, 0, n); }
int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;
    for (size_t i = 0; i < n; i++) { if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1; }
    return 0;
}
size_t strlen(const char *s) { size_t n = 0; while (s && s[n]) n++; return n; }
int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}
void *memmem(const void *h, size_t hl, const void *n, size_t nl) {
    if (!nl) return (void *)h;
    if (hl < nl) return 0;
    const unsigned char *hp = (const unsigned char *)h, *np = (const unsigned char *)n;
    for (size_t i = 0; i + nl <= hl; i++) {
        size_t j = 0;
        while (j < nl && hp[i + j] == np[j]) j++;
        if (j == nl) return (void *)(hp + i);
    }
    return 0;
}

/* ── 输出静音 ── */
int printf(const char *fmt, ...) { (void)fmt; return 0; }
int puts(const char *s) { (void)s; return 0; }
int sscanf(const char *s, const char *fmt, ...) { (void)s; (void)fmt; return 0; }
